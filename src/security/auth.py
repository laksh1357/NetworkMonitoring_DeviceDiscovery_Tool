"""Short-lived challenge and session authentication for local administration."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Challenge:
    challenge_id: str
    nonce: str
    expires_in: int
    iterations: int


class AdminAuthenticator:
    """Validate PBKDF2-backed HMAC challenges and short-lived admin sessions."""

    def __init__(
        self,
        password: str | None,
        *,
        challenge_ttl: int = 15,
        session_ttl: int = 1800,
        iterations: int = 310_000,
        max_failures: int = 5,
        lockout_seconds: int = 60,
        max_pending_challenges: int = 2048,
    ) -> None:
        if challenge_ttl < 1 or session_ttl < 1 or iterations < 1:
            raise ValueError("Authentication lifetimes and iterations must be positive")
        if password and len(password) < 16:
            raise ValueError("LAN_WATCHTOWER_ADMIN_PASSWORD must contain at least 16 characters")
        self._key = (
            hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                b"lan-watchtower-admin-v1",
                iterations,
            )
            if password
            else None
        )
        self.challenge_ttl = challenge_ttl
        self.session_ttl = session_ttl
        self.iterations = iterations
        self.max_failures = max_failures
        self.lockout_seconds = lockout_seconds
        self.max_pending_challenges = max_pending_challenges
        self._lock = threading.Lock()
        self._challenges: dict[str, tuple[str, float, str]] = {}
        self._sessions: dict[str, tuple[str, float]] = {}
        self._failures: dict[str, tuple[int, float, float]] = {}

    @property
    def configured(self) -> bool:
        return self._key is not None

    def issue_challenge(self, client_key: str) -> Challenge:
        if self._key is None:
            raise RuntimeError("Admin password is not configured")
        now = time.monotonic()
        with self._lock:
            self._cleanup(now)
            failures, reset_at, blocked_until = self._failures.get(client_key, (0, 0.0, 0.0))
            if blocked_until > now:
                raise PermissionError("Too many failed attempts; try again later")
            if len(self._challenges) >= self.max_pending_challenges or sum(
                challenge[2] == client_key for challenge in self._challenges.values()
            ) >= 8:
                raise PermissionError("Too many pending challenges; try again shortly")
            challenge_id = secrets.token_urlsafe(24)
            nonce = secrets.token_hex(32)
            self._challenges[challenge_id] = (
                nonce,
                now + self.challenge_ttl,
                client_key,
            )
        return Challenge(challenge_id, nonce, self.challenge_ttl, self.iterations)

    def verify_challenge(
        self,
        challenge_id: str,
        response_hex: str,
        client_key: str,
    ) -> tuple[str, str] | None:
        if self._key is None:
            raise RuntimeError("Admin password is not configured")
        now = time.monotonic()
        with self._lock:
            self._cleanup(now)
            challenge = self._challenges.pop(challenge_id, None)
            failures, reset_at, blocked_until = self._failures.get(client_key, (0, 0.0, 0.0))
            if blocked_until > now or challenge is None:
                return None
            nonce, expires, owner = challenge
            if owner != client_key or expires < now:
                return None
            expected = hmac.new(
                self._key,
                f"{challenge_id}:{nonce}".encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected, response_hex.lower()):
                if reset_at <= now:
                    failures = 0
                failures += 1
                blocked_until = now + self.lockout_seconds if failures >= self.max_failures else 0.0
                self._failures[client_key] = (
                    failures,
                    now + self.lockout_seconds,
                    blocked_until,
                )
                return None
            self._failures.pop(client_key, None)
            session_token = secrets.token_urlsafe(32)
            csrf_token = secrets.token_urlsafe(32)
            self._sessions[session_token] = (csrf_token, now + self.session_ttl)
            return session_token, csrf_token

    def is_authenticated(self, session_token: str | None) -> bool:
        if not session_token:
            return False
        now = time.monotonic()
        with self._lock:
            self._cleanup(now)
            return session_token in self._sessions

    def validate_csrf(self, session_token: str | None, csrf_token: str | None) -> bool:
        if not session_token or not csrf_token:
            return False
        now = time.monotonic()
        with self._lock:
            self._cleanup(now)
            session = self._sessions.get(session_token)
            return bool(session and hmac.compare_digest(session[0], csrf_token))

    def csrf_token(self, session_token: str | None) -> str | None:
        if not session_token:
            return None
        now = time.monotonic()
        with self._lock:
            self._cleanup(now)
            session = self._sessions.get(session_token)
            return session[0] if session else None

    def logout(self, session_token: str | None) -> None:
        if not session_token:
            return
        with self._lock:
            self._sessions.pop(session_token, None)

    def _cleanup(self, now: float) -> None:
        self._challenges = {
            identifier: challenge
            for identifier, challenge in self._challenges.items()
            if challenge[1] >= now
        }
        self._sessions = {
            token: session for token, session in self._sessions.items() if session[1] >= now
        }
        self._failures = {
            client: record
            for client, record in self._failures.items()
            if record[1] > now or record[2] > now
        }
