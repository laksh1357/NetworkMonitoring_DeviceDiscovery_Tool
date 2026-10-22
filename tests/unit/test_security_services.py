from __future__ import annotations

import hashlib
import hmac
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from src.core.database import NetworkDatabase
from src.security.auth import AdminAuthenticator
from src.security.honeypot import HoneypotListeners, validate_honeypot_config
from src.security.merkle import event_leaf_hash, merkle_root


def sign_challenge(password: str, challenge_id: str, nonce: str) -> str:
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        b"lan-watchtower-admin-v1",
        1,
    )
    return hmac.new(key, f"{challenge_id}:{nonce}".encode("ascii"), hashlib.sha256).hexdigest()


class AdminAuthenticatorTests(unittest.TestCase):
    def test_15_second_challenge_creates_csrf_protected_session(self):
        password = "correct horse battery"
        auth = AdminAuthenticator(password, iterations=1)
        challenge = auth.issue_challenge("127.0.0.1")
        token, csrf = auth.verify_challenge(
            challenge.challenge_id,
            sign_challenge(password, challenge.challenge_id, challenge.nonce),
            "127.0.0.1",
        )
        self.assertTrue(auth.is_authenticated(token))
        self.assertTrue(auth.validate_csrf(token, csrf))
        self.assertFalse(auth.validate_csrf(token, "wrong"))
        auth.logout(token)
        self.assertFalse(auth.is_authenticated(token))

    def test_challenge_is_single_use_and_bound_to_client(self):
        auth = AdminAuthenticator("correct horse battery", iterations=1)
        challenge = auth.issue_challenge("127.0.0.1")
        response = sign_challenge("correct horse battery", challenge.challenge_id, challenge.nonce)
        self.assertIsNone(auth.verify_challenge(challenge.challenge_id, response, "192.168.1.2"))
        self.assertIsNone(auth.verify_challenge(challenge.challenge_id, response, "127.0.0.1"))

    def test_rejects_short_configured_password(self):
        with self.assertRaisesRegex(ValueError, "16 characters"):
            AdminAuthenticator("short")

    def test_unconfigured_authentication_fails_closed(self):
        auth = AdminAuthenticator(None)
        self.assertFalse(auth.configured)
        with self.assertRaisesRegex(RuntimeError, "not configured"):
            auth.issue_challenge("127.0.0.1")


class AuditMerkleTests(unittest.TestCase):
    def test_merkle_root_is_deterministic_and_changes_with_leaves(self):
        leaves = [
            event_leaf_hash({"sequence": 1, "action": "scan"}),
            event_leaf_hash({"sequence": 2, "action": "login"}),
        ]
        self.assertEqual(merkle_root(leaves), merkle_root(leaves))
        self.assertNotEqual(merkle_root(leaves), merkle_root(reversed(leaves)))

    def test_database_audit_verification_detects_event_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "audit.db") as database:
                database.append_audit_event("admin", "SCAN_START", {"subnet": "192.168.1.0/24"})
                database.append_audit_event("admin", "LOGIN", {})
                database.append_audit_event("scanner", "SCAN_COMPLETE", {"count": 3})
                self.assertTrue(database.verify_audit_log()["valid"])
                database._connection.execute(
                    "UPDATE audit_events SET action = 'TAMPERED' WHERE sequence = 1"
                )
                self.assertFalse(database.verify_audit_log()["valid"])

    def test_database_rebuilds_missing_frontier_on_open(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "audit.db"
            database = NetworkDatabase(database_path)
            database.append_audit_event("admin", "LOGIN", {})
            database.append_audit_event("scanner", "SCAN_COMPLETED", {"count": 2})
            original_root = database.verify_audit_log()["merkle_root"]
            database._connection.execute("DELETE FROM audit_merkle_frontier")
            database.close()

            with NetworkDatabase(database_path) as migrated:
                result = migrated.verify_audit_log()
                self.assertTrue(result["valid"])
                self.assertEqual(result["merkle_root"], original_root)
                migrated.append_audit_event("admin", "LOGOUT", {})
                self.assertTrue(migrated.verify_audit_log()["valid"])


class HoneypotConfigTests(unittest.TestCase):
    def test_disabled_honeypot_opens_no_ports(self):
        self.assertIsNone(validate_honeypot_config(False, "0.0.0.0", ()))

    def test_enabled_honeypot_requires_explicit_private_bind_and_unprivileged_ports(self):
        validate_honeypot_config(True, "127.0.0.1", (2222, 8088))
        with self.assertRaisesRegex(ValueError, "specific private"):
            validate_honeypot_config(True, "0.0.0.0", (2222,))
        with self.assertRaisesRegex(ValueError, "1024"):
            validate_honeypot_config(True, "127.0.0.1", (80,))

    def test_enabled_listener_records_a_local_connection_without_payload(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        events = []
        received = threading.Event()

        def record(event):
            events.append(event)
            received.set()

        listener = HoneypotListeners(True, "127.0.0.1", (port,), record)
        try:
            listener.start()
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                pass
            self.assertTrue(received.wait(2))
            self.assertEqual(events[0]["source_ip"], "127.0.0.1")
            self.assertEqual(events[0]["destination_port"], port)
        finally:
            listener.stop()


if __name__ == "__main__":
    unittest.main()
