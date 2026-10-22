from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from http.server import HTTPServer
from pathlib import Path

from src.core.database import NetworkDatabase
from src.security.auth import AdminAuthenticator
from src.security.storage import StorageTelemetry
import src.api.server as api


class LiveAPIIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_database = api.database
        self.original_authenticator = api.authenticator
        self.original_storage = api.storage_telemetry
        api.database = NetworkDatabase(Path(self.temp_dir.name) / "live.db")
        api.authenticator = AdminAuthenticator("this is a secure test password", iterations=1)
        api.storage_telemetry = StorageTelemetry(
            Path(self.temp_dir.name) / "live.db",
            base_dir=Path(self.temp_dir.name),
            log_dir=Path(self.temp_dir.name) / "logs",
            quarantine_dir=Path(self.temp_dir.name) / "quarantine",
        )
        self.httpd = HTTPServer(("127.0.0.1", 0), api.NOCRequestHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(CookieJar())
        )
        self.base_url = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        api.database.close()
        self.original_database.close()
        api.database = self.original_database
        api.authenticator = self.original_authenticator
        api.storage_telemetry = self.original_storage
        self.temp_dir.cleanup()

    def request(self, path: str, *, method: str = "GET", body=None, headers=None):
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=payload,
            headers=headers or {},
            method=method,
        )
        try:
            with self.opener.open(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def authenticate(self) -> str:
        _, challenge = self.request("/api/auth/challenge", method="POST")
        key = hashlib.pbkdf2_hmac(
            "sha256",
            b"this is a secure test password",
            b"lan-watchtower-admin-v1",
            challenge["iterations"],
        )
        signature = hmac.new(
            key,
            f"{challenge['challenge_id']}:{challenge['nonce']}".encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        _, session = self.request(
            "/api/auth/verify",
            method="POST",
            body={"challenge_id": challenge["challenge_id"], "response": signature},
        )
        self.assertTrue(session["authenticated"])
        return session["csrf_token"]

    def test_live_api_requires_auth_and_exposes_real_security_data(self):
        status, error = self.request("/api/metrics")
        self.assertEqual(status, 401)
        self.assertEqual(error["error"], "Admin login is required")

        csrf_token = self.authenticate()
        status, metrics = self.request("/api/metrics")
        self.assertEqual(status, 200)
        self.assertEqual(metrics["total_devices"], 0)

        status, storage = self.request("/api/security/storage")
        self.assertEqual(status, 200)
        self.assertEqual(
            [zone["id"] for zone in storage["zones"]],
            ["system", "database", "logs", "quarantine"],
        )

        status, security = self.request("/api/security/status")
        self.assertEqual(status, 200)
        self.assertFalse(security["honeypot"]["running"])
        self.assertFalse(security["quarantine"]["configured"])

        status, audit = self.request("/api/security/audit")
        self.assertEqual(status, 200)
        self.assertTrue(audit["valid"])
        self.assertGreaterEqual(audit["event_count"], 1)

        status, _ = self.request(
            "/api/scan/start",
            method="POST",
            body={"subnet": "8.8.8.0/24"},
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 403)

        status, error = self.request(
            "/api/scan/start",
            method="POST",
            body={"subnet": "8.8.8.0/24"},
            headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
        )
        self.assertEqual(status, 400)
        self.assertIn("private", error["error"])


if __name__ == "__main__":
    unittest.main()
