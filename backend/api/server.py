"""Minimal deployment API with liveness and readiness endpoints."""

from __future__ import annotations

import json
import os
import signal
import sqlite3
import threading
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from database_manager import NetworkDatabase


class HealthHandler(BaseHTTPRequestHandler):
    """Expose process liveness and SQLite readiness without secrets."""

    database_path = Path(os.environ.get("DATABASE_PATH", "network_logs.db"))

    def _respond(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - required HTTP handler API
        if self.path == "/health":
            self._respond(
                HTTPStatus.OK,
                {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()},
            )
            return
        if self.path == "/ready":
            try:
                with NetworkDatabase(self.database_path) as database:
                    database.fetch_devices(limit=1)
            except (OSError, ValueError, RuntimeError, sqlite3.Error):
                self._respond(HTTPStatus.SERVICE_UNAVAILABLE, {"status": "not_ready"})
                return
            self._respond(HTTPStatus.OK, {"status": "ready"})
            return
        self._respond(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def log_message(self, _format: str, *_args: object) -> None:
        return


class HealthServer:
    """Single-process HTTP server with graceful SIGTERM shutdown."""

    def __init__(self, host: str | None = None, port: int | None = None, database_path: str | Path | None = None):
        self.host = host or os.environ.get("API_HOST", "0.0.0.0")
        self.port = port if port is not None else int(os.environ.get("API_PORT", "8000"))
        if not 0 <= self.port <= 65535:
            raise ValueError("API_PORT must be between 0 and 65535")
        if database_path is not None:
            HealthHandler.database_path = Path(database_path)
        self.server = ThreadingHTTPServer((self.host, self.port), HealthHandler)
        self._stopping = threading.Event()

    def serve_forever(self) -> None:
        def stop(_signum: int, _frame: object) -> None:
            if not self._stopping.is_set():
                self._stopping.set()
                threading.Thread(target=self.server.shutdown, daemon=True).start()

        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, stop)
            signal.signal(signal.SIGINT, stop)
        try:
            self.server.serve_forever(poll_interval=0.5)
        finally:
            self.server.server_close()


def main() -> None:
    HealthServer().serve_forever()


if __name__ == "__main__":
    main()
