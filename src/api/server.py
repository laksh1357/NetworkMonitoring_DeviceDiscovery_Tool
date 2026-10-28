"""REST API server for LAN Watchtower NOC Dashboard."""

from __future__ import annotations

import csv
import io
import json
import os
import signal
import socket
import sys
import threading
import time
import uuid
import webbrowser
from http.cookies import CookieError, SimpleCookie
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

try:
    import psutil
except ImportError:
    psutil = None

from src.api.validation import parse_private_ipv4_address, parse_private_scan_subnet
from src.core.database import NetworkDatabase
from src.core.models import Device, ScanJobState
from src.discovery.scanner import NetworkScanner, detect_local_subnet, ping_host
from src.discovery.port_scanner import scan_ports
from src.identity import IdentityVerificationService, NetworkObservation
from src.security.auth import AdminAuthenticator
from src.security.honeypot import HoneypotListeners
from src.security.storage import StorageTelemetry

_BASE_DIR = Path(__file__).resolve().parent.parent.parent
_WEB_DIR = _BASE_DIR / "web"

scanner = NetworkScanner()
database = NetworkDatabase(os.environ.get("DATABASE_PATH", _BASE_DIR / "network_logs.db"))
identity_service = IdentityVerificationService(database)
authenticator = AdminAuthenticator(os.environ.get("LAN_WATCHTOWER_ADMIN_PASSWORD"))
storage_telemetry = StorageTelemetry(database.database_path, base_dir=_BASE_DIR)


def _env_bool(name: str, default: str = "false") -> bool:
    value = os.environ.get(name, default).strip().lower()
    if value not in {"true", "false"}:
        raise ValueError(f"{name} must be 'true' or 'false'")
    return value == "true"


def _honeypot_ports() -> tuple[int, ...]:
    value = os.environ.get("LAN_WATCHTOWER_HONEYPOT_PORTS", "")
    if not value.strip():
        return ()
    try:
        return tuple(int(part.strip()) for part in value.split(",") if part.strip())
    except ValueError as exc:
        raise ValueError("LAN_WATCHTOWER_HONEYPOT_PORTS must be comma-separated port numbers") from exc


def _record_honeypot_connection(event: dict[str, object]) -> None:
    source_ip = str(event["source_ip"])
    database.create_alert(
        "HONEYPOT_CONNECTION",
        "HIGH",
        f"TCP connection observed from {source_ip} to decoy port {event['destination_port']}",
        source_ip,
    )
    database.append_audit_event("honeypot", "CONNECTION_OBSERVED", event)


honeypot_listeners = HoneypotListeners(
    _env_bool("LAN_WATCHTOWER_HONEYPOT_ENABLED"),
    os.environ.get("LAN_WATCHTOWER_HONEYPOT_BIND", "127.0.0.1"),
    _honeypot_ports(),
    _record_honeypot_connection,
)

AUTH_ENABLED = os.environ.get("AUTH_ENABLED", "true").lower() in ("true", "1", "yes")

scan_state = {
    "running": False,
    "done": 0,
    "total": 0,
    "discovered": 0,
    "online": 0,
    "offline": 0,
    "last_completed": None,
    "last_error": None,
    "current_subnet": None,
}
in_memory_devices: dict[str, Device] = {}
auto_scan_active = False
auto_scan_interval = 300  # seconds


class NOCRequestHandler(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(_WEB_DIR), **kwargs)

    def _send_json(
        self,
        data: object,
        code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, message: str, code: int = 400) -> None:
        self._send_json({"error": message}, code=code)

    def _session_token(self) -> str | None:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except CookieError:
            return None
        morsel = cookie.get("lan_watchtower_session")
        return morsel.value if morsel else None

    def _get_session_token(self) -> str:
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        cookie_token = self._session_token()
        if cookie_token:
            return cookie_token
        if "Cookie" in self.headers:
            cookies = self.headers.get("Cookie", "").split(";")
            for c in cookies:
                if "=" in c:
                    k, v = c.strip().split("=", 1)
                    if k.strip() in ("session", "token", "lan_watchtower_session"):
                        return v.strip()
        return ""

    def _get_current_user(self) -> dict[str, Any] | None:
        if not AUTH_ENABLED:
            return {
                "id": 1,
                "username": "admin",
                "role": "admin",
                "display_name": "Admin User",
                "email": "admin@network.local",
            }
        token = self._get_session_token()
        if not token:
            return None
        user = database.validate_session(token)
        if user:
            return user
        if authenticator.is_authenticated(token):
            return {
                "id": 1,
                "username": "admin",
                "role": "admin",
                "display_name": "Admin Authenticator",
                "email": "admin@network.local",
            }
        return None

    def _require_session(self, *, require_csrf: bool = False) -> bool:
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            bearer_token = auth_header[7:].strip()
            user = database.validate_session(bearer_token)
            if user:
                return True

        token = self._session_token()
        if not authenticator.is_authenticated(token):
            user = self._get_current_user()
            if user:
                return True
            message = (
                "Set LAN_WATCHTOWER_ADMIN_PASSWORD to enable authenticated administration"
                if not authenticator.configured
                else "Admin login is required"
            )
            self._send_error_json(message, code=503 if not authenticator.configured else 401)
            return False
        if require_csrf and not authenticator.validate_csrf(token, self.headers.get("X-CSRF-Token")):
            self._send_error_json("A valid CSRF token is required", code=403)
            return False
        return True

    def _read_json_body(self) -> dict[str, object] | None:
        try:
            content_len = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_error_json("Invalid Content-Length header")
            return None
        if content_len < 0 or content_len > 1_048_576:
            self._send_error_json("Request body must be at most 1 MiB", code=413)
            return None
        post_bytes = self.rfile.read(content_len) if content_len else b"{}"
        try:
            body = json.loads(post_bytes.decode("utf-8")) if post_bytes else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_error_json("Request body must contain valid JSON")
            return None
        if not isinstance(body, dict):
            self._send_error_json("Request JSON must be an object")
            return None
        return body

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/health":
            self._send_json({"status": "ok", "service": "lan-watchtower"})
            return

        if path == "/ready":
            try:
                database.fetch_devices(limit=1)
            except Exception:
                self._send_json({"status": "not_ready"}, code=503)
                return
            self._send_json({"status": "ready"})
            return

        if path == "/api/auth/status":
            session_token = self._session_token()
            user = self._get_current_user()
            self._send_json({
                "configured": authenticator.configured or database.count_users() > 0,
                "authenticated": user is not None or authenticator.is_authenticated(session_token),
                "csrf_token": authenticator.csrf_token(session_token) if session_token else None,
                "challenge_ttl_seconds": authenticator.challenge_ttl,
                "session_ttl_seconds": authenticator.session_ttl,
                "user": user,
            })
            return

        if path == "/api/auth/me":
            user = self._get_current_user()
            if not user:
                self._send_json({"authenticated": False})
                return
            self._send_json({"authenticated": True, "user": user})
            return

        if path == "/api/auth/setup-status":
            self._send_json({"has_users": database.count_users() > 0})
            return

        if path == "/api/auth/users":
            user = self._get_current_user()
            if not user or user.get("role") != "admin":
                self._send_error_json("Administrator privileges required", code=403)
                return
            self._send_json({"users": database.list_users()})
            return

        if path.startswith("/api/") and not self._require_session():
            return

        if path == "/api/security/status":
            self._send_json({
                "host_platform": sys.platform,
                "honeypot": honeypot_listeners.status(),
                "quarantine": {
                    "configured": False,
                    "automated": False,
                    "message": "Network isolation requires a supported router, switch, or firewall integration; none is configured.",
                },
            })
            return

        if path == "/api/security/storage":
            try:
                self._send_json(storage_telemetry.snapshot())
            except Exception as exc:
                self._send_error_json(f"Storage telemetry failed: {exc}", code=503)
            return

        if path == "/api/security/audit":
            self._send_json({
                **database.verify_audit_log(),
                "events": database.fetch_audit_events(limit=25),
            })
            return

        if path == "/api/subnet":
            try:
                sub = detect_local_subnet()
                scan_state["current_subnet"] = str(sub)
                self._send_json({
                    "subnet": str(sub),
                    "num_hosts": sub.num_addresses - 2 if sub.num_addresses > 2 else sub.num_addresses,
                    "privileged": scanner.privileged,
                })
            except Exception as exc:
                self._send_error_json(f"Unable to detect local subnet: {exc}", code=503)
            return

        if path == "/api/devices":
            db_devices = database.fetch_devices()
            result = []
            for item in db_devices:
                ip = item["ip"]
                mem_dev = in_memory_devices.get(ip)
                status = mem_dev.status if mem_dev else item.get("status", "Unknown")
                latency = mem_dev.latency_ms if mem_dev else item.get("latency_ms")
                result.append({
                    "ip": ip,
                    "mac": item.get("mac", "Unknown"),
                    "hostname": item.get("hostname", "Unknown"),
                    "vendor": item.get("vendor", "Unknown"),
                    "device_type": item.get("device_type", "Unknown"),
                    "custom_name": item.get("custom_name", ""),
                    "notes": item.get("notes", ""),
                    "status": status,
                    "latency_ms": latency,
                    "first_seen": item.get("first_seen", ""),
                    "last_seen": item.get("last_seen", ""),
                })
            self._send_json(result)
            return

        if path == "/api/scan/status":
            done = scan_state["done"]
            total = max(1, scan_state["total"])
            pct = int((done / total) * 100) if total > 0 else 0
            self._send_json({
                "running": scanner.running,
                "done": done,
                "total": total,
                "discovered": scan_state["discovered"],
                "online": scan_state["online"],
                "offline": scan_state["offline"],
                "percent": pct if scanner.running else (100 if done > 0 else 0),
                "subnet": scan_state["current_subnet"],
                "last_completed": scan_state["last_completed"],
                "last_error": scan_state["last_error"],
            })
            return

        if path == "/api/scan/jobs":
            self._send_json({"jobs": database.fetch_scan_jobs()})
            return

        if path.startswith("/api/scan/jobs/"):
            job_id = path.removeprefix("/api/scan/jobs/").strip("/")
            if not job_id:
                self._send_error_json("Scan job ID is required")
                return
            job = database.fetch_scan_job(job_id)
            if job is None:
                self._send_error_json("Scan job not found", code=404)
            else:
                self._send_json(job)
            return

        if path == "/api/alerts":
            alerts = database.fetch_alerts(limit=50)
            self._send_json([
                {
                    **alert,
                    "title": str(alert.get("type", "Alert")).replace("_", " ").title(),
                }
                for alert in alerts
            ])
            return

        if path == "/api/topology":
            devices = database.fetch_devices()
            # Only return observed nodes. Edges are intentionally empty until
            # LLDP/CDP or switch forwarding evidence is collected.
            self._send_json({
                "nodes": [
                    {
                        "id": device["ip"],
                        "ip": device["ip"],
                        "hostname": device.get("hostname", "Unknown"),
                        "vendor": device.get("vendor", "Unknown"),
                        "status": device.get("status", "Unknown"),
                        "last_seen": device.get("last_seen", ""),
                    }
                    for device in devices
                ],
                "edges": [],
                "relationships": "inferred nodes only; no physical connections verified",
            })
            return

        if path == "/api/identities":
            self._send_json({"identities": database.fetch_identities()})
            return

        if path.startswith("/api/identities/"):
            identity_id, _, suffix = path.removeprefix("/api/identities/").partition("/")
            identity = database.fetch_identity(identity_id)
            if identity is None:
                self._send_error_json("Identity not found", code=404)
                return
            if suffix in {"lineage", "observations"}:
                self._send_json({"observations": database.fetch_identity_observations(identity_id)})
            elif suffix == "conflicts":
                self._send_json({"conflicts": database.fetch_identity_conflicts(identity_id)})
            else:
                self._send_json(identity)
            return

        if path == "/api/activity":
            logs = database.fetch_activity_logs(limit=100)
            self._send_json(logs)
            return

        if path == "/api/profile":
            profile = database.get_user_profile()
            self._send_json(profile)
            return

        if path == "/api/metrics":
            db_devices = database.fetch_devices()
            total_devs = len(db_devices)
            online_count = sum(
                1
                for d in db_devices
                if str(in_memory_devices.get(d["ip"], Device(ip=d["ip"], status=d.get("status", "Unknown"))).status).upper()
                == "ONLINE"
            )
            offline_count = total_devs - online_count
            warning_count = sum(1 for d in db_devices if str(d.get("status", "")).upper() == "WARNING")
            active_alerts = database.fetch_alerts(status="active", limit=500)
            health_denominator = total_devs
            health_percentage = (
                round((online_count / health_denominator) * 100, 1)
                if health_denominator
                else 0.0
            )

            types_breakdown: dict[str, int] = {}
            for d in db_devices:
                dt = d.get("device_type", "PC/Workstation")
                types_breakdown[dt] = types_breakdown.get(dt, 0) + 1

            self._send_json({
                "total_devices": total_devs,
                "online_devices": online_count,
                "offline_devices": offline_count,
                "degraded_devices": warning_count,
                "active_alerts": len(active_alerts),
                "critical_alerts": sum(1 for alert in active_alerts if str(alert.get("severity", "")).upper() == "CRITICAL"),
                "network_health": health_percentage,
                "devices_by_type": types_breakdown,
                "scans_run": len(database.fetch_scan_logs(limit=500)),
            })
            return

        if path == "/api/export/csv":
            db_devices = database.fetch_devices()
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["IP Address", "MAC Address", "Vendor", "Hostname", "Device Type", "Custom Name", "Status", "Last Seen"])
            for d in db_devices:
                mem = in_memory_devices.get(d["ip"])
                st = mem.status if mem else d.get("status", "Unknown")
                writer.writerow([d["ip"], d["mac"], d["vendor"], d["hostname"], d["device_type"], d["custom_name"], st, d["last_seen"]])
            csv_bytes = output.getvalue().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="netmonitor-inventory.csv"')
            self.send_header("Content-Length", str(len(csv_bytes)))
            self.end_headers()
            self.wfile.write(csv_bytes)
            return

        if path == "/api/export/json":
            db_devices = database.fetch_devices()
            self._send_json(db_devices)
            return

        return super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/auth/challenge":
            if not authenticator.configured:
                self._send_error_json(
                    "Set LAN_WATCHTOWER_ADMIN_PASSWORD before using the live dashboard",
                    code=503,
                )
                return
            try:
                challenge = authenticator.issue_challenge(self.client_address[0])
            except PermissionError as exc:
                self._send_error_json(str(exc), code=429)
                return
            self._send_json({
                "challenge_id": challenge.challenge_id,
                "nonce": challenge.nonce,
                "expires_in": challenge.expires_in,
                "iterations": challenge.iterations,
                "algorithm": f"PBKDF2-HMAC-SHA256({challenge.iterations}) then HMAC-SHA256",
            })
            return

        body = self._read_json_body()
        if body is None:
            return

        if path == "/api/auth/verify":
            challenge_id = body.get("challenge_id")
            response = body.get("response")
            if not isinstance(challenge_id, str) or not isinstance(response, str):
                self._send_error_json("Challenge ID and response are required")
                return
            try:
                session = authenticator.verify_challenge(
                    challenge_id,
                    response,
                    self.client_address[0],
                )
            except RuntimeError as exc:
                self._send_error_json(str(exc), code=503)
                return
            if session is None:
                self._send_error_json("Invalid or expired admin challenge", code=401)
                return
            session_token, csrf_token = session
            database.append_audit_event("admin", "ADMIN_LOGIN", {"client_ip": self.client_address[0]})
            self._send_json(
                {"authenticated": True, "csrf_token": csrf_token},
                headers={
                    "Set-Cookie": (
                        f"lan_watchtower_session={session_token}; Path=/; "
                        f"Max-Age={authenticator.session_ttl}; HttpOnly; SameSite=Strict"
                    )
                },
            )
            return

        if path == "/api/auth/login":
            username = str(body.get("username", "")).strip()
            password = str(body.get("password", ""))
            if not username or not password:
                self._send_error_json("Username and password are required", code=400)
                return
            user = database.authenticate_user(username, password)
            if not user:
                self._send_error_json("Invalid username or password", code=401)
                return
            token = database.create_session(user["id"])
            database.insert_activity_log(
                user["display_name"],
                "USER_LOGIN",
                f"User {user['username']} logged in successfully",
            )
            self._send_json({
                "message": "Login successful",
                "token": token,
                "user": user,
            })
            return

        if path == "/api/auth/logout":
            token = self._get_session_token()
            if token:
                database.delete_session(token)
            session_token = self._session_token()
            if session_token:
                authenticator.logout(session_token)
            database.append_audit_event("admin", "ADMIN_LOGOUT", {"client_ip": self.client_address[0]})
            self._send_json(
                {"authenticated": False, "message": "Logged out successfully"},
                headers={
                    "Set-Cookie": (
                        "lan_watchtower_session=; Path=/; Max-Age=0; "
                        "HttpOnly; SameSite=Strict"
                    )
                },
            )
            return

        if path == "/api/auth/register":
            has_users = database.count_users() > 0
            current_user = self._get_current_user()
            if has_users and (not current_user or current_user.get("role") != "admin"):
                self._send_error_json("Administrator privileges required to register new users", code=403)
                return
            username = str(body.get("username", "")).strip()
            password = str(body.get("password", ""))
            display_name = str(body.get("display_name", ""))
            role = str(body.get("role", "operator" if has_users else "admin"))
            email = str(body.get("email", ""))
            try:
                new_user = database.create_user(
                    username, password, role=role, display_name=display_name, email=email
                )
                token = database.create_session(new_user["id"])
                database.insert_activity_log(
                    new_user["display_name"],
                    "USER_REGISTER",
                    f"User {new_user['username']} created ({new_user['role']})",
                )
                self._send_json({
                    "message": "Registration successful",
                    "token": token,
                    "user": new_user,
                }, code=201)
            except Exception as exc:
                self._send_error_json(str(exc), code=400)
            return

        if path == "/api/auth/change-password":
            user = self._get_current_user()
            if not user:
                self._send_error_json("Authentication required", code=401)
                return
            old_password = str(body.get("old_password", ""))
            new_password = str(body.get("new_password", ""))
            try:
                success = database.change_password(user["id"], old_password, new_password)
                if not success:
                    self._send_error_json("Incorrect current password", code=400)
                    return
                database.insert_activity_log(
                    user["display_name"],
                    "PASSWORD_CHANGE",
                    "User updated account password",
                )
                self._send_json({"message": "Password updated successfully"})
            except Exception as exc:
                self._send_error_json(str(exc), code=400)
            return

        if path.startswith("/api/") and not self._require_session(require_csrf=True):
            return

        if path.startswith("/api/"):
            database.append_audit_event(
                "admin",
                "API_MUTATION_REQUEST",
                {"path": path, "client_ip": self.client_address[0]},
            )

        if path == "/api/scan/jobs":
            raw_subnet = body.get("subnet")
            try:
                subnet = parse_private_scan_subnet(raw_subnet)
            except ValueError as exc:
                self._send_error_json(f"Invalid subnet range: {exc}")
                return
            job_id = uuid.uuid4().hex
            database.create_scan_job(job_id)
            self._send_json(database.fetch_scan_job(job_id), code=201)
            return

        if path.startswith("/api/scan/jobs/") and path.endswith("/transition"):
            job_id = path.removeprefix("/api/scan/jobs/").removesuffix("/transition").strip("/")
            target = body.get("state")
            if not job_id or not isinstance(target, str):
                self._send_error_json("Job ID and target state are required")
                return
            try:
                job = database.update_scan_job_state(
                    job_id,
                    ScanJobState(target),
                    error_message=body.get("error_message"),
                )
            except ValueError as exc:
                if "not found" in str(exc):
                    self._send_error_json("Scan job not found", code=404)
                else:
                    self._send_error_json(str(exc))
                return
            self._send_json(job)
            return

        if path == "/api/scan/start":
            if scanner.running:
                self._send_error_json("Scan is already in progress")
                return

            try:
                raw_sub = body.get("subnet")
                if not raw_sub:
                    raw_sub = str(detect_local_subnet())
                sub = parse_private_scan_subnet(raw_sub)
            except (ValueError, OSError) as exc:
                self._send_error_json(f"Invalid subnet range: {exc}")
                return

            scan_state["running"] = True
            scan_state["done"] = 0
            scan_state["total"] = len(list(sub.hosts()))
            scan_state["discovered"] = 0
            scan_state["online"] = 0
            scan_state["offline"] = 0
            scan_state["current_subnet"] = str(sub)

            database.create_alert("SCAN_STARTED", "INFO", f"Initiated discovery scan on {sub}")

            def on_prog(done: int, total: int):
                scan_state["done"] = done
                scan_state["total"] = total

            def on_dev_found(dev: Device):
                in_memory_devices[dev.ip] = dev
                scan_state["discovered"] = len([d for d in in_memory_devices.values() if d.status == "Online"])
                scan_state["online"] = scan_state["discovered"]
                database.upsert_device(
                    ip=dev.ip,
                    mac=dev.mac,
                    hostname=dev.hostname,
                    vendor=dev.vendor,
                    device_type=getattr(dev, "device_type", "Unknown"),
                )
                database.append_audit_event(
                    "scanner",
                    "DEVICE_DISCOVERED",
                    {"ip": dev.ip, "mac": dev.mac, "subnet": str(sub)},
                )
                identity_service.process(
                    NetworkObservation(
                        ip=dev.ip,
                        mac=dev.mac,
                        hostname=dev.hostname,
                        vendor=dev.vendor,
                        device_type=getattr(dev, "device_type", "Unknown"),
                        open_ports=dev.open_ports,
                        latency_ms=dev.latency_ms,
                        source=dev.source,
                        interface=dev.interface,
                        fingerprint=dev.fingerprint,
                        raw_evidence={
                            "collector": "src.discovery.scanner.NetworkScanner",
                            "scan_subnet": str(sub),
                        },
                    )
                )
                database.create_alert(
                    "LIVE_DEVICE_DISCOVERED",
                    "INFO",
                    f"Real-time node online: {dev.ip} ({dev.hostname})",
                    dev.ip,
                )

            def on_comp(found: list[Device]):
                scan_state["running"] = False
                scan_state["discovered"] = len(found)
                scan_state["online"] = len(found)
                scan_state["last_completed"] = time.strftime("%Y-%m-%d %H:%M:%S")

                for dev in found:
                    in_memory_devices[dev.ip] = dev

                database.record_scan(found, total_devices_online=len(found))
                database.append_audit_event(
                    "scanner",
                    "SCAN_COMPLETED",
                    {"subnet": str(sub), "devices_found": len(found)},
                )
                database.create_alert(
                    "SCAN_COMPLETED",
                    "INFO",
                    f"Scan finished: {len(found)} online devices discovered.",
                )

            def on_err(err: str):
                scan_state["running"] = False
                scan_state["last_error"] = err
                database.append_audit_event(
                    "scanner",
                    "SCAN_FAILED",
                    {"subnet": str(sub), "error": err},
                )
                database.create_alert("SCAN_ERROR", "CRITICAL", f"Discovery scan failed: {err}")

            scanner.scan(sub, on_prog, on_comp, on_err, on_device_found=on_dev_found)
            self._send_json({"message": "Discovery scan launched successfully", "subnet": str(sub)})
            return

        if path == "/api/scan/stop":
            scanner.stop()
            scan_state["running"] = False
            database.create_alert("SCAN_ABORTED", "WARNING", "User manually canceled the discovery scan.")
            self._send_json({"message": "Scan stop signal sent"})
            return

        if path == "/api/ports/scan":
            ip = body.get("ip")
            if not isinstance(ip, str) or not ip:
                self._send_error_json("Target IP is required")
                return
            try:
                parse_private_ipv4_address(ip)
            except ValueError:
                self._send_error_json("Target IP must be an RFC1918 private IPv4 address")
                return
            ports_to_check = body.get("ports")
            try:
                results = scan_ports(ip, ports=ports_to_check) if ports_to_check else scan_ports(ip)
                res_list = [{"port": p.port, "service": p.service} for p in results]
                self._send_json({"ip": ip, "open_ports": res_list, "total_open": len(res_list)})
            except Exception as exc:
                self._send_error_json(str(exc))
            return

        if path == "/api/device/update":
            ip = body.get("ip")
            if not ip:
                self._send_error_json("Target IP is required")
                return
            custom_name = body.get("custom_name", "")
            notes = body.get("notes", "")
            dev_type = body.get("device_type")
            hostname = body.get("hostname")
            vendor = body.get("vendor")
            mac = body.get("mac")
            location = body.get("location")
            try:
                database.update_device_meta(ip, custom_name, notes, dev_type, hostname, vendor, mac, location)
            except ValueError as exc:
                self._send_error_json(str(exc), code=404)
                return
            self._send_json({"message": "Device metadata updated successfully", "ip": ip})
            return

        if path == "/api/device/create":
            ip = body.get("ip")
            try:
                ip = str(parse_private_ipv4_address(ip))
            except ValueError as exc:
                self._send_error_json(str(exc))
                return
            mac = body.get("mac", "Unknown")
            hostname = body.get("hostname", "Unknown")
            vendor = body.get("vendor", "Unknown")
            dev_type = body.get("device_type", "PC/Workstation")
            custom_name = body.get("custom_name", "")
            location = body.get("location", "Main Network")
            notes = body.get("notes", "")

            database.upsert_device(
                ip=ip,
                mac=mac,
                hostname=hostname,
                vendor=vendor,
                device_type=dev_type,
                custom_name=custom_name,
                notes=notes,
                location=location,
            )
            in_memory_devices[ip] = Device(
                ip=ip,
                mac=mac,
                vendor=vendor,
                hostname=hostname,
                status="Online",
                latency_ms=1.5,
                last_seen=time.strftime("%Y-%m-%d %H:%M:%S"),
            )
            database.create_alert(
                "CUSTOM_DEVICE_ADDED",
                "INFO",
                f"Manually created device {custom_name or ip} ({dev_type})",
                ip,
            )
            self._send_json({"message": "Device created successfully", "ip": ip})
            return

        if path == "/api/device/delete":
            ip = body.get("ip")
            if not ip:
                self._send_error_json("Target IP is required")
                return
            try:
                database.delete_device(ip)
            except ValueError as exc:
                self._send_error_json(str(exc), code=404)
                return
            if ip in in_memory_devices:
                del in_memory_devices[ip]
            database.create_alert(
                "DEVICE_REMOVED",
                "WARNING",
                f"Deleted device node {ip} from network registry",
                ip,
            )
            self._send_json({"message": "Device deleted successfully", "ip": ip})
            return

        if path == "/api/device/ping":
            ip = body.get("ip")
            try:
                ip = str(parse_private_ipv4_address(ip))
            except ValueError as exc:
                self._send_error_json(str(exc))
                return
            success, latency = ping_host(ip, timeout=1.5)
            if success and ip in in_memory_devices:
                in_memory_devices[ip].status = "Online"
                in_memory_devices[ip].latency_ms = latency
            self._send_json({"ip": ip, "online": success, "latency_ms": latency})
            return

        if path == "/api/profile/update":
            d_name = body.get("display_name", "Admin User")
            role = body.get("role_title", "Administrator")
            email = body.get("email", "admin@network.local")
            avatar = body.get("avatar_initials", "AU")
            database.update_user_profile(d_name, role, email, avatar)
            database.insert_activity_log(d_name, "PROFILE_UPDATE", f"User updated profile name to {d_name} ({role})")
            self._send_json({"message": "User profile updated successfully"})
            return

        if path == "/api/activity/log":
            u_name = body.get("user_name", "Admin User")
            action = body.get("action_type", "USER_ACTION")
            desc = body.get("description", "")
            ip = body.get("ip", "")
            database.insert_activity_log(u_name, action, desc, ip)
            self._send_json({"message": "Activity logged successfully"})
            return

        if path == "/api/database/clear":
            database.clear_database()
            in_memory_devices.clear()
            scan_state["done"] = 0
            scan_state["discovered"] = 0
            scan_state["online"] = 0
            scan_state["offline"] = 0
            database.create_alert(
                "DATABASE_RESET",
                "INFO",
                "Cleared stored network data; the append-only audit history was preserved.",
            )
            database.insert_activity_log("Admin User", "DATABASE_RESET", "Wiped network database inventory and scan logs.")
            self._send_json({"message": "Database cleared successfully"})
            return



        self._send_error_json("Endpoint not found", code=404)


def run_server(port: int = 8000, open_browser: bool = True) -> HTTPServer:
    host = os.environ.get("API_HOST", "127.0.0.1")
    actual_port = port
    try:
        httpd = HTTPServer((host, actual_port), NOCRequestHandler)
    except OSError as err:
        if getattr(err, "errno", None) == 48 and actual_port == 8000:
            actual_port = 8080
            print(f"Port 8000 already in use, binding to fallback port {actual_port} instead...")
            httpd = HTTPServer((host, actual_port), NOCRequestHandler)
        else:
            raise
    try:
        honeypot_listeners.start()
    except OSError:
        httpd.server_close()
        raise
    print(f"LAN Watchtower dashboard and API running at http://{host}:{actual_port}")

    if open_browser:
        threading.Thread(target=lambda: (time.sleep(1.0), webbrowser.open(f"http://127.0.0.1:{actual_port}")), daemon=True).start()

    return httpd


def main() -> None:
    """Run the canonical API without opening a desktop browser."""
    port = int(os.environ.get("API_PORT", "8000"))
    server = run_server(port, open_browser=False)
    previous_sigterm_handler = signal.signal(signal.SIGTERM, _handle_sigterm)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm_handler)
        honeypot_listeners.stop()
        server.server_close()
        database.close()


def _handle_sigterm(signum, frame) -> None:
    raise KeyboardInterrupt


if __name__ == "__main__":
    main()
