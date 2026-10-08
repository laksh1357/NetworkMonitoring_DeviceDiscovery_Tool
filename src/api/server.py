"""REST API server for LAN Watchtower NOC Dashboard."""

from __future__ import annotations

import csv
import io
import json
import os
import socket
import sys
import threading
import time
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from src.core.database import NetworkDatabase
from src.core.models import Device
from src.discovery.scanner import NetworkScanner, detect_local_subnet
from src.discovery.port_scanner import scan_ports

_BASE_DIR = Path(__file__).resolve().parent.parent.parent
_WEB_DIR = _BASE_DIR / "web"

scanner = NetworkScanner()
database = NetworkDatabase(_BASE_DIR / "network_logs.db")

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

    def _send_json(self, data: object, code: int = 200) -> None:
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, message: str, code: int = 400) -> None:
        self._send_json({"error": message}, code=code)

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
                    "device_type": item.get("device_type", "PC/Workstation"),
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

        if path == "/api/alerts":
            alerts = database.fetch_alerts(limit=50)
            self._send_json(alerts)
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
            online_count = sum(1 for d in db_devices if in_memory_devices.get(d["ip"], Device(ip=d["ip"])).status == "Online")
            offline_count = total_devs - online_count

            types_breakdown: dict[str, int] = {}
            for d in db_devices:
                dt = d.get("device_type", "PC/Workstation")
                types_breakdown[dt] = types_breakdown.get(dt, 0) + 1

            self._send_json({
                "total_devices": total_devs,
                "online_devices": online_count,
                "offline_devices": offline_count,
                "degraded_devices": 1 if online_count > 0 else 0,
                "active_alerts": 4,
                "critical_alerts": 1,
                "network_health": 98.5 if online_count > 0 else 100.0,
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
                st = mem.status if mem else "Online"
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

        content_len = int(self.headers.get("Content-Length", 0))
        post_bytes = self.rfile.read(content_len) if content_len > 0 else b"{}"
        try:
            body = json.loads(post_bytes.decode("utf-8")) if post_bytes else {}
        except json.JSONDecodeError:
            body = {}

        if path == "/api/scan/start":
            if scanner.running:
                self._send_error_json("Scan is already in progress")
                return

            try:
                import ipaddress
                raw_sub = body.get("subnet")
                if not raw_sub:
                    raw_sub = str(detect_local_subnet())
                sub = ipaddress.ip_network(raw_sub, strict=False)
            except Exception as exc:
                self._send_error_json(f"Invalid subnet range: {exc}")
                return

            scan_state["running"] = True
            scan_state["done"] = 0
            scan_state["total"] = len(list(sub.hosts()))
            scan_state["discovered"] = 0
            scan_state["online"] = 0
            scan_state["offline"] = 0
            scan_state["current_subnet"] = str(sub)

            database.insert_alert("INFO", "Scan Started", f"Initiated discovery scan on {sub}")

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
                    device_type=dev.device_type,
                )
                database.insert_alert("INFO", "Live Device Discovered", f"Real-time node online: {dev.ip} ({dev.hostname})", dev.ip)

            def on_comp(found: list[Device]):
                scan_state["running"] = False
                scan_state["discovered"] = len(found)
                scan_state["online"] = len(found)
                scan_state["last_completed"] = time.strftime("%Y-%m-%d %H:%M:%S")

                for dev in found:
                    in_memory_devices[dev.ip] = dev

                database.record_scan(found, total_devices_online=len(found))
                database.insert_alert("RESOLVED", "Scan Completed", f"Scan finished: {len(found)} online devices discovered.")

            def on_err(err: str):
                scan_state["running"] = False
                scan_state["last_error"] = err
                database.insert_alert("CRITICAL", "Scan Error", f"Discovery scan failed: {err}")

            scanner.scan(sub, on_prog, on_comp, on_err, on_device_found=on_dev_found)
            self._send_json({"message": "Discovery scan launched successfully", "subnet": str(sub)})
            return

        if path == "/api/scan/stop":
            scanner.stop()
            scan_state["running"] = False
            database.insert_alert("WARNING", "Scan Aborted", "User manually canceled the discovery scan.")
            self._send_json({"message": "Scan stop signal sent"})
            return

        if path == "/api/ports/scan":
            ip = body.get("ip")
            if not ip:
                self._send_error_json("Target IP is required")
                return
            try:
                import ipaddress
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private:
                    self._send_error_json("Target IP must be a private network address to prevent SSRF")
                    return
            except ValueError:
                self._send_error_json("Invalid IP address format")
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
            database.update_device_meta(ip, custom_name, notes, dev_type, hostname, vendor, mac, location)
            if ip in in_memory_devices:
                dev = in_memory_devices[ip]
                dev.custom_name = custom_name
                dev.notes = notes
                if dev_type: dev.device_type = dev_type
                if hostname: dev.hostname = hostname
                if vendor: dev.vendor = vendor
                if mac: dev.mac = mac
            self._send_json({"message": "Device metadata updated successfully", "ip": ip})
            return

        if path == "/api/device/create":
            ip = body.get("ip")
            if not ip:
                self._send_error_json("IP address is required")
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
                device_type=dev_type,
                custom_name=custom_name,
                notes=notes,
            )
            database.insert_alert("INFO", "Custom Device Added", f"Manually created device {custom_name or ip} ({dev_type})", ip)
            self._send_json({"message": "Device created successfully", "ip": ip})
            return

        if path == "/api/device/delete":
            ip = body.get("ip")
            if not ip:
                self._send_error_json("Target IP is required")
                return
            database.delete_device(ip)
            if ip in in_memory_devices:
                del in_memory_devices[ip]
            database.insert_alert("WARNING", "Device Removed", f"Deleted device node {ip} from network registry", ip)
            self._send_json({"message": "Device deleted successfully", "ip": ip})
            return

        if path == "/api/device/ping":
            ip = body.get("ip")
            if not ip:
                self._send_error_json("Target IP is required")
                return
            from src.core.models import Device
            from src.discovery.scanner import ping_host
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
            database.insert_alert("INFO", "Database Reset", "Cleared all stored network devices, alerts, and history logs.")
            database.insert_activity_log("Admin User", "DATABASE_RESET", "Wiped network database inventory and scan logs.")
            self._send_json({"message": "Database cleared successfully"})
            return



        self._send_error_json("Endpoint not found", code=404)


def run_server(port: int = 8000, open_browser: bool = True) -> HTTPServer:
    try:
        httpd = HTTPServer(("0.0.0.0", port), NOCRequestHandler)
    except OSError:
        httpd = HTTPServer(("127.0.0.1", port), NOCRequestHandler)
    print(f"===========================================================")
    print(f"🚀 LAN Watchtower NOC Server running at http://localhost:{port}")
    print(f"===========================================================")

    if open_browser:
        threading.Thread(target=lambda: (time.sleep(1.0), webbrowser.open(f"http://localhost:{port}")), daemon=True).start()

    return httpd


def main() -> None:
    """Run the canonical API without opening a desktop browser."""
    port = int(os.environ.get("API_PORT", "8000"))
    server = run_server(port, open_browser=False)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    main()
