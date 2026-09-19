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

from database_manager import NetworkDatabase
from main import Device, NetworkScanner, detect_local_subnet
from port_scanner import scan_ports

_BASE_DIR = Path(__file__).resolve().parent
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
    "current_subnet": "192.168.1.0/24",
}
in_memory_devices: dict[str, Device] = {}
auto_scan_active = False
auto_scan_interval = 300  # seconds


def init_demo_seed_if_empty() -> None:
    """Seed sample network topology and devices if database is brand new for immediate NOC demonstration."""
    existing = database.fetch_devices()
    if len(existing) > 0:
        return

    sample_nodes = [
        ("192.168.1.1", "00:1A:2B:3C:4D:5E", "Edge-Router", "Cisco Systems", "Router", "Core Edge Gateway", "Primary ISP Uplink"),
        ("192.168.1.2", "00:1A:2B:88:99:AA", "Firewall-01", "Palo Alto Networks", "Firewall", "Main Perimeter FW", "Active HA Mode"),
        ("192.168.1.3", "00:22:55:66:77:88", "Core-Switch-01", "Cisco Systems", "Switch", "Data Center Core", "10G Fiber Backbone"),
        ("192.168.1.10", "A4:83:E7:11:22:33", "SW-1-Access", "Cisco Systems", "Switch", "Floor 1 Switch", "24-Port PoE Switch"),
        ("192.168.1.11", "A4:83:E7:44:55:66", "SW-2-Access", "Hewlett Packard", "Switch", "Floor 2 Switch", "48-Port Gigabit"),
        ("192.168.1.12", "A4:83:E7:77:88:99", "SW-3-Access", "Cisco Systems", "Switch", "Floor 3 Switch", "24-Port PoE"),
        ("192.168.1.20", "00:50:56:AA:BB:CC", "App-Server-01", "Dell Inc.", "Server", "Production Web App", "Ubuntu 22.04 LTS"),
        ("192.168.1.21", "00:50:56:DD:EE:FF", "App-Server-02", "Dell Inc.", "Server", "API Gateway", "Docker Swarm Host"),
        ("192.168.1.22", "00:50:56:11:33:55", "DB-Server-01", "Dell Inc.", "Server", "Primary PostgreSQL DB", "NVMe RAID 10 Cluster"),
        ("192.168.1.25", "00:11:32:99:88:77", "NAS-Backup-01", "Synology Inc.", "Server", "Network Storage", "120TB Btrfs Storage"),
        ("192.168.1.50", "D8:07:B6:12:34:56", "AP-Lobby", "Ubiquiti Networks", "Access Point", "Lobby Guest Wi-Fi", "UniFi 6 Pro"),
        ("192.168.1.51", "D8:07:B6:65:43:21", "AP-Office-West", "Ubiquiti Networks", "Access Point", "West Wing Wi-Fi", "UniFi 6 Long-Range"),
        ("192.168.1.101", "3c:22:fb:11:22:33", "Lakshya-MacBook", "Apple Inc.", "PC/Workstation", "Dev Workstation", "macOS Sonoma"),
        ("192.168.1.102", "54:ee:75:33:44:55", "Workstation-02", "Lenovo Group", "PC/Workstation", "CAD Design Rig", "Windows 11 Pro"),
        ("192.168.1.103", "b4:2e:99:66:77:88", "Printer-HR", "HP Inc.", "Printer", "HR Office LaserJet", "Color LaserJet Enterprise"),
    ]

    for ip, mac, host, vendor, dev_type, custom_name, notes in sample_nodes:
        database.upsert_device(
            ip=ip,
            mac=mac,
            hostname=host,
            vendor=vendor,
            device_type=dev_type,
            custom_name=custom_name,
            notes=notes,
        )
        in_memory_devices[ip] = Device(
            ip=ip,
            mac=mac,
            vendor=vendor,
            hostname=host,
            status="Online" if not ip.endswith(".103") else "Offline",
            latency_ms=1.2 if ip.endswith(".1") else (4.5 if not ip.endswith(".103") else None),
            last_seen=time.strftime("%Y-%m-%d %H:%M:%S"),
            device_type=dev_type,
            custom_name=custom_name,
            notes=notes,
        )

    database.insert_alert("INFO", "NOC Engine Online", "Network Operations Monitoring Engine initialized successfully.")
    database.insert_alert("WARNING", "High Memory Load Detected", "App-Server-02 memory usage reached 68%", "192.168.1.21")
    database.insert_alert("CRITICAL", "High Latency Warning", "SW-2-Access response time spiked above 45ms", "192.168.1.11")
    database.insert_alert("RESOLVED", "Printer-HR Back Online", "Printer device resumed network connection", "192.168.1.103")


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
                self._send_json({"subnet": "192.168.1.0/24", "num_hosts": 254, "privileged": False, "warning": str(exc)})
            return

        if path == "/api/devices":
            db_devices = database.fetch_devices()
            result = []
            for item in db_devices:
                ip = item["ip"]
                mem_dev = in_memory_devices.get(ip)
                status = mem_dev.status if mem_dev else "Online"
                latency = mem_dev.latency_ms if mem_dev else 2.4
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
                raw_sub = body.get("subnet") or "192.168.1.0/24"
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
            from main import ping_host
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

        if path == "/api/database/seed":
            init_demo_seed_if_empty()
            self._send_json({"message": "Demo data populated successfully"})
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


if __name__ == "__main__":
    server = run_server(8000, open_browser=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down NOC Web Server...")
        server.server_close()
