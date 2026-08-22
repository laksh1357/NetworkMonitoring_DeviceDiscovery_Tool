import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from main import Device, detect_local_subnet, has_admin_privileges, normalize_mac
from vendor_lookup import lookup_vendor, normalize_mac_prefix
from database_manager import NetworkDatabase
from port_scanner import OpenPort, scan_ports
from notifications import notify_new_device


class NetworkUtilityTests(unittest.TestCase):
    def test_detect_local_subnet_uses_connected_interface(self):
        class FakeSocket:
            def connect(self, address):
                self.address = address

            def getsockname(self):
                return ("192.168.50.23", 0)

            def close(self):
                pass

        with patch("main.socket.socket", return_value=FakeSocket()):
            self.assertEqual(detect_local_subnet(), ipaddress.ip_network("192.168.50.0/24"))

    def test_device_row_formats_latency_and_unknown_values(self):
        row = Device(ip="192.168.1.4", status="Online", latency_ms=3.14159, last_seen="now").as_row()
        self.assertEqual(row, ("192.168.1.4", "Unknown", "Unknown", "Unknown", "Online", "3.1 ms", "now"))

    def test_mac_normalization(self):
        self.assertEqual(normalize_mac("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(normalize_mac(""), "Unknown")

    def test_vendor_lookup_normalizes_common_mac_separators(self):
        database = {"AABBCC": "Example Networks"}
        self.assertEqual(normalize_mac_prefix("aa-bb-cc-dd-ee-ff"), "AABBCC")
        self.assertEqual(lookup_vendor("aa:bb:cc:dd:ee:ff", database), "Example Networks")

    def test_vendor_lookup_handles_unknown_and_invalid_macs(self):
        self.assertEqual(lookup_vendor("00:00:00:00:00:00", {}), "Unknown")
        self.assertEqual(lookup_vendor("not-a-mac", {}), "Unknown")

    def test_database_creates_tables_and_upserts_device_history(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "network_logs.db"
            with NetworkDatabase(database_path) as database:
                database.upsert_device("192.168.1.20", "AA:BB:CC:DD:EE:FF", "router", "Example", "first")
                database.upsert_device("192.168.1.20", "AA:BB:CC:DD:EE:FF", "router.local", "Example", "second")
                devices = database.fetch_devices()
                self.assertEqual(len(devices), 1)
                self.assertEqual(devices[0]["first_seen"], "first")
                self.assertEqual(devices[0]["last_seen"], "second")
                self.assertEqual(database_path.exists(), True)

    def test_database_records_and_fetches_scan_history(self):
        class FoundDevice:
            ip = "192.168.1.21"
            mac = "00:11:22:33:44:55"
            hostname = "laptop"
            vendor = "Example"

        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "network_logs.db") as database:
                database.record_scan([FoundDevice()], total_devices_online=1)
                logs = database.fetch_scan_logs()
                self.assertEqual(logs[0]["total_devices_online"], 1)
                self.assertIn("timestamp", logs[0])

    @patch("port_scanner.socket.create_connection")
    def test_port_scanner_returns_open_ports_and_services(self, create_connection):
        class FakeConnection:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        def connect(address, timeout):
            if address[1] == 443:
                return FakeConnection()
            raise ConnectionRefusedError

        create_connection.side_effect = connect
        self.assertEqual(scan_ports("192.168.1.5", ports=[80, 443]), [OpenPort(443, "HTTPS")])

    def test_port_scanner_validates_arguments(self):
        with self.assertRaises(ValueError):
            scan_ports("192.168.1.5", ports=[0])

    @patch("main.os.geteuid", return_value=0)
    def test_privilege_helper_detects_root(self, _geteuid):
        self.assertTrue(has_admin_privileges())

    @patch("main.os.geteuid", return_value=1000)
    def test_privilege_helper_detects_unprivileged_mode(self, _geteuid):
        self.assertFalse(has_admin_privileges())

    @patch("main.resolve_hostname", return_value="host.local")
    @patch("main.resolve_mac_from_arp", return_value="Unknown")
    @patch("main.NetworkScanner._tcp_probe", return_value=True)
    @patch("main.ping_host", return_value=(False, None))
    def test_layered_scan_uses_tcp_when_ping_is_blocked(
        self, _ping, _tcp_probe, _arp_lookup, _hostname
    ):
        scanner = __import__("main").NetworkScanner(max_workers=2, host_timeout=0.01)
        progress = []
        devices = scanner._layered_scan(ipaddress.ip_network("192.168.1.0/30"), {}, lambda done, total: progress.append((done, total)))
        self.assertEqual(len(devices), 2)
        self.assertEqual({device.status for device in devices}, {"Online"})
        self.assertEqual(progress[-1], (2, 2))

    @patch("notifications.notification")
    def test_new_device_notification_uses_hostname_or_ip(self, notifier):
        self.assertTrue(notify_new_device("192.168.1.30", "printer.local"))
        notifier.notify.assert_called_once()
        self.assertEqual(notifier.notify.call_args.kwargs["message"], "New Device Detected: printer.local")


if __name__ == "__main__":
    unittest.main()
