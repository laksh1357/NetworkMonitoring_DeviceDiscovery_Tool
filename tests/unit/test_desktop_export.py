import unittest

from desktop.app import CSV_EXPORT_HEADERS, device_csv_row, display_device_status
from port_scanner import OpenPort
from src.core.models import Device


class DesktopExportTests(unittest.TestCase):
    def test_status_normalization_matches_visible_online_status(self):
        self.assertEqual(display_device_status("ONLINE"), "Online")
        self.assertEqual(display_device_status("Online"), "Online")
        self.assertEqual(display_device_status("offline"), "Offline")
        self.assertEqual(display_device_status("other"), "Unknown")

    def test_csv_row_matches_headers_and_orders_fields_correctly(self):
        device = Device(
            ip="192.168.1.12", hostname="lab-pc", mac="AA:BB:CC:DD:EE:FF",
            vendor="Example Vendor", status="ONLINE", latency_ms=12.345,
            last_seen="2026-10-27 14:00:00",
        )
        row = device_csv_row(device, [OpenPort(443, "HTTPS"), OpenPort(80, "HTTP")])
        self.assertEqual(len(row), len(CSV_EXPORT_HEADERS))
        self.assertEqual(row, (
            "lab-pc", "192.168.1.12", "AA:BB:CC:DD:EE:FF", "Example Vendor",
            "Online", "12.3 ms", "80 (HTTP); 443 (HTTPS)", "2026-10-27 14:00:00",
        ))

    def test_csv_row_marks_unmeasured_values_explicitly(self):
        device = Device(ip="192.168.1.15", status="Offline")
        row = device_csv_row(device)
        self.assertEqual(row[1], "192.168.1.15")
        self.assertEqual(row[4], "Offline")
        self.assertEqual(row[5], "Unavailable")
        self.assertEqual(row[6], "None discovered")


if __name__ == "__main__":
    unittest.main()
