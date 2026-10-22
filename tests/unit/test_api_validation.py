"""Request validation tests for the public API boundary."""

from __future__ import annotations

import unittest

from src.api.validation import parse_private_ipv4_address, parse_private_scan_subnet


class PrivateSubnetValidationTests(unittest.TestCase):
    def test_accepts_small_private_ipv4_subnet(self):
        self.assertEqual(str(parse_private_scan_subnet("192.168.1.0/24")), "192.168.1.0/24")

    def test_rejects_public_ipv4_subnet(self):
        with self.assertRaisesRegex(ValueError, "private"):
            parse_private_scan_subnet("8.8.8.0/24")

    def test_rejects_ipv6_subnet(self):
        with self.assertRaisesRegex(ValueError, "IPv4"):
            parse_private_scan_subnet("fd00::/120")

    def test_rejects_large_private_subnet(self):
        with self.assertRaisesRegex(ValueError, "1024"):
            parse_private_scan_subnet("10.0.0.0/21")

    def test_rejects_missing_subnet(self):
        with self.assertRaisesRegex(ValueError, "CIDR"):
            parse_private_scan_subnet(None)

    def test_rejects_reserved_but_non_rfc1918_range(self):
        with self.assertRaisesRegex(ValueError, "private"):
            parse_private_scan_subnet("192.0.0.0/24")

    def test_accepts_and_rejects_only_rfc1918_target_addresses(self):
        self.assertEqual(str(parse_private_ipv4_address("192.168.1.8")), "192.168.1.8")
        for target in ("8.8.8.8", "192.0.0.8", "fd00::1", "127.0.0.1"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                parse_private_ipv4_address(target)


if __name__ == "__main__":
    unittest.main()
