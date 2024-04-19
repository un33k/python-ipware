import unittest
import logging
from ipaddress import IPv4Address, IPv6Address

from python_ipware import IpWare

logging.disable(logging.CRITICAL)  # Disable logging for the entire file


class TestIPv6Common(unittest.TestCase):
    """IPv6 Default"""

    def setUp(self):
        self.ipware = IpWare()

    def tearDown(self):
        self.ipware = None

    def test_meta_empty(self):
        meta = {}
        ip, trusted = self.ipware.get_client_ip(meta)
        self.assertIsNone(ip)
        self.assertFalse(trusted)

    def test_meta_single(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv6Address("3ffe:1900:4545:3:200:f8ff:fe21:67cf"), False))

    def test_meta_multi(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888",
            "REMOTE_ADDR": "74dc:2bc",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv6Address("3ffe:1900:4545:3:200:f8ff:fe21:67cf"), False))

    def test_multi_precedence_order(self):
        meta = {
            "X_FORWARDED_FOR": "74dc:2be, 74dc:2bf",
            "HTTP_X_FORWARDED_FOR": "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888",
            "REMOTE_ADDR": "74dc:2bc",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv6Address("3ffe:1900:4545:3:200:f8ff:fe21:67cf"), False))

    def test_multi_precedence_private_first(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "2001:db8:, ::1",
            "X_FORWARDED_FOR": "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888",
            "REMOTE_ADDR": "74dc:2bc",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv6Address("3ffe:1900:4545:3:200:f8ff:fe21:67cf"), False))

    def test_multi_precedence_invalid_first(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "unknown, 2001:db8:, ::1",
            "X_FORWARDED_FOR": "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888",
            "REMOTE_ADDR": "74dc:2bc",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv6Address("3ffe:1900:4545:3:200:f8ff:fe21:67cf"), False))

    def test_error_only(self):
        meta = {
            "X_FORWARDED_FOR": "unknown, 3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv6Address("3ffe:1900:4545:3:200:f8ff:fe21:67cf"), False))

    def test_error_only_strict(self):
        meta = {
            "X_FORWARDED_FOR": "unknown, 3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888",
        }
        r = self.ipware.get_client_ip(meta, strict=True)
        self.assertEqual(r, (None, False))

    def test_first_error_bailout(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "unknown, 3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888",
            "X_FORWARDED_FOR": "2606:4700:4700::1111, 2001:4860:4860::8888",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv6Address("2606:4700:4700::1111"), False))

    def test_with_error_best_match(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "unknown, 3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888",
            "X_FORWARDED_FOR": "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv6Address("3ffe:1900:4545:3:200:f8ff:fe21:67cf"), False))

    def test_singleton(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "3ffe:1900:4545:3:200:f8ff:fe21:67cf",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv6Address("3ffe:1900:4545:3:200:f8ff:fe21:67cf"), False))

    def test_singleton_private_fallback(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "::1",
            "HTTP_X_REAL_IP": "3ffe:1900:4545:3:200:f8ff:fe21:67cf",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv6Address("3ffe:1900:4545:3:200:f8ff:fe21:67cf"), False))


class TestIPv6ProxyCount(unittest.TestCase):
    """IPv6 Proxy Count Test"""

    def setUp(self):
        self.ipware = IpWare(proxy_count=1)

    def tearDown(self):
        self.ipware = None

    def test_singleton_proxy_count(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "3ffe:1900:4545:3:200:f8ff:fe21:67cf",
            "HTTP_X_REAL_IP": "2606:4700:4700::1111",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (None, False))

    def test_singleton_proxy_count_private(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "::1",
            "HTTP_X_REAL_IP": "3ffe:1900:4545:3:200:f8ff:fe21:67cf",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (None, False))


class TestIPv6ProxyList(unittest.TestCase):
    """IPv6 Proxy List Test"""

    def setUp(self):
        self.ipware = IpWare(
            proxy_list=["2606:4700:4700::1111", "2001:4860:4860::8888"]
        )

    def tearDown(self):
        self.ipware = None

    def test_proxy_trusted_proxy_strict(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888",
        }
        r = self.ipware.get_client_ip(meta, strict=True)
        self.assertEqual(r, (IPv6Address("3ffe:1900:4545:3:200:f8ff:fe21:67cf"), True))

    def test_proxy_trusted_proxy_not_strict(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv6Address("3ffe:1900:4545:3:200:f8ff:fe21:67cf"), True))

    def test_proxy_trusted_proxy_not_strict_long(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "2001:4860:4860::7777,3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv6Address("3ffe:1900:4545:3:200:f8ff:fe21:67cf"), True))

    def test_proxy_trusted_proxy_error(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 74dc::2bb",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (None, False))


class TestIPv6Encapsulation(unittest.TestCase):
    """IPv6 Encapsulation of IPv4 - IP address Test"""

    def setUp(self):
        self.ipware = IpWare()

    def tearDown(self):
        self.ipware = None

    def test_ipv6_encapsulation_of_ipv4_private(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "::ffff:127.0.0.1",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("127.0.0.1"), False))

    def test_ipv6_encapsulation_of_ipv4_public(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "::ffff:177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))


class TestIPv6Port(unittest.TestCase):
    """IPv6 Port - IP address Test"""

    def setUp(self):
        self.ipware = IpWare()

    def tearDown(self):
        self.ipware = None

    def test_ipv6_encapsulation_of_ipv4_public_with_port(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "[::ffff:177.139.233.139]:80",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv6_public_with_port(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "[3ffe:1900:4545:3:200:f8ff:fe21:67cf]:443, 2606:4700:4700::1111, 2001:4860:4860::8888",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv6Address("3ffe:1900:4545:3:200:f8ff:fe21:67cf"), False))

    def test_ipv6_loopback_with_port(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "[::1]:80",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv6Address("::1"), False))


if __name__ == "__main__":
    unittest.main()
