import unittest
import logging
from ipaddress import IPv4Address
from ipware import IpWare

logging.disable(logging.CRITICAL)  # Disable logging for the entire file


class TestIPv4Common(unittest.TestCase):
    """IPv4 Default Test"""

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
            "HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_meta_multi(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157, 198.84.193.158",
            "REMOTE_ADDR": "177.139.233.133",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_multi_precedence_order(self):
        meta = {
            "X_FORWARDED_FOR": "177.139.233.138, 198.84.193.157, 198.84.193.158",
            "HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157, 198.84.193.158",
            "REMOTE_ADDR": "177.139.233.133",
        }
        ipware = IpWare(precedence=["HTTP_X_FORWARDED_FOR", "X_FORWARDED_FOR"])
        r = ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_multi_precedence_private_first(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "10.0.0.0, 10.0.0.1, 10.0.0.2",
            "X_FORWARDED_FOR": "177.139.233.138, 198.84.193.157, 198.84.193.158",
            "REMOTE_ADDR": "177.139.233.133",
        }
        ipware = IpWare(precedence=["HTTP_X_FORWARDED_FOR", "X_FORWARDED_FOR"])
        r = ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.138"), False))

    def test_multi_precedence_invalid_first(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "unknown, 10.0.0.1, 10.0.0.2",
            "X_FORWARDED_FOR": "177.139.233.138, 198.84.193.157, 198.84.193.158",
            "REMOTE_ADDR": "177.139.233.133",
        }
        ipware = IpWare(precedence=["HTTP_X_FORWARDED_FOR", "X_FORWARDED_FOR"])
        r = ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.138"), False))

    def test_error_only(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "unknown, 177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (None, False))

    def test_error_first(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "unknown, 177.139.233.139, 198.84.193.157, 198.84.193.158",
            "X_FORWARDED_FOR": "177.139.233.138, 198.84.193.157, 198.84.193.158",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.138"), False))

    def test_singleton(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_singleton_private_fallback(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "10.0.0.0",
            "HTTP_X_REAL_IP": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_best_matched_ip(self):
        meta = {
            "HTTP_X_REAL_IP": "192.168.1.1",
            "REMOTE_ADDR": "177.31.233.133",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.31.233.133"), False))

    def test_best_matched_ip_public(self):
        meta = {
            "HTTP_X_REAL_IP": "177.31.233.122",
            "REMOTE_ADDR": "177.31.233.133",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.31.233.122"), False))

    def test_best_matched_ip_private(self):
        meta = {
            "HTTP_X_REAL_IP": "192.168.1.1",
            "REMOTE_ADDR": "127.0.0.1",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("192.168.1.1"), False))

    def test_best_matched_ip_private_loopback_precedence(self):
        meta = {
            "HTTP_X_REAL_IP": "127.0.0.1",
            "REMOTE_ADDR": "192.168.1.1",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("192.168.1.1"), False))

    def test_best_matched_ip_private_precedence(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "172.25.0.1",
            "REMOTE_ADDR": "172.25.0.3",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("172.25.0.1"), False))

    def test_100_low_range_public(self):
        meta = {
            "HTTP_X_REAL_IP": "100.63.0.9",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("100.63.0.9"), False))

    def test_100_block_private(self):
        meta = {
            "HTTP_X_REAL_IP": "100.76.0.9",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("100.76.0.9"), False))

    def test_100_high_range_public(self):
        meta = {
            "HTTP_X_REAL_IP": "100.128.0.9",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("100.128.0.9"), False))

    def test_proxy_order_right_most(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        ipware = IpWare(leftmost=False)
        r = ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("198.84.193.158"), False))


class TestIPv4ProxyCount(unittest.TestCase):
    """IPv4 Proxy Count Test"""

    def setUp(self):
        self.ipware = IpWare(proxy_count=1)

    def tearDown(self):
        self.ipware = None

    def test_singleton_proxy_count(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (None, False))

    def test_singleton_proxy_count_private(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "10.0.0.0",
            "HTTP_X_REAL_IP": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (None, False))

    def test_proxy_count_relax(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = self.ipware.get_client_ip(meta, strict=False)
        self.assertEqual(r, (IPv4Address("198.84.193.157"), True))

    def test_proxy_count_strict(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.138, 177.139.233.139, 198.84.193.158",
        }
        r = self.ipware.get_client_ip(meta, strict=True)
        self.assertEqual(r, (None, False))


class TestIPv4ProxyList(unittest.TestCase):
    """IPv4 Proxy List Test"""

    def setUp(self):
        self.ipware = IpWare(proxy_list=["198.84.193.157", "198.84.193.158"])

    def tearDown(self):
        self.ipware = None

    def test_proxy_list_strict_success(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = self.ipware.get_client_ip(meta, strict=True)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), True))

    def test_proxy_list_strict_failure(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.138, 177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = self.ipware.get_client_ip(meta, strict=True)
        self.assertEqual(r, (None, False))

    def test_proxy_list_success(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.138, 177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), True))


class TestIPv4ProxyCountProxyList(unittest.TestCase):
    """IPv4 Proxy Count Test"""

    def setUp(self):
        self.ipware = IpWare(
            proxy_count=2, proxy_list=["198.84.193.157", "198.84.193.158"]
        )

    def tearDown(self):
        self.ipware = None

    def test_proxy_list_relax(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.138, 177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), True))

    def test_proxy_list_strict(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.138, 177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = self.ipware.get_client_ip(meta, strict=True)
        self.assertEqual(r, (None, False))


class TestIPv4Port(unittest.TestCase):
    """IPv4 Port - IP address Test"""

    def setUp(self):
        self.ipware = IpWare()

    def tearDown(self):
        self.ipware = None

    def test_ipv4_public_with_port(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139:80",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_private_with_port(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "10.0.0.1:443, 10.0.0.1, 10.0.0.2",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("10.0.0.1"), False))

    def test_ipv4_loopback_with_port(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "127.0.0.1:80",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("127.0.0.1"), False))


if __name__ == "__main__":
    unittest.main()
