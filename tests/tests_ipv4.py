import unittest
import logging
from ipaddress import IPv4Address
from python_ipware import IpWare

logging.disable(logging.CRITICAL)  # Disable logging for the entire file


class TestIPv4Common(unittest.TestCase):
    """IPv4 Default Test"""

    def setUp(self):
        self.ipware = IpWare()

    def tearDown(self):
        self.ipware = None

    def test_meta_none(self):
        meta = None
        ip, trusted = self.ipware.get_client_ip(meta)
        self.assertIsNone(ip)
        self.assertFalse(trusted)

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
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_error_only_strict(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "unknown, 177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = self.ipware.get_client_ip(meta, strict=True)
        self.assertEqual(r, (None, False))

    def test_error_only_first_strict(self):
        meta = {
            "X_FORWARDED_FOR": "177.139.233.138, 198.84.193.157, 198.84.193.158",
            "HTTP_X_FORWARDED_FOR": "unknown, 177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = self.ipware.get_client_ip(meta, strict=True)
        self.assertEqual(r, (IPv4Address("177.139.233.138"), False))

    def test_error_first(self):
        meta = {
            "X_FORWARDED_FOR": "unknown, 177.139.233.138, 198.84.193.157, 198.84.193.158",
            "HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157, 198.84.193.158",
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

    def test_proxy_count_one_missing_proxy_fail(self):
        ipware = IpWare(proxy_count=1)
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139",
        }
        r = ipware.get_client_ip(meta)

        self.assertEqual(r, (None, False))

    def test_proxy_count_one_at_least_one_proxy_pass(self):
        ipware = IpWare(proxy_count=1)
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("198.84.193.157"), True))

    def test_proxy_count_one_exactly_one_proxy_fail(self):
        ipware = IpWare(proxy_count=1)
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = ipware.get_client_ip(meta, strict=True)
        self.assertEqual(r, (None, False))

    def test_proxy_count_one_exactly_one_proxy_pass(self):
        ipware = IpWare(proxy_count=1)
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157",
        }
        r = ipware.get_client_ip(meta, strict=True)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), True))

    def test_proxy_count_one_dont_care_proxy_pass(self):
        ipware = IpWare()
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_proxy_count_zero_dont_care_proxy_pass(self):
        ipware = IpWare(proxy_count=0)
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("198.84.193.158"), True))

    def test_proxy_count_zero_exact_zero_proxy_pass(self):
        ipware = IpWare(proxy_count=0)
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139",
        }
        r = ipware.get_client_ip(meta, strict=True)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), True))

    def test_proxy_count_zero_exact_zero_proxy_fail(self):
        ipware = IpWare(proxy_count=0)
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = ipware.get_client_ip(meta, strict=True)
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

    def test_proxy_list_relax(self):
        ipware = IpWare(proxy_list=["198.84.193.157", "198.84.193.158"])
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.138, 177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), True))

    def test_proxy_list_strict_pass(self):
        ipware = IpWare(proxy_list=["198.84.193.157", "198.84.193.158"])
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = ipware.get_client_ip(meta, strict=True)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), True))

    def test_proxy_list_strict_fail(self):
        ipware = IpWare(proxy_list=["198.84.193.157", "198.84.193.158"])
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.138, 177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = ipware.get_client_ip(meta, strict=True)
        self.assertEqual(r, (None, False))

    def test_proxy_list_relax_exact_pass(self):
        ipware = IpWare(proxy_count=2, proxy_list=["198.84.193.157", "198.84.193.158"])
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.138, 177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), True))

    def test_proxy_list_relax_count_under_pass(self):
        ipware = IpWare(proxy_count=1, proxy_list=["198.84.193.157", "198.84.193.158"])
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.138, 177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), True))

    def test_proxy_list_relax_count_over_pass(self):
        ipware = IpWare(proxy_count=5, proxy_list=["198.84.193.157", "198.84.193.158"])
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.138, 177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = ipware.get_client_ip(meta)
        self.assertEqual(r, (None, False))

    def test_proxy_list_count_exact_pass(self):
        ipware = IpWare(proxy_count=2, proxy_list=["198.84.193.157", "198.84.193.158"])
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.138, 177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), True))

    def test_proxy_list_count_exact_fail(self):
        ipware = IpWare(proxy_count=4, proxy_list=["198.84.193.157", "198.84.193.158"])
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.138, 177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        r = ipware.get_client_ip(meta)
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


class TestIPv4Headers(unittest.TestCase):
    """IPv4 Headers - IP address Headers Test"""

    def setUp(self):
        self.ipware = IpWare()

    def tearDown(self):
        self.ipware = None

    def test_ipv4_x_forwarded_for(self):
        meta = {
            "X_FORWARDED_FOR": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_http_x_forwarded_for(self):
        meta = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_http_http_client_ip(self):
        meta = {
            "HTTP_CLIENT_IP": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_http_x_real_ip(self):
        meta = {
            "HTTP_X_REAL_IP": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_http_x_forwarded(self):
        meta = {
            "HTTP_X_FORWARDED": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_http_x_cluster_client_ip(self):
        meta = {
            "HTTP_X_CLUSTER_CLIENT_IP": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_http_http_forwarded_for(self):
        meta = {
            "HTTP_FORWARDED_FOR": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_http_http_forwarded(self):
        meta = {
            "HTTP_FORWARDED": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_x_client_ip(self):
        meta = {
            "X-CLIENT-IP": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_x_real_ip(self):
        meta = {
            "X-REAL-IP": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_x_cluster_client_ip(self):
        meta = {
            "X-CLUSTER-CLIENT-IP": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_x_forwarded(self):
        meta = {
            "X_FORWARDED": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_forwarded_for(self):
        meta = {
            "FORWARDED_FOR": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_cf_connecting_ip(self):
        meta = {
            "CF-CONNECTING-IP": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_true_client_ip(self):
        meta = {
            "TRUE-CLIENT-IP": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_fastly_client_ip(self):
        meta = {
            "FASTLY-CLIENT-IP": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_forwarded(self):
        meta = {
            "FORWARDED": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_client_ip(self):
        meta = {
            "CLIENT-IP": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))

    def test_ipv4_remote_addr(self):
        meta = {
            "REMOTE_ADDR": "177.139.233.139",
        }
        r = self.ipware.get_client_ip(meta)
        self.assertEqual(r, (IPv4Address("177.139.233.139"), False))


if __name__ == "__main__":
    unittest.main()
