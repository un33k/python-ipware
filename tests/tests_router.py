import logging
import unittest

from python_ipware import IpWare, LegacyIpWare, ModernIpWare

logging.disable(logging.CRITICAL)


class TestAlgorithmRouter(unittest.TestCase):
    def test_default_is_auto_modern(self):
        ipw = IpWare()
        self.assertEqual(ipw.algorithm, "auto")
        self.assertEqual(ipw.resolved_algorithm, "modern")
        self.assertIsInstance(ipw.engine, ModernIpWare)

    def test_explicit_modern(self):
        self.assertIsInstance(IpWare(algorithm="modern").engine, ModernIpWare)

    def test_explicit_legacy(self):
        ipw = IpWare(algorithm="legacy")
        self.assertEqual(ipw.resolved_algorithm, "legacy")
        self.assertIsInstance(ipw.engine, LegacyIpWare)

    def test_invalid_algorithm(self):
        with self.assertRaises(ValueError):
            IpWare(algorithm="bogus")

    def test_all_algorithms_agree_on_simple_chain(self):
        meta = {"HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157, 198.84.193.158"}
        results = {
            algo: str(IpWare(algorithm=algo).get_client_ip(meta)[0])
            for algo in ("auto", "modern", "legacy")
        }
        self.assertEqual(set(results.values()), {"177.139.233.139"})


class TestModernNewHeaders(unittest.TestCase):
    def test_true_client_ip(self):
        ip, _ = IpWare().get_client_ip({"HTTP_TRUE_CLIENT_IP": "203.0.113.10"})
        self.assertEqual(str(ip), "203.0.113.10")

    def test_fastly_client_ip(self):
        ip, _ = IpWare().get_client_ip({"HTTP_FASTLY_CLIENT_IP": "203.0.113.11"})
        self.assertEqual(str(ip), "203.0.113.11")

    def test_appengine_user_ip(self):
        ip, _ = IpWare().get_client_ip({"HTTP_X_APPENGINE_USER_IP": "203.0.113.12"})
        self.assertEqual(str(ip), "203.0.113.12")


class TestModernHardening(unittest.TestCase):
    def test_quoted_token(self):
        ip, _ = IpWare().get_client_ip({"REMOTE_ADDR": '"8.8.8.8"'})
        self.assertEqual(str(ip), "8.8.8.8")

    def test_ipv4_mapped_unwrapped(self):
        ip, _ = IpWare().get_client_ip({"REMOTE_ADDR": "::ffff:8.8.8.8"})
        self.assertEqual(str(ip), "8.8.8.8")

    def test_bracketed_ipv6_with_port(self):
        ip, _ = IpWare().get_client_ip({"REMOTE_ADDR": "[2001:db8::1]:443"})
        self.assertEqual(str(ip), "2001:db8::1")


if __name__ == "__main__":
    unittest.main()
