import ipaddress
import logging
import unittest
from typing import ClassVar

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


class TestModernFlyHeader(unittest.TestCase):
    """Fly.io support, suggested by @mdalp in #23."""

    def test_fly_client_ip_django_style(self):
        ip, _ = IpWare().get_client_ip({"HTTP_FLY_CLIENT_IP": "203.0.113.13"})
        self.assertEqual(str(ip), "203.0.113.13")

    def test_fly_client_ip_raw_header(self):
        ip, _ = IpWare().get_client_ip({"FLY-CLIENT-IP": "203.0.113.14"})
        self.assertEqual(str(ip), "203.0.113.14")


class TestModernCidrProxyList(unittest.TestCase):
    """CIDR entries in proxy_list, requested by @griffi-gh in #26."""

    def test_ipv4_cidr_trusted(self):
        ipw = IpWare(proxy_list=["100.64.0.0/10"])
        meta = {"HTTP_X_FORWARDED_FOR": "177.139.233.139, 100.100.1.2"}
        self.assertEqual(ipw.get_client_ip(meta), (ipaddress.ip_address("177.139.233.139"), True))

    def test_ipv4_cidr_outside_rejected(self):
        ipw = IpWare(proxy_list=["100.64.0.0/10"])
        meta = {"HTTP_X_FORWARDED_FOR": "177.139.233.139, 100.128.0.1"}
        self.assertEqual(ipw.get_client_ip(meta), (None, False))

    def test_cidr_is_not_a_string_prefix(self):
        # "10.1.0.0/16" must not match 10.10.x.x the way the prefix "10.1" would.
        ipw = IpWare(proxy_list=["10.1.0.0/16"])
        meta = {"HTTP_X_FORWARDED_FOR": "177.139.233.139, 10.10.0.1"}
        self.assertEqual(ipw.get_client_ip(meta), (None, False))

    def test_ipv6_cidr_trusted(self):
        ipw = IpWare(proxy_list=["fd7a:115c:a1e0::/48"])
        meta = {"HTTP_X_FORWARDED_FOR": "2606:4700::1, fd7a:115c:a1e0:ab12::1"}
        ip, trusted = ipw.get_client_ip(meta)
        self.assertEqual(str(ip), "2606:4700::1")
        self.assertTrue(trusted)

    def test_cross_version_never_matches(self):
        ipw = IpWare(proxy_list=["fd7a:115c:a1e0::/48"])
        meta = {"HTTP_X_FORWARDED_FOR": "177.139.233.139, 100.100.1.2"}
        self.assertEqual(ipw.get_client_ip(meta), (None, False))

    def test_mixed_cidr_and_prefix(self):
        ipw = IpWare(proxy_list=["198.84.", "100.64.0.0/10"])
        meta = {"HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157, 100.100.1.2"}
        ip, trusted = ipw.get_client_ip(meta, strict=True)
        self.assertEqual(str(ip), "177.139.233.139")
        self.assertTrue(trusted)

    def test_invalid_cidr_raises(self):
        with self.assertRaises(ValueError):
            IpWare(proxy_list=["300.1.0.0/16"])

    def test_legacy_unchanged(self):
        # Legacy is frozen: CIDR text is still treated as a literal prefix there.
        ipw = IpWare(algorithm="legacy", proxy_list=["100.64.0.0/10"])
        meta = {"HTTP_X_FORWARDED_FOR": "177.139.233.139, 100.100.1.2"}
        self.assertEqual(ipw.get_client_ip(meta), (None, False))


class TestModernRightmost(unittest.TestCase):
    """leftmost=False must validate proxies and pick the client from the same end."""

    XFF: ClassVar[dict[str, str]] = {
        "HTTP_X_FORWARDED_FOR": "198.84.193.158, 198.84.193.157, 177.139.233.139"
    }

    def test_rightmost_proxy_list_exact(self):
        ipw = IpWare(leftmost=False, proxy_list=["198.84.193.157", "198.84.193.158"])
        ip, trusted = ipw.get_client_ip(self.XFF, strict=True)
        self.assertEqual(str(ip), "177.139.233.139")
        self.assertTrue(trusted)

    def test_rightmost_proxy_list_prefix(self):
        ipw = IpWare(leftmost=False, proxy_list=["198.84"])
        ip, trusted = ipw.get_client_ip(self.XFF)
        self.assertEqual(str(ip), "198.84.193.157")
        self.assertTrue(trusted)

    def test_rightmost_untrusted_proxy_rejected(self):
        ipw = IpWare(leftmost=False, proxy_list=["10.0.0."])
        self.assertEqual(ipw.get_client_ip(self.XFF), (None, False))


class TestModernStrict(unittest.TestCase):
    def test_strict_rejects_empty_token(self):
        meta = {"HTTP_X_FORWARDED_FOR": "1.2.3.4,, 5.6.7.8"}
        self.assertEqual(IpWare().get_client_ip(meta, strict=True), (None, False))

    def test_non_strict_skips_empty_token(self):
        meta = {"HTTP_X_FORWARDED_FOR": "1.2.3.4,, 5.6.7.8"}
        ip, _ = IpWare().get_client_ip(meta)
        self.assertEqual(str(ip), "1.2.3.4")


class TestModernMatchesLegacy(unittest.TestCase):
    """Differential check: on well-formed input, modern must agree with legacy
    for every combination of direction, proxy_count, proxy_list and strict."""

    CHAINS = (
        "177.139.233.139",
        "177.139.233.139, 198.84.193.157",
        "177.139.233.139, 198.84.193.157, 198.84.193.158",
        "198.84.193.158, 198.84.193.157, 177.139.233.139",
        "10.0.0.1, 177.139.233.139, 198.84.193.157",
        "192.168.1.1, 10.0.0.2",
        "127.0.0.1, 198.84.193.157",
        "2001:db8::1, 2606:4700::1",
        "[2606:4700::6810:84e5]:443, 198.84.193.157:8080",
        "::ffff:177.139.233.139, 198.84.193.157",
        "not-an-ip, 177.139.233.139, 198.84.193.157",
    )
    PROXY_COUNTS = (None, 0, 1, 2, 3)
    PROXY_LISTS = (
        None,
        ["198.84.193.157"],
        ["198.84.193.157", "198.84.193.158"],
        ["198.84.193.158", "198.84.193.157"],
        ["198.84"],
        ["10.0.0."],
        ["177.139.233.139"],
    )

    def test_engines_agree(self):
        checked = 0
        for raw in self.CHAINS:
            for header in ("HTTP_X_FORWARDED_FOR", "REMOTE_ADDR"):
                meta = {header: raw}
                for leftmost in (True, False):
                    for count in self.PROXY_COUNTS:
                        for plist in self.PROXY_LISTS:
                            kw = {"leftmost": leftmost, "proxy_count": count, "proxy_list": plist}
                            legacy = IpWare(algorithm="legacy", **kw)
                            modern = IpWare(algorithm="modern", **kw)
                            for strict in (False, True):
                                with self.subTest(raw=raw, header=header, strict=strict, **kw):
                                    self.assertEqual(
                                        modern.get_client_ip(meta, strict),
                                        legacy.get_client_ip(meta, strict),
                                    )
                                checked += 1
        self.assertGreater(checked, 3000)


if __name__ == "__main__":
    unittest.main()
