import ipaddress
import logging
import unittest
from typing import ClassVar

from python_ipware import IpWare, LegacyIpWare, ModernIpWare
from python_ipware.modern.defaults import DEFAULT_PRECEDENCE
from python_ipware.modern.parsers import TIER_GLOBAL, TIER_REJECT, ip_tier

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


class TestModernRfc7239Forwarded(unittest.TestCase):
    """RFC 7239 ``Forwarded`` elements are reduced to their ``for=`` value."""

    def test_ipv4_with_params(self):
        meta = {"HTTP_FORWARDED": "for=203.0.113.60;proto=https;by=198.51.100.1"}
        ip, _ = IpWare().get_client_ip(meta)
        self.assertEqual(str(ip), "203.0.113.60")

    def test_quoted_bracketed_ipv6_with_port(self):
        meta = {"HTTP_FORWARDED": 'for="[2001:4860::17]:4711"'}
        ip, _ = IpWare().get_client_ip(meta)
        self.assertEqual(str(ip), "2001:4860::17")

    def test_param_name_case_insensitive(self):
        meta = {"HTTP_FORWARDED": "proto=http;For=203.0.113.61"}
        ip, _ = IpWare().get_client_ip(meta)
        self.assertEqual(str(ip), "203.0.113.61")

    def test_multi_hop_with_proxy_count(self):
        # Globally routable addresses: the trusted flag is only kept for a global client.
        meta = {"HTTP_FORWARDED": "for=177.139.233.139, for=198.84.193.157;by=198.84.193.158"}
        ip, trusted = IpWare(proxy_count=1).get_client_ip(meta, strict=True)
        self.assertEqual(str(ip), "177.139.233.139")
        self.assertTrue(trusted)

    def test_obfuscated_hop_strict_rejects(self):
        meta = {"HTTP_FORWARDED": "for=unknown, for=198.51.100.7"}
        self.assertEqual(IpWare().get_client_ip(meta, strict=True), (None, False))

    def test_obfuscated_hop_non_strict_skips(self):
        meta = {"HTTP_FORWARDED": "for=_hidden, for=198.51.100.7"}
        ip, _ = IpWare().get_client_ip(meta)
        self.assertEqual(str(ip), "198.51.100.7")

    def test_element_without_for_is_invalid(self):
        meta = {"HTTP_FORWARDED": "proto=https;by=198.51.100.1"}
        self.assertEqual(IpWare().get_client_ip(meta), (None, False))


class TestModernMalformedRejected(unittest.TestCase):
    """Malformed tokens are rejected, never truncated into a valid-looking IP."""

    def test_malformed_tokens(self):
        for value in (
            "[2606:4700::1",  # unclosed bracket
            "[2606:4700::1]junk",  # text after the bracket
            "8.8.8.8:abc",  # non-numeric port
            "8.8.8.8:70000",  # port out of range
            "8.8.8.8:\u00b2",  # Unicode digit that isdigit() accepts
            "8.8.8.8:",  # empty port
        ):
            with self.subTest(value=value):
                self.assertEqual(IpWare().get_client_ip({"REMOTE_ADDR": value}), (None, False))

    def test_valid_ports_still_accepted(self):
        for value, expected in (("8.8.8.8:443", "8.8.8.8"), ("[2606:4700::1]:65535", "2606:4700::1")):
            with self.subTest(value=value):
                ip, _ = IpWare().get_client_ip({"REMOTE_ADDR": value})
                self.assertEqual(str(ip), expected)


class TestModernMetaHardening(unittest.TestCase):
    def test_non_string_values_are_ignored(self):
        for bad in (None, b"1.2.3.4", ["1.2.3.4"], 42):
            with self.subTest(bad=bad):
                meta = {"HTTP_X_FORWARDED_FOR": bad, "REMOTE_ADDR": "8.8.8.8"}
                ip, _ = IpWare().get_client_ip(meta)
                self.assertEqual(str(ip), "8.8.8.8")

    def test_lowercase_keys_match(self):
        # AWS Lambda / API Gateway v2 deliver lowercase header names.
        meta = {"x-forwarded-for": "203.0.113.70, 198.51.100.1"}
        ip, _ = IpWare().get_client_ip(meta)
        self.assertEqual(str(ip), "203.0.113.70")

    def test_exact_key_beats_folded_key(self):
        meta = {"X_FORWARDED_FOR": "203.0.113.71", "x-forwarded-for": "203.0.113.72"}
        ip, _ = IpWare().get_client_ip(meta)
        self.assertEqual(str(ip), "203.0.113.71")

    def test_empty_proxy_entry_raises(self):
        for plist in ([""], ["  "], ["10.0.0.", ""]):
            with self.subTest(plist=plist), self.assertRaises(ValueError):
                IpWare(proxy_list=plist)

    def test_proxy_prefix_whitespace_is_stripped(self):
        ipw = IpWare(proxy_list=[" 198.84. "])
        meta = {"HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157"}
        self.assertEqual(ipw.get_client_ip(meta), (ipaddress.ip_address("177.139.233.139"), True))


class TestModernPrecedence(unittest.TestCase):
    V400_ORDER = (
        "X_FORWARDED_FOR", "HTTP_X_FORWARDED_FOR", "HTTP_CLIENT_IP", "HTTP_X_REAL_IP",
        "HTTP_X_FORWARDED", "HTTP_X_CLUSTER_CLIENT_IP", "HTTP_FORWARDED_FOR", "HTTP_FORWARDED",
        "HTTP_CF_CONNECTING_IP", "HTTP_TRUE_CLIENT_IP", "HTTP_FASTLY_CLIENT_IP",
        "HTTP_FLY_CLIENT_IP", "HTTP_X_APPENGINE_USER_IP", "X-CLIENT-IP", "X-REAL-IP",
        "X-CLUSTER-CLIENT-IP", "X_FORWARDED", "FORWARDED_FOR", "CF-CONNECTING-IP",
        "TRUE-CLIENT-IP", "FASTLY-CLIENT-IP", "FLY-CLIENT-IP", "FORWARDED", "CLIENT-IP",
    )  # fmt: skip

    def test_released_order_is_frozen(self):
        # New headers may only be inserted between the 4.0.0 entries and REMOTE_ADDR.
        n = len(self.V400_ORDER)
        self.assertEqual(DEFAULT_PRECEDENCE[:n], self.V400_ORDER)
        self.assertEqual(DEFAULT_PRECEDENCE[-1], "REMOTE_ADDR")
        self.assertEqual(len(set(DEFAULT_PRECEDENCE)), len(DEFAULT_PRECEDENCE))

    def test_new_headers(self):
        for header in (
            "HTTP_X_CLIENT_IP", "HTTP_X_AZURE_CLIENTIP", "HTTP_DO_CONNECTING_IP",
            "HTTP_X_ENVOY_EXTERNAL_ADDRESS", "x-azure-clientip", "do-connecting-ip",
            "x-envoy-external-address", "x-appengine-user-ip",
        ):  # fmt: skip
            with self.subTest(header=header):
                ip, _ = IpWare().get_client_ip({header: "203.0.113.80"})
                self.assertEqual(str(ip), "203.0.113.80")

    def test_new_headers_never_outrank_existing(self):
        meta = {"HTTP_FLY_CLIENT_IP": "203.0.113.81", "HTTP_DO_CONNECTING_IP": "203.0.113.82"}
        ip, _ = IpWare().get_client_ip(meta)
        self.assertEqual(str(ip), "203.0.113.81")

    def test_new_headers_outrank_remote_addr(self):
        meta = {"REMOTE_ADDR": "203.0.113.83", "HTTP_X_AZURE_CLIENTIP": "203.0.113.84"}
        ip, _ = IpWare().get_client_ip(meta)
        self.assertEqual(str(ip), "203.0.113.84")


class TestModernDominatesLegacy(unittest.TestCase):
    """Differential check over every combination of direction, proxy_count,
    proxy_list and strict: modern never returns a worse address than legacy.

    * Whenever legacy finds a genuinely global address, modern returns the
      same address with the same trusted flag.
    * Otherwise modern's address ranks at least as high as legacy's, and on
      an equal rank it is the same address.
    * trusted is True exactly when legacy said so, or when a proxy config is
      set and modern resolved a (non-global) address through it.
    """

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

    @staticmethod
    def _rank(ip):
        # None ranks 0; a rejected address (0.0.0.0, multicast) ranks below None.
        if ip is None:
            return 0
        tier = ip_tier(ip)
        return -1 if tier == TIER_REJECT else tier

    def test_modern_never_worse(self):
        checked = improved = 0
        for raw in self.CHAINS:
            for header in ("HTTP_X_FORWARDED_FOR", "REMOTE_ADDR"):
                meta = {header: raw}
                for leftmost in (True, False):
                    for count in self.PROXY_COUNTS:
                        for plist in self.PROXY_LISTS:
                            kw = {"leftmost": leftmost, "proxy_count": count, "proxy_list": plist}
                            configured = count is not None or bool(plist)
                            legacy = IpWare(algorithm="legacy", **kw)
                            modern = IpWare(algorithm="modern", **kw)
                            for strict in (False, True):
                                l_ip, l_trusted = legacy.get_client_ip(meta, strict)
                                m_ip, m_trusted = modern.get_client_ip(meta, strict)
                                with self.subTest(raw=raw, header=header, strict=strict, **kw):
                                    if self._rank(l_ip) == TIER_GLOBAL:
                                        self.assertEqual((m_ip, m_trusted), (l_ip, l_trusted))
                                    self.assertGreaterEqual(self._rank(m_ip), self._rank(l_ip))
                                    if self._rank(m_ip) == self._rank(l_ip):
                                        self.assertEqual(m_ip, l_ip)
                                    self.assertEqual(m_trusted, l_trusted or (configured and m_ip is not None))
                                checked += 1
                                improved += (m_ip, m_trusted) != (l_ip, l_trusted)
        self.assertGreater(checked, 3000)
        self.assertGreater(improved, 0)  # the matrix really exercises the new ranking


if __name__ == "__main__":
    unittest.main()
