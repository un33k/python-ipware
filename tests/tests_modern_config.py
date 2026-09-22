"""Modern engine: configuration validation, proxy matchers, meta handling,
RFC 7239 quoting and address classes. Each test pins a behavior that the
exhaustive matrices in tests_modern_matrix.py cannot reach."""

import ipaddress
import unittest
from typing import ClassVar

from python_ipware import IpWare
from python_ipware.modern.parsers import TIER_PRIVATE, TIER_REJECT, ip_tier, split_proxy_chain, split_unquoted

ip = ipaddress.ip_address
CLIENT = ip("8.8.8.8")


def trusted_via(proxy_entry, hop, strict=True):
    """Resolve ``8.8.8.8, <hop>`` with a single trusted proxy entry."""
    meta = {"HTTP_X_FORWARDED_FOR": f"8.8.8.8, {hop}"}
    return IpWare(proxy_list=[proxy_entry]).get_client_ip(meta, strict)


class TestConstructorValidation(unittest.TestCase):
    def test_rejected_configs(self):
        cases = [
            {"proxy_count": -1},
            {"proxy_count": True},
            {"proxy_count": 1.5},
            {"proxy_count": "1"},
            {"proxy_list": "10.0.0.1"},  # bare string, would explode per character
            {"proxy_list": [1]},
            {"proxy_list": [None]},
            {"proxy_list": ["10.", 5]},
            {"proxy_list": [""]},
            {"proxy_list": ["  "]},
            {"proxy_list": ["foo"]},
            {"proxy_list": ["10.0.0.0/33"]},
            {"proxy_list": ["300.1.0.0/16"]},
            {"precedence": "REMOTE_ADDR"},
            {"precedence": ("REMOTE_ADDR", 5)},
        ]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                IpWare(**kwargs)

    def test_accepted_configs(self):
        for kwargs in (
            {"proxy_count": 0},
            {"proxy_list": []},
            {"proxy_list": ("10.0.0.1",)},
            {"proxy_list": [" 10.0.0.0/8 ", "2001:db8::/32", "fd00:", "198.84"]},
            {"proxy_count": 2, "proxy_list": ["198.84."]},  # may differ, see TestCountAndList
            {"precedence": ["REMOTE_ADDR"]},
        ):
            with self.subTest(kwargs=kwargs):
                IpWare(**kwargs)

    def test_caller_objects_are_copied(self):
        precedence, proxies = ["REMOTE_ADDR"], ["198.84.193.157"]
        ipw = IpWare(precedence=precedence, proxy_list=proxies)
        precedence.append("HTTP_X_REAL_IP")
        proxies.append("10.")
        self.assertEqual(ipw.engine.precedence, ("REMOTE_ADDR",))
        self.assertEqual(ipw.engine.proxy_list, ["198.84.193.157"])

    def test_empty_precedence_means_defaults(self):
        ipw = IpWare(precedence=())
        self.assertEqual(str(ipw.get_client_ip({"HTTP_X_REAL_IP": "8.8.8.8"})[0]), "8.8.8.8")

    def test_repr(self):
        self.assertEqual(repr(IpWare()), "IpWare(algorithm='auto' -> 'modern')")
        self.assertEqual(repr(IpWare(algorithm="legacy")), "IpWare(algorithm='legacy' -> 'legacy')")


class TestProxyMatchers(unittest.TestCase):
    def test_full_ip_entry_is_exact(self):
        # v3 prefix-matched, so "1.2.3.4" trusted 1.2.3.45 and let it forge the client.
        self.assertEqual(trusted_via("1.2.3.4", "1.2.3.45"), (None, False))
        self.assertEqual(trusted_via("1.2.3.4", "1.2.3.4"), (CLIENT, True))

    def test_ipv4_prefix_respects_octet_boundary(self):
        cases = {
            ("10.1", "10.1.0.1"): True,
            ("10.1", "10.100.0.1"): False,
            ("10.1", "10.10.0.1"): False,
            ("10.1.", "10.1.0.1"): True,
            ("10.1.", "10.10.0.1"): False,
            ("198.84.193", "198.84.193.157"): True,
            ("198.84.19", "198.84.193.157"): False,
        }
        for (entry, hop), trusted in cases.items():
            with self.subTest(entry=entry, hop=hop):
                self.assertEqual(trusted_via(entry, hop), (CLIENT, True) if trusted else (None, False))

    def test_ipv6_entry_spelling_does_not_matter(self):
        for entry in ("2001:db8::5", "2001:DB8::5", "2001:0db8:0000:0000:0000:0000:0000:0005", "2001:db8::5/128"):
            with self.subTest(entry=entry):
                self.assertEqual(trusted_via(entry, "2001:db8::5"), (CLIENT, True))
        self.assertEqual(trusted_via("2001:db8::5", "2001:db8::50"), (None, False))

    def test_ipv6_prefix_respects_group_boundary(self):
        cases = {
            ("2001:db8:", "2001:db8::5"): True,
            ("2001:DB8:", "2001:db8::5"): True,
            ("2001:db8::", "2001:db8::5"): True,  # trailing "::" stays a prefix, as in 4.0.0
            ("2001:db8", "2001:db8::5"): True,
            ("2001:db8", "2001:db80::5"): False,
            ("fe80:", "fe80::1%eth0"): True,
        }
        for (entry, hop), trusted in cases.items():
            with self.subTest(entry=entry, hop=hop):
                self.assertEqual(trusted_via(entry, hop), (CLIENT, True) if trusted else (None, False))

    def test_cidr_matchers(self):
        cases = {
            ("10.0.0.0/8", "10.9.9.9"): True,
            ("10.0.0.5/24", "10.0.0.200"): True,  # host bits allowed
            ("10.0.0.0/8", "11.0.0.1"): False,
            ("2001:db8::/32", "2001:db8:ffff::1"): True,
            ("2001:db8::/32", "2001:db9::1"): False,
            ("fe80::/10", "fe80::1%eth0"): True,
            ("10.0.0.0/8", "2001:db8::1"): False,  # cross-version never matches
        }
        for (entry, hop), trusted in cases.items():
            with self.subTest(entry=entry, hop=hop):
                self.assertEqual(trusted_via(entry, hop), (CLIENT, True) if trusted else (None, False))

    def test_embedded_ipv4_forms_match_as_ipv4(self):
        # Hops are unwrapped to IPv4, so entries in either spelling must still match.
        cases = {
            ("10.0.0.0/8", "::ffff:10.0.0.2"): True,
            ("10.0.0.0/8", "64:ff9b::a00:2"): True,
            ("::ffff:10.0.0.0/104", "10.0.0.2"): True,
            ("64:ff9b::a00:0/104", "10.0.0.2"): True,
            ("::ffff:10.0.0.2", "10.0.0.2"): True,
            ("64:ff9b::a00:2", "::ffff:10.0.0.2"): True,
            ("::ffff:10.0.0.0/104", "11.0.0.2"): False,
        }
        for (entry, hop), trusted in cases.items():
            with self.subTest(entry=entry, hop=hop):
                self.assertEqual(trusted_via(entry, hop), (CLIENT, True) if trusted else (None, False))

    def test_zone_id_hop_matches_exact_entry(self):
        self.assertEqual(trusted_via("fe80::1", "fe80::1%eth0"), (CLIENT, True))


class TestCountAndList(unittest.TestCase):
    """Both may be set and may differ (v3 API): the count is a hop-count
    requirement (minimum, exact when strict); the list pins the position."""

    META: ClassVar[dict[str, str]] = {"HTTP_X_FORWARDED_FOR": "6.6.6.6, 8.8.8.8, 9.9.9.9, 198.84.1.1"}

    def test_list_pins_position_count_is_minimum(self):
        ipw = IpWare(proxy_count=2, proxy_list=["198.84."])
        self.assertEqual(ipw.get_client_ip(self.META), (ip("9.9.9.9"), True))

    def test_count_above_hops_rejects(self):
        ipw = IpWare(proxy_count=4, proxy_list=["198.84."])
        self.assertEqual(ipw.get_client_ip(self.META), (None, False))

    def test_strict_needs_both_exact(self):
        self.assertEqual(IpWare(proxy_count=3, proxy_list=["198.84."]).get_client_ip(self.META, True), (None, False))
        ipw = IpWare(proxy_count=1, proxy_list=["198.84."])
        meta = {"HTTP_X_FORWARDED_FOR": "8.8.8.8, 198.84.1.1"}
        self.assertEqual(ipw.get_client_ip(meta, True), (CLIENT, True))


class TestMetaHandling(unittest.TestCase):
    def test_non_mapping_meta_raises(self):
        for meta in (["REMOTE_ADDR"], "REMOTE_ADDR", 5):
            with self.subTest(meta=meta), self.assertRaises(TypeError):
                IpWare().get_client_ip(meta)

    def test_none_and_empty_meta(self):
        self.assertEqual(IpWare().get_client_ip(None), (None, False))
        self.assertEqual(IpWare().get_client_ip({}), (None, False))

    def test_non_string_keys_are_skipped(self):
        meta = {1: "x", None: "y", ("a",): "z", "REMOTE_ADDR": "8.8.8.8"}
        self.assertEqual(IpWare().get_client_ip(meta), (CLIENT, False))

    def test_dash_spelling_beats_underscore_in_any_order(self):
        pairs = [("x_forwarded_for", "6.6.6.6"), ("x-forwarded-for", "8.8.8.8")]
        for order in (pairs, pairs[::-1]):
            with self.subTest(order=order):
                self.assertEqual(IpWare().get_client_ip(dict(order)), (CLIENT, False))

    def test_underscore_spelling_cannot_forge_through_trusted_proxy(self):
        ipw = IpWare(proxy_list=["10.0.0.0/8"])
        pairs = [("x_forwarded_for", "6.6.6.6, 10.0.0.2"), ("x-forwarded-for", "8.8.8.8, 10.0.0.2")]
        for order in (pairs, pairs[::-1]):
            with self.subTest(order=order):
                self.assertEqual(ipw.get_client_ip(dict(order)), (CLIENT, True))

    def test_conflicting_dash_spellings_are_ignored(self):
        meta = {"X-Forwarded-For": "6.6.6.6", "x-forwarded-for": "8.8.8.8", "REMOTE_ADDR": "9.9.9.9"}
        self.assertEqual(IpWare().get_client_ip(meta), (ip("9.9.9.9"), False))

    def test_agreeing_spellings_resolve(self):
        meta = {"X-Forwarded-For": "8.8.8.8", "x-forwarded-for": "8.8.8.8"}
        self.assertEqual(IpWare().get_client_ip(meta), (CLIENT, False))

    def test_unhashable_values_do_not_crash(self):
        meta = {"x-forwarded-for": ["8.8.8.8"], "X-Forwarded-For": ["8.8.8.8"], "REMOTE_ADDR": "9.9.9.9"}
        self.assertEqual(IpWare().get_client_ip(meta), (ip("9.9.9.9"), False))

    def test_whitespace_only_value_is_absent(self):
        meta = {"HTTP_X_FORWARDED_FOR": " \t\r\n", "REMOTE_ADDR": "8.8.8.8"}
        self.assertEqual(IpWare().get_client_ip(meta), (CLIENT, False))


class TestForwardedQuoting(unittest.TestCase):
    def test_quoted_separators_do_not_split(self):
        cases = {
            'for=10.0.0.1;ext="x,8.8.8.8"': ip("10.0.0.1"),  # no smuggled hop
            'for=8.8.8.8;by="a,b"': CLIENT,
            'for=8.8.8.8;ext="a;for=6.6.6.6"': CLIENT,
            'ext="a\\"b,c";for=8.8.8.8': CLIENT,  # escaped quote inside quoted-string
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(IpWare().get_client_ip({"HTTP_FORWARDED": raw}, strict=True), (expected, False))

    def test_quoted_comma_cannot_fake_proxy_hop(self):
        meta = {"HTTP_FORWARDED": 'for=8.8.4.4;by="_a,9.9.9.9"'}
        self.assertEqual(IpWare(proxy_count=1).get_client_ip(meta), (None, False))

    def test_unclosed_quote_swallows_the_rest(self):
        meta = {"HTTP_FORWARDED": 'for=8.8.8.8, for="6.6.6.6, for=9.9.9.9'}
        self.assertEqual(IpWare().get_client_ip(meta), (CLIENT, False))
        self.assertEqual(IpWare().get_client_ip(meta, strict=True), (None, False))

    def test_split_unquoted_helper(self):
        self.assertEqual(split_unquoted("a,b", ","), ["a", "b"])
        self.assertEqual(split_unquoted('a,"b,c",d', ","), ["a", '"b,c"', "d"])
        self.assertEqual(split_unquoted('"a\\",b",c', ","), ['"a\\",b"', "c"])
        self.assertEqual(split_unquoted("", ","), [""])

    def test_split_proxy_chain_empty(self):
        self.assertEqual(split_proxy_chain(""), [])
        self.assertEqual(split_proxy_chain(None), [])


class TestAddressClasses(unittest.TestCase):
    def test_extra_tiers(self):
        cases = {
            "fec0::1": TIER_PRIVATE,  # deprecated site-local; Python calls it global
            "64:ff9b:1::808:808": TIER_PRIVATE,  # RFC 8215 local-use NAT64; Python calls it reserved
            "0.1.2.3": TIER_REJECT,  # "this network"
            "0.255.255.255": TIER_REJECT,
        }
        for address, tier in cases.items():
            with self.subTest(address=address):
                self.assertEqual(ip_tier(ip(address)), tier)

    def test_site_local_does_not_beat_public(self):
        meta = {"HTTP_X_FORWARDED_FOR": "fec0::1, 8.8.8.8"}
        self.assertEqual(IpWare().get_client_ip(meta), (CLIENT, False))

    def test_this_network_never_returned(self):
        self.assertEqual(IpWare().get_client_ip({"REMOTE_ADDR": "0.1.2.3"}), (None, False))

    def test_local_use_nat64_is_a_private_fallback(self):
        meta = {"HTTP_X_FORWARDED_FOR": "64:ff9b:1::808:808", "REMOTE_ADDR": "127.0.0.1"}
        self.assertEqual(IpWare().get_client_ip(meta), (ip("64:ff9b:1::808:808"), False))


class TestLargeInput(unittest.TestCase):
    def test_long_header_is_handled(self):
        raw = ", ".join(["10.0.0.1"] * 20000 + ["8.8.8.8"])
        self.assertEqual(IpWare().get_client_ip({"HTTP_X_FORWARDED_FOR": raw}), (CLIENT, False))


if __name__ == "__main__":
    unittest.main()
