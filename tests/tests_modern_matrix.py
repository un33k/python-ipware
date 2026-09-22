"""Exhaustive combination tests for the modern engine.

The core check compares the engine with an independent reference model
(``_oracle``). The model never calls the engine's parser or ranking: every
test token has a hand-assigned address and tier in ``TRUTH``, so a bug in
``parse_ip`` or ``ip_tier`` cannot hide by being shared with the oracle.

Covered exhaustively:

* every ordered chain of 1-3 hops drawn from a pool of 10 token kinds
  (global v4/v6, a proxy, private v4/v6, link-local, loopback, unspecified,
  multicast, garbage), in every configuration of leftmost, strict,
  proxy_count and proxy_list;
* every assignment of chains to three headers, in both dict insertion orders;
* every formatting variant of the same hop (port, brackets, quotes, RFC 7239
  ``for=``, whitespace, IPv4-mapped, case, zero-expansion);
* never-worse-than-legacy over the whole single-header matrix;
* a seeded fuzz run over junk input for crash-freedom and output invariants.
"""

import ipaddress
import itertools
import random
import unittest
from typing import ClassVar, Optional

from python_ipware import IpWare
from python_ipware.modern.parsers import (
    TIER_GLOBAL,
    TIER_LINK_LOCAL,
    TIER_LOOPBACK,
    TIER_PRIVATE,
    TIER_REJECT,
    ip_tier,
)

G, P, LL, LB, REJ = TIER_GLOBAL, TIER_PRIVATE, TIER_LINK_LOCAL, TIER_LOOPBACK, TIER_REJECT

# token -> (address, tier) by hand, or None for a token that is not an IP.
TRUTH: dict[str, Optional[tuple[str, int]]] = {
    "177.139.233.139": ("177.139.233.139", G),
    "2606:4700::6810:84e5": ("2606:4700::6810:84e5", G),
    "198.84.193.157": ("198.84.193.157", G),  # doubles as the trusted proxy
    "10.0.0.1": ("10.0.0.1", P),
    "fd00::1": ("fd00::1", P),
    "169.254.1.1": ("169.254.1.1", LL),
    "127.0.0.1": ("127.0.0.1", LB),
    "0.0.0.0": ("0.0.0.0", REJ),
    "224.0.0.1": ("224.0.0.1", REJ),
    "unknown": None,
}
POOL = tuple(TRUTH)

# (proxy_count, proxy_list) configurations, including both set at once.
CONFIGS = (
    (None, None),
    (0, None),
    (1, None),
    (2, None),
    (None, ["198.84.193.157"]),  # exact IPv4
    (None, ["198.84."]),  # IPv4 prefix
    (None, ["198.84"]),  # IPv4 prefix without trailing dot (octet boundary)
    (None, ["10.0.0.0/8"]),  # IPv4 CIDR
    (None, ["2606:4700::6810:84E5"]),  # exact IPv6, non-canonical case
    (None, ["fd00::/8"]),  # IPv6 CIDR
    (None, ["198.84.193.157", "10.0.0.0/8"]),  # two trusted hops
    (1, ["198.84.193.157"]),  # count and list agree
    (2, ["198.84."]),  # count and list differ: list pins, count is a minimum
)


def _chains(max_len: int = 3):
    for n in range(1, max_len + 1):
        yield from itertools.product(POOL, repeat=n)


def _proxy_ok(address: str, pattern: str) -> bool:
    """Spec for one proxy_list entry, written independently of the engine."""
    ip = ipaddress.ip_address(address)
    if "/" in pattern:
        net = ipaddress.ip_network(pattern, strict=False)
        return ip.version == net.version and ip in net
    try:
        return ip == ipaddress.ip_address(pattern)  # a complete IP is exact
    except ValueError:
        pass
    # An IPv4 prefix names leading octets; a partial last octet is not allowed.
    want = pattern.rstrip(".").split(".")
    have = address.split(".")
    return ip.version == 4 and have[: len(want)] == want


def _oracle(raw_values, leftmost, proxy_count, proxy_list, strict):
    """Reference model of the documented modern algorithm.

    ``raw_values`` are header values already in precedence order.
    """
    configured = proxy_count is not None or bool(proxy_list)
    best = None  # (address, tier, trusted); first header wins ties
    for raw in raw_values:
        hops = [TRUTH[t.strip()] for t in raw.split(",")]
        if strict and any(h is None for h in hops):
            continue
        chain = [h for h in hops if h is not None]
        if not leftmost:
            chain.reverse()
        if not chain:
            continue
        proxies = len(chain) - 1
        if proxy_count is not None and (proxies < proxy_count or (strict and proxies != proxy_count)):
            continue
        if proxy_list:
            n = len(proxy_list)
            if proxies < n or (strict and proxies != n):
                continue
            if not all(_proxy_ok(addr, pat) for (addr, _), pat in zip(chain[-n:], proxy_list)):
                continue
        if configured:
            n = len(proxy_list) if proxy_list else proxy_count
            address, tier = chain[-(n + 1)]
        else:
            globals_ = [h for h in chain if h[1] == G]
            address, tier = globals_[0] if globals_ else max(chain, key=lambda h: h[1])
        if tier == REJ:
            continue
        if tier == G:
            return ipaddress.ip_address(address), configured
        if best is None or tier > best[1]:
            best = (address, tier, configured)
    if best is None:
        return None, False
    return ipaddress.ip_address(best[0]), best[2]


class TestTierTable(unittest.TestCase):
    """The ranking every other test relies on, checked against the labels."""

    def test_pool_labels(self):
        for token, truth in TRUTH.items():
            if truth is None:
                continue
            with self.subTest(token=token):
                self.assertEqual(ip_tier(ipaddress.ip_address(truth[0])), truth[1])

    def test_extra_classes(self):
        cases = {
            "8.8.8.8": G, "2001:4860::8888": G,
            "192.168.1.1": P, "172.16.0.1": P, "100.64.0.1": P, "203.0.113.10": P, "2001:db8::1": P,
            "fe80::1": LL, "::1": LB,
            "::": REJ, "ff02::1": REJ, "255.255.255.255": REJ, "240.0.0.1": REJ, "::8.8.8.8": REJ,
        }  # fmt: skip
        for address, tier in cases.items():
            with self.subTest(address=address):
                self.assertEqual(ip_tier(ipaddress.ip_address(address)), tier)


class TestSingleHeaderMatrix(unittest.TestCase):
    def test_every_chain_and_config_matches_oracle(self):
        checked = 0
        for hops in _chains():
            raw = ", ".join(hops)
            meta = {"HTTP_X_FORWARDED_FOR": raw}
            for proxy_count, proxy_list in CONFIGS:
                for leftmost in (True, False):
                    ipw = IpWare(leftmost=leftmost, proxy_count=proxy_count, proxy_list=proxy_list)
                    for strict in (False, True):
                        expected = _oracle([raw], leftmost, proxy_count, proxy_list, strict)
                        actual = ipw.get_client_ip(meta, strict)
                        if actual != expected:
                            self.fail(
                                f"{raw!r} leftmost={leftmost} count={proxy_count} "
                                f"list={proxy_list} strict={strict}: {actual} != {expected}"
                            )
                        checked += 1
        self.assertEqual(checked, (10 + 100 + 1000) * len(CONFIGS) * 4)


class TestMultiHeaderMatrix(unittest.TestCase):
    HEADERS = ("HTTP_X_FORWARDED_FOR", "HTTP_X_REAL_IP", "REMOTE_ADDR")
    VALUES = (
        None,  # header absent
        "177.139.233.139",
        "2606:4700::6810:84e5",
        "10.0.0.1",
        "127.0.0.1",
        "0.0.0.0",
        "unknown",
        "10.0.0.1, 177.139.233.139",
        "169.254.1.1, fd00::1",
        "177.139.233.139, 198.84.193.157",
        "10.0.0.1, 198.84.193.157",
    )
    CONFIGS = ((None, None), (1, None), (None, ["198.84.193.157"]))

    def test_every_header_assignment_and_order(self):
        checked = 0
        for values in itertools.product(self.VALUES, repeat=len(self.HEADERS)):
            present = [(h, v) for h, v in zip(self.HEADERS, values) if v is not None]
            for proxy_count, proxy_list in self.CONFIGS:
                for leftmost in (True, False):
                    ipw = IpWare(
                        precedence=self.HEADERS, leftmost=leftmost, proxy_count=proxy_count, proxy_list=proxy_list
                    )
                    for strict in (False, True):
                        expected = _oracle([v for _, v in present], leftmost, proxy_count, proxy_list, strict)
                        # Dict insertion order must never matter, only precedence.
                        for order in (present, present[::-1]):
                            actual = ipw.get_client_ip(dict(order), strict)
                            if actual != expected:
                                self.fail(
                                    f"{dict(order)} leftmost={leftmost} count={proxy_count} "
                                    f"list={proxy_list} strict={strict}: {actual} != {expected}"
                                )
                            checked += 1
        self.assertEqual(checked, len(self.VALUES) ** 3 * len(self.CONFIGS) * 2 * 2 * 2)


class TestFormattingInvariance(unittest.TestCase):
    """Every spelling of a hop must resolve exactly like the plain address."""

    RENDERINGS: ClassVar[dict[str, tuple[str, ...]]] = {
        "177.139.233.139": (
            "177.139.233.139:8080",
            '"177.139.233.139"',
            "  177.139.233.139  ",
            "for=177.139.233.139",
            'for="177.139.233.139:4711";proto=https;by=198.84.193.158',
            "::ffff:177.139.233.139",
            "[::ffff:177.139.233.139]:443",
        ),
        "2606:4700::6810:84e5": (
            "[2606:4700::6810:84e5]",
            "[2606:4700::6810:84e5]:443",
            "2606:4700::6810:84E5",
            "2606:4700:0:0:0:0:6810:84e5",
            'for="[2606:4700::6810:84e5]:4711"',
            "'2606:4700::6810:84e5'",
        ),
        "10.0.0.1": ("10.0.0.1:443", 'for="10.0.0.1"', "Proto=http;FOR=10.0.0.1"),
        "198.84.193.157": ("198.84.193.157:80", "for=198.84.193.157;by=_edge"),
    }

    def test_all_rendering_combinations(self):
        templates = (
            ("177.139.233.139", "198.84.193.157"),
            ("10.0.0.1", "177.139.233.139"),
            ("2606:4700::6810:84e5", "10.0.0.1", "198.84.193.157"),
        )
        configs = ((None, None), (1, None), (None, ["198.84.193.157"]))
        checked = 0
        for template in templates:
            plain_meta = {"HTTP_X_FORWARDED_FOR": ", ".join(template)}
            options = [(hop, *self.RENDERINGS[hop]) for hop in template]
            for spelled in itertools.product(*options):
                meta = {"HTTP_X_FORWARDED_FOR": ", ".join(spelled)}
                for proxy_count, proxy_list in configs:
                    for leftmost in (True, False):
                        ipw = IpWare(leftmost=leftmost, proxy_count=proxy_count, proxy_list=proxy_list)
                        for strict in (False, True):
                            with self.subTest(meta=meta, count=proxy_count, list=proxy_list, strict=strict):
                                self.assertEqual(ipw.get_client_ip(meta, strict), ipw.get_client_ip(plain_meta, strict))
                            checked += 1
        self.assertGreater(checked, 1000)


class TestNeverWorseThanLegacy(unittest.TestCase):
    @staticmethod
    def _rank(ip):
        if ip is None:
            return 0
        tier = ip_tier(ip)
        return -1 if tier == REJ else tier

    def test_whole_single_header_matrix(self):
        improved = 0
        for hops in _chains():
            meta = {"HTTP_X_FORWARDED_FOR": ", ".join(hops)}
            for proxy_count, proxy_list in CONFIGS:
                configured = proxy_count is not None or bool(proxy_list)
                for leftmost in (True, False):
                    kw = {"leftmost": leftmost, "proxy_count": proxy_count, "proxy_list": proxy_list}
                    legacy, modern = IpWare(algorithm="legacy", **kw), IpWare(**kw)
                    for strict in (False, True):
                        l_ip, l_trusted = legacy.get_client_ip(meta, strict)
                        m_ip, m_trusted = modern.get_client_ip(meta, strict)
                        where = f"{meta} {kw} strict={strict}: modern={m_ip, m_trusted} legacy={l_ip, l_trusted}"
                        self.assertGreaterEqual(self._rank(m_ip), self._rank(l_ip), where)
                        if self._rank(l_ip) == G:
                            self.assertEqual((m_ip, m_trusted), (l_ip, l_trusted), where)
                        if m_trusted:
                            self.assertTrue(configured, where)
                        improved += self._rank(m_ip) > self._rank(l_ip)
        self.assertGreater(improved, 1000)


class TestBestMatchExamples(unittest.TestCase):
    """Readable examples of each improvement over v3."""

    def test_public_hop_behind_private_first_hop(self):
        # v3 returned 10.0.0.1 here.
        ip, _ = IpWare().get_client_ip({"HTTP_X_FORWARDED_FOR": "10.0.0.1, 177.139.233.139, 198.84.193.157"})
        self.assertEqual(str(ip), "177.139.233.139")

    def test_rightmost_scans_from_the_right(self):
        meta = {"HTTP_X_FORWARDED_FOR": "6.6.6.6, 177.139.233.139, 10.0.0.2"}
        ip, _ = IpWare(leftmost=False).get_client_ip(meta)
        self.assertEqual(str(ip), "177.139.233.139")

    def test_nat64_well_known_prefix_unwrapped(self):
        # v3 returned the IPv6 form; the embedded IPv4 is the real client.
        cases = {
            "64:ff9b::2d01:101": "45.1.1.1",
            "[64:ff9b::b18b:e98b]:443": "177.139.233.139",
            "64:ff9b::a00:1": "10.0.0.1",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                ip, _ = IpWare().get_client_ip({"REMOTE_ADDR": raw})
                self.assertEqual(str(ip), expected)

    def test_nat64_matches_proxy_as_ipv4(self):
        ipw = IpWare(proxy_list=["198.84.193.157"])
        meta = {"HTTP_X_FORWARDED_FOR": "177.139.233.139, 64:ff9b::c654:c19d"}
        self.assertEqual(ipw.get_client_ip(meta, strict=True), (ipaddress.ip_address("177.139.233.139"), True))

    def test_junk_addresses_never_returned(self):
        for junk in ("0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255", "240.0.0.1", "::8.8.8.8"):
            with self.subTest(junk=junk):
                self.assertEqual(IpWare().get_client_ip({"REMOTE_ADDR": junk}), (None, False))

    def test_multicast_is_not_mistaken_for_global(self):
        # Python reports 224.0.0.1 as is_global; v3 returned it as the client.
        meta = {"HTTP_X_FORWARDED_FOR": "224.0.0.1", "REMOTE_ADDR": "10.0.0.5"}
        ip, _ = IpWare().get_client_ip(meta)
        self.assertEqual(str(ip), "10.0.0.5")

    def test_link_local_ranks_below_private(self):
        meta = {"HTTP_X_FORWARDED_FOR": "169.254.1.1", "REMOTE_ADDR": "10.0.0.5"}
        ip, _ = IpWare().get_client_ip(meta)
        self.assertEqual(str(ip), "10.0.0.5")

    def test_link_local_ranks_above_loopback(self):
        meta = {"HTTP_X_FORWARDED_FOR": "127.0.0.1", "REMOTE_ADDR": "fe80::1"}
        ip, _ = IpWare().get_client_ip(meta)
        self.assertEqual(str(ip), "fe80::1")

    def test_private_client_through_trusted_proxy_is_trusted(self):
        # v3 reported trusted=False for any non-global client.
        ipw = IpWare(proxy_list=["198.84.193.157"])
        meta = {"HTTP_X_FORWARDED_FOR": "10.0.0.1, 198.84.193.157"}
        self.assertEqual(ipw.get_client_ip(meta, strict=True), (ipaddress.ip_address("10.0.0.1"), True))

    def test_proxy_config_still_fixes_the_position(self):
        # With a trusted proxy the client slot is fixed; a public hop further left is ignored.
        ipw = IpWare(proxy_count=1)
        meta = {"HTTP_X_FORWARDED_FOR": "177.139.233.139, 10.0.0.1, 198.84.193.157"}
        self.assertEqual(ipw.get_client_ip(meta), (ipaddress.ip_address("10.0.0.1"), True))


class TestFuzz(unittest.TestCase):
    FRAGMENTS = (
        "", " ", ",", ";", "=", '"', "'", "[", "]", ":", "::", "%eth0", "for=", "by=", "proto=https",
        "unknown", "_hidden", "1", "255", "256", "999", ".", "1.2.3", "::ffff:", "fe80::", "0x7f",
        "177.139.233.139", "10.0.0.1", "2606:4700::1", "127.0.0.1", "0.0.0.0", "224.0.0.1",
        "\u00b2", "\uff11", "\x00", "65535", "70000", "\t",
    )  # fmt: skip
    HEADERS = ("HTTP_X_FORWARDED_FOR", "HTTP_FORWARDED", "x-real-ip", "REMOTE_ADDR")

    def test_random_junk_is_safe(self):
        rng = random.Random(20260922)
        for _ in range(3000):
            meta = {
                h: "".join(rng.choice(self.FRAGMENTS) for _ in range(rng.randint(0, 12)))
                for h in rng.sample(self.HEADERS, rng.randint(1, len(self.HEADERS)))
            }
            proxy_count, proxy_list = rng.choice(CONFIGS)
            ipw = IpWare(leftmost=rng.random() < 0.5, proxy_count=proxy_count, proxy_list=proxy_list)
            strict = rng.random() < 0.5
            with self.subTest(meta=meta, count=proxy_count, list=proxy_list, strict=strict):
                ip, trusted = ipw.get_client_ip(meta, strict)
                self.assertEqual((ip, trusted), ipw.get_client_ip(meta, strict))  # deterministic
                if ip is None:
                    self.assertFalse(trusted)
                else:
                    self.assertNotEqual(ip_tier(ip), REJ)
                if trusted:
                    self.assertTrue(proxy_count is not None or bool(proxy_list))


if __name__ == "__main__":
    unittest.main()
