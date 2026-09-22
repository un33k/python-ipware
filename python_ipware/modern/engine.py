"""The modern python-ipware engine.

Same inputs, outputs and proxy semantics as v3, with a better best-match:

* Superset header precedence (Forwarded parsing, more CDN / edge headers).
* Robust IPv6 / bracketed-port / IPv4-mapped / RFC 7239 parsing.
* Explicit ranking: global > private > link-local > loopback. Unspecified,
  multicast, broadcast and reserved addresses are never returned.
* Without trusted-proxy config, the first *globally routable* hop of a chain
  wins, not just the first hop, so ``10.0.0.1, 177.139.233.139`` yields the
  public address. With ``proxy_count`` / ``proxy_list`` the client position is
  fixed by the config, exactly as in v3.
* Same ``strict`` semantics for proxy_count / proxy_list validation.
* Trusted-proxy matching anchored to the end of the chain. Each ``proxy_list``
  entry is either a CIDR network (``"100.64.0.0/10"``, ``"fd7a:115c:a1e0::/48"``)
  matched by real network membership, or a plain string prefix (``"10.1."``).
* ``trusted_route`` is True whenever the returned IP came from a chain that
  passed the configured proxy validation, whatever its tier.
"""

import ipaddress
from typing import Optional, Union

from .defaults import DEFAULT_PRECEDENCE
from .parsers import TIER_GLOBAL, TIER_REJECT, IpAddressType, ip_tier, split_proxy_chain

OptionalIp = Optional[IpAddressType]
IpNetworkType = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
ProxyMatcher = Union[str, IpNetworkType]


def _compile_proxy_matcher(pattern: str) -> ProxyMatcher:
    """CIDR entries become networks; anything else stays a string prefix."""
    if "/" not in pattern:
        return pattern
    try:
        # strict=False accepts host bits set, e.g. "10.0.0.5/24" -> 10.0.0.0/24.
        return ipaddress.ip_network(pattern.strip(), strict=False)
    except ValueError as exc:
        msg = f"Invalid CIDR in proxy_list: {pattern!r}"
        raise ValueError(msg) from exc


def _proxy_matches(ip: IpAddressType, matcher: ProxyMatcher) -> bool:
    if isinstance(matcher, str):
        return str(ip).startswith(matcher)
    # Membership across IP versions is simply False, never an error.
    return ip.version == matcher.version and ip in matcher


class ModernIpWare:
    def __init__(
        self,
        precedence: Optional[tuple[str, ...]] = None,
        leftmost: bool = True,
        proxy_count: Optional[int] = None,
        proxy_list: Optional[list[str]] = None,
    ) -> None:
        if proxy_count is not None and proxy_count < 0:
            raise ValueError("proxy_count must be non-negative")
        if proxy_list is not None and not all(isinstance(p, str) for p in proxy_list):
            raise ValueError("All elements in the proxy list must be strings.")
        proxy_list = [p.strip() for p in proxy_list or []]
        # An empty prefix matches every address, which would mark any spoofed
        # chain as trusted. It is always a misconfiguration (e.g. a trailing
        # comma in an env var), so fail loudly instead.
        if any(not p for p in proxy_list):
            raise ValueError("proxy_list entries must not be empty.")

        self.precedence = precedence or DEFAULT_PRECEDENCE
        self.leftmost = leftmost
        self.proxy_count = proxy_count
        self.proxy_list = proxy_list
        self._proxy_matchers = [_compile_proxy_matcher(p) for p in self.proxy_list]

    # -- meta access --------------------------------------------------------

    @staticmethod
    def _fold(key: str) -> str:
        return key.upper().replace("-", "_")

    def _get_meta_value(
        self,
        meta: dict[str, str],
        key: str,
        folded: Optional[dict[str, object]] = None,
    ) -> str:
        meta = meta or {}
        value = meta.get(key)
        if value is None:
            value = meta.get(key.replace("_", "-"))
        # Exact keys win; the folded view only fills gaps, so lowercase keys
        # (AWS Lambda / API Gateway v2, raw ASGI dicts) still match.
        if value is None and folded is not None:
            value = folded.get(self._fold(key))
        # Header values are text; anything else (None, bytes, lists from a
        # misbehaving adapter) is ignored rather than crashing the lookup.
        return value.strip() if isinstance(value, str) else ""

    def _get_meta_values(self, meta: dict[str, str]) -> list[str]:
        meta = meta or {}
        folded: dict[str, object] = {}
        for k, v in meta.items():
            if isinstance(k, str):
                folded.setdefault(self._fold(k), v)
        values: list[str] = []
        for key in self.precedence:
            value = self._get_meta_value(meta, key, folded)
            if value:
                values.append(value)
        return values

    # -- validation ---------------------------------------------------------

    def _proxy_count_valid(self, chain: list[IpAddressType], strict: bool) -> bool:
        if self.proxy_count is None:
            return True
        proxies = len(chain) - 1
        if strict:
            return proxies == self.proxy_count
        return proxies >= self.proxy_count

    def _proxy_list_valid(self, chain: list[IpAddressType], strict: bool) -> bool:
        if not self.proxy_list:
            return True
        count = len(self.proxy_list)
        if strict and (len(chain) - 1) != count:
            return False
        if (len(chain) - 1) < count:
            return False
        # Compare the trailing proxies against the trusted entries in order.
        return all(
            _proxy_matches(ip, matcher)
            for ip, matcher in zip(chain[-count:], self._proxy_matchers)
        )

    # -- selection ----------------------------------------------------------

    def _best_from_chain(self, chain: list[IpAddressType]) -> tuple[OptionalIp, bool]:
        # ``chain`` is already client-first (see get_client_ip) and non-empty.
        if self.proxy_list:
            return chain[-(len(self.proxy_list) + 1)], True
        if self.proxy_count is not None:
            return chain[-(self.proxy_count + 1)], True
        # No trusted-proxy config, so no position in the chain is verified.
        # Take the first globally routable hop; otherwise the best-ranked hop,
        # earliest on ties. This never picks a worse address than v3's chain[0].
        best: OptionalIp = None
        best_tier = TIER_REJECT
        for ip in chain:
            tier = ip_tier(ip)
            if tier == TIER_GLOBAL:
                return ip, False
            if tier > best_tier:
                best, best_tier = ip, tier
        return best, False

    # -- public API ---------------------------------------------------------

    def get_client_ip(self, meta: dict[str, str], strict: bool = False) -> tuple[OptionalIp, bool]:
        # Best non-global candidate so far. Strictly-greater comparison keeps
        # the earliest header on ties, preserving header precedence.
        fallback: OptionalIp = None
        fallback_tier = TIER_REJECT
        fallback_trusted = False

        for raw in self._get_meta_values(meta):
            chain = split_proxy_chain(raw, strict)
            if not chain:
                continue
            # Put the chain in client-first order ONCE, before any validation, so
            # the proxy checks and the client pick look at the same end.
            if not self.leftmost:
                chain.reverse()
            if not self._proxy_count_valid(chain, strict):
                continue
            if not self._proxy_list_valid(chain, strict):
                continue

            ip, trusted = self._best_from_chain(chain)
            if ip is None:
                continue
            tier = ip_tier(ip)
            if tier == TIER_GLOBAL:
                return ip, trusted
            if tier > fallback_tier:
                fallback, fallback_tier, fallback_trusted = ip, tier, trusted

        return fallback, fallback_trusted
