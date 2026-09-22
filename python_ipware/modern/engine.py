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
  entry is a CIDR network (``"100.64.0.0/10"``, ``"fd7a:115c:a1e0::/48"``), a
  complete IP matched exactly, or an IP prefix matched on octet / group
  boundaries (``"10.1."``, ``"10.1"`` -> 10.1.x.x only).
* ``trusted_route`` is True whenever the returned IP came from a chain that
  passed the configured proxy validation, whatever its tier.
* Misconfiguration fails loudly at construction instead of silently trusting
  or never matching.
"""

import ipaddress
from collections.abc import Mapping
from typing import Any, Optional, Union

from .defaults import DEFAULT_PRECEDENCE
from .parsers import (
    TIER_GLOBAL,
    TIER_REJECT,
    IpAddressType,
    IpNetworkType,
    ip_tier,
    split_proxy_chain,
    unwrap_ipv4,
    unwrap_ipv4_network,
)

OptionalIp = Optional[IpAddressType]
ProxyMatcher = Union[str, IpNetworkType]

_PREFIX_CHARS = frozenset("0123456789abcdef.:")


def _compile_proxy_matcher(pattern: str) -> ProxyMatcher:
    """Compile one ``proxy_list`` entry.

    * ``"10.0.0.0/8"`` -> network, matched by membership.
    * ``"198.84.193.157"`` (a complete IP) -> exact /32 or /128 network, so it
      can never match ``198.84.193.15x`` and IPv6 spelling (case, zeros) does
      not matter.
    * ``"198.84."`` / ``"10.1"`` / ``"2001:db8:"`` -> text prefix, matched on
      octet / group boundaries only. An entry ending in ``:`` is always a
      prefix, since ``"2001:db8::"`` historically meant "anything under it".
    """
    if "/" in pattern:
        try:
            # strict=False accepts host bits set, e.g. "10.0.0.5/24" -> 10.0.0.0/24.
            return unwrap_ipv4_network(ipaddress.ip_network(pattern, strict=False))
        except ValueError as exc:
            msg = f"Invalid CIDR in proxy_list: {pattern!r}"
            raise ValueError(msg) from exc
    if not pattern.endswith(":"):
        try:
            return ipaddress.ip_network(unwrap_ipv4(ipaddress.ip_address(pattern)))
        except ValueError:
            pass
    prefix = pattern.lower()
    if not set(prefix) <= _PREFIX_CHARS:
        msg = f"proxy_list entry is not an IP, CIDR or IP prefix: {pattern!r}"
        raise ValueError(msg)
    return prefix


def _proxy_matches(ip: IpAddressType, matcher: ProxyMatcher) -> bool:
    if isinstance(matcher, str):
        text = str(ip)
        if not text.startswith(matcher):
            return False
        # Boundary check: "10.1" matches 10.1.x.x but not 10.100.x.x.
        rest = text[len(matcher) :]
        return not rest or matcher[-1] in ".:" or rest[0] in ".:%"
    # Membership across IP versions is simply False, never an error.
    return ip.version == matcher.version and ip in matcher


def _fold(key: str) -> str:
    return key.upper().replace("-", "_")


def _build_folded(meta: Mapping[Any, Any]) -> dict[str, object]:
    """Case- and dash-insensitive view of ``meta`` for lowercase-key adapters.

    When several spellings fold to the same name, the result must not depend
    on dict order. Real header names use dashes, while an underscore spelling
    in a raw header dict can only come from the client, so dash spellings win.
    If several dash spellings disagree, the header is treated as absent.
    """
    groups: dict[str, list[tuple[str, object]]] = {}
    for key, value in meta.items():
        if isinstance(key, str):
            groups.setdefault(_fold(key), []).append((key, value))
    folded: dict[str, object] = {}
    for name, items in groups.items():
        dashed = [v for k, v in items if "-" in k]
        pool = dashed or [v for _, v in items]
        distinct: list[object] = []
        for value in pool:
            if value not in distinct:
                distinct.append(value)
        if len(distinct) == 1:
            folded[name] = distinct[0]
    return folded


class ModernIpWare:
    def __init__(
        self,
        precedence: Optional[tuple[str, ...]] = None,
        leftmost: bool = True,
        proxy_count: Optional[int] = None,
        proxy_list: Optional[list[str]] = None,
    ) -> None:
        if proxy_count is not None and (
            isinstance(proxy_count, bool) or not isinstance(proxy_count, int) or proxy_count < 0
        ):
            raise ValueError("proxy_count must be a non-negative integer")
        # A bare string is iterable and would silently become one prefix per
        # character ("10.0.0.1" -> "1", "0", ...), trusting almost anything.
        if isinstance(proxy_list, str) or (
            proxy_list is not None and not all(isinstance(p, str) for p in proxy_list)
        ):
            raise ValueError("proxy_list must be a list of strings.")
        proxy_list = [p.strip() for p in proxy_list or []]
        # An empty prefix matches every address, which would mark any spoofed
        # chain as trusted. It is always a misconfiguration (e.g. a trailing
        # comma in an env var), so fail loudly instead.
        if any(not p for p in proxy_list):
            raise ValueError("proxy_list entries must not be empty.")
        # proxy_count and proxy_list may both be set and may differ (v3 API):
        # the count is a hop-count requirement (minimum, or exact when strict)
        # and the list pins the client position. See _best_from_chain.
        if isinstance(precedence, str) or (
            precedence is not None and not all(isinstance(h, str) for h in precedence)
        ):
            raise ValueError("precedence must be a sequence of header-name strings.")

        # Copy, so later changes to the caller's objects cannot leak in.
        self.precedence = tuple(precedence) if precedence else DEFAULT_PRECEDENCE
        self.leftmost = leftmost
        self.proxy_count = proxy_count
        self.proxy_list = proxy_list
        self._proxy_matchers = [_compile_proxy_matcher(p) for p in self.proxy_list]

    # -- meta access --------------------------------------------------------

    def _get_meta_values(self, meta: Optional[Mapping[Any, Any]]) -> list[str]:
        if meta is None:
            return []
        if not isinstance(meta, Mapping):
            msg = f"meta must be a mapping of header names to values, got {type(meta).__name__}"
            raise TypeError(msg)
        folded = _build_folded(meta)
        values: list[str] = []
        for key in self.precedence:
            value = meta.get(key)
            if value is None:
                value = meta.get(key.replace("_", "-"))
            # Exact keys win; the folded view only fills gaps, so lowercase
            # keys (AWS Lambda / API Gateway v2, raw ASGI dicts) still match.
            if value is None:
                value = folded.get(_fold(key))
            # Header values are text; anything else (None, bytes, lists from
            # a misbehaving adapter) is ignored rather than crashing.
            if isinstance(value, str) and value.strip():
                values.append(value.strip())
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

    def get_client_ip(self, meta: Optional[Mapping[Any, Any]], strict: bool = False) -> tuple[OptionalIp, bool]:
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
