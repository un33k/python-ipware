"""The modern python-ipware engine.

Behavior-compatible with the v3 algorithm on the essentials, but cleaner and
hardened:

* Superset header precedence (adds True-Client-IP, Fastly, App Engine, Azure).
* Robust IPv6 / bracketed-port / IPv4-mapped parsing.
* Same "best IP" fallback ladder: prefer a globally routable address; else the
  first private; else loopback.
* Same ``strict`` semantics for proxy_count / proxy_list validation.
* Trusted-proxy matching anchored to the end of the chain. Each ``proxy_list``
  entry is either a CIDR network (``"100.64.0.0/10"``, ``"fd7a:115c:a1e0::/48"``)
  matched by real network membership, or a plain string prefix (``"10.1."``).
"""

import ipaddress
from typing import Optional, Union

from .defaults import DEFAULT_PRECEDENCE
from .parsers import IpAddressType, split_proxy_chain

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

        self.precedence = precedence or DEFAULT_PRECEDENCE
        self.leftmost = leftmost
        self.proxy_count = proxy_count
        self.proxy_list = list(proxy_list or [])
        self._proxy_matchers = [_compile_proxy_matcher(p) for p in self.proxy_list]

    # -- meta access --------------------------------------------------------

    def _get_meta_value(self, meta: dict[str, str], key: str) -> str:
        meta = meta or {}
        return meta.get(key, meta.get(key.replace("_", "-"), "")).strip()

    def _get_meta_values(self, meta: dict[str, str]) -> list[str]:
        values: list[str] = []
        for key in self.precedence:
            value = self._get_meta_value(meta, key)
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
        # ``chain`` is already client-first (see get_client_ip).
        if not chain:
            return None, False
        if self.proxy_list:
            return chain[-(len(self.proxy_list) + 1)], True
        if self.proxy_count is not None:
            return chain[-(self.proxy_count + 1)], True
        return chain[0], False

    # -- public API ---------------------------------------------------------

    def get_client_ip(
        self, meta: dict[str, str], strict: bool = False
    ) -> tuple[OptionalIp, bool]:
        loopback: list[IpAddressType] = []
        private: list[IpAddressType] = []

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
            if ip.is_global:
                return ip, trusted
            if ip.is_loopback:
                loopback.append(ip)
            else:
                private.append(ip)

        if private:
            return private[0], False
        if loopback:
            return loopback[0], False
        return None, False
