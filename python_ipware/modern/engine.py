"""The modern python-ipware engine.

Behavior-compatible with the v3 algorithm on the essentials, but cleaner and
hardened:

* Superset header precedence (adds True-Client-IP, Fastly, App Engine, Azure).
* Robust IPv6 / bracketed-port / IPv4-mapped parsing.
* Same "best IP" fallback ladder: prefer a globally routable address; else the
  first private; else loopback.
* Same ``strict`` semantics for proxy_count / proxy_list validation.
* Trusted-proxy matching by prefix, anchored to the end of the chain.
"""

from typing import Optional

from .defaults import DEFAULT_PRECEDENCE
from .parsers import IpAddressType, split_proxy_chain

OptionalIp = Optional[IpAddressType]


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
        # Compare the trailing proxies against the trusted prefixes in order.
        return all(
            str(ip).startswith(pattern)
            for ip, pattern in zip(chain[-count:], self.proxy_list)
        )

    # -- selection ----------------------------------------------------------

    def _best_from_chain(self, chain: list[IpAddressType]) -> tuple[OptionalIp, bool]:
        if not chain:
            return None, False

        # Order the chain client-first regardless of leftmost, so indexing is
        # consistent. XFF is naturally client, proxy1, proxy2 ...
        ordered = chain if self.leftmost else list(reversed(chain))

        if self.proxy_list:
            idx = len(self.proxy_list) + 1
            return ordered[-idx], True
        if self.proxy_count is not None:
            idx = self.proxy_count + 1
            return ordered[-idx], True
        return ordered[0], False

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
