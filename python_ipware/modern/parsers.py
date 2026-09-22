"""Framework-agnostic IP parsing helpers for the modern engine.

Pure stdlib. Knows how to clean raw header tokens, strip ports/brackets,
validate IPv4/IPv6, and split proxy chains.
"""

import ipaddress
from typing import Optional, Union

IpAddressType = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def strip_port(value: str) -> str:
    """Remove a trailing ``:port`` (IPv4) or ``[addr]:port`` (IPv6) suffix."""
    value = value.strip()
    if not value:
        return value

    if value.startswith("["):  # [addr] or [addr]:port
        end = value.find("]")
        if end != -1:
            return value[1:end]
        return value.lstrip("[")

    if value.count(":") == 1:  # IPv4:port
        host, _, _ = value.partition(":")
        return host

    return value  # bare IPv6 or bare IPv4


def clean_ip(value: Optional[str]) -> str:
    """Normalize a raw candidate token into a bare IP string."""
    if not value:
        return ""
    value = value.strip().strip('"').strip("'")
    value = strip_port(value)
    return value.strip()


def parse_ip(value: Optional[str]) -> Optional[IpAddressType]:
    """Return a validated ip_address object, or None. Unwraps IPv4-mapped IPv6."""
    cleaned = clean_ip(value)
    if not cleaned:
        return None
    try:
        ip = ipaddress.ip_address(cleaned)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def split_proxy_chain(raw: Optional[str], strict: bool = False) -> Optional[list[IpAddressType]]:
    """Split a comma-separated proxy chain into ordered ``ip_address`` objects.

    Order is preserved left-to-right (``client, proxy1, proxy2``). In strict
    mode, a single invalid token makes the whole chain invalid (returns None).
    Otherwise invalid tokens are skipped.
    """
    if not raw:
        return []
    result: list[IpAddressType] = []
    for token in raw.split(","):
        ip = parse_ip(token)
        if ip is not None:
            result.append(ip)
        elif strict and token.strip():
            return None
    return result


def is_valid_ip(value: Optional[str]) -> bool:
    return parse_ip(value) is not None
