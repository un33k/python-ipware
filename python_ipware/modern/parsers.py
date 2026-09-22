"""Framework-agnostic IP parsing helpers for the modern engine.

Pure stdlib. Knows how to clean raw header tokens, strip ports/brackets,
read RFC 7239 ``Forwarded`` elements, validate IPv4/IPv6, and split proxy
chains.
"""

import ipaddress
from typing import Optional, Union

IpAddressType = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# How good an address is as a client IP; higher wins. REJECT is never returned.
TIER_REJECT = 0
TIER_LOOPBACK = 1
TIER_LINK_LOCAL = 2
TIER_PRIVATE = 3  # RFC 1918, ULA, CGNAT 100.64/10, documentation ranges, ...
TIER_GLOBAL = 4


def ip_tier(ip: IpAddressType) -> int:
    """Rank ``ip`` as a client address candidate.

    Check order matters: Python reports multicast (``224.0.0.1``, ``ff02::1``)
    and the deprecated ``::a.b.c.d`` form as ``is_global``, and ``::1`` as
    ``is_reserved``, so those are resolved before ``is_global`` is trusted.
    Unspecified, multicast, broadcast and reserved addresses can never be a
    real client and are rejected outright.
    """
    if ip.is_unspecified or ip.is_multicast:
        return TIER_REJECT
    if ip.is_loopback:
        return TIER_LOOPBACK
    if ip.is_reserved:  # 240.0.0.0/4 incl. 255.255.255.255; unallocated IPv6
        return TIER_REJECT
    if ip.is_global:
        return TIER_GLOBAL
    if ip.is_link_local:
        return TIER_LINK_LOCAL
    return TIER_PRIVATE


def _is_port(value: str) -> bool:
    # isascii() guards against Unicode digits such as "²" that isdigit() accepts.
    return value.isascii() and value.isdigit() and int(value) <= 65535


def strip_port(value: str) -> str:
    """Remove a trailing ``:port`` (IPv4) or ``[addr]:port`` (IPv6) suffix.

    Returns ``""`` for a malformed token (unclosed bracket, text after the
    bracket, or a non-numeric/out-of-range port) so it is rejected rather than
    silently truncated into something that looks valid.
    """
    value = value.strip()
    if not value:
        return value

    if value.startswith("["):  # [addr] or [addr]:port
        end = value.find("]")
        if end == -1:
            return ""
        rest = value[end + 1 :]
        if rest and not (rest.startswith(":") and _is_port(rest[1:])):
            return ""
        return value[1:end]

    if value.count(":") == 1:  # IPv4:port
        host, _, port = value.partition(":")
        return host if _is_port(port) else ""

    return value  # bare IPv6 or bare IPv4


def forwarded_for(element: str) -> str:
    """Return the ``for=`` value of one RFC 7239 ``Forwarded`` element.

    ``for=192.0.2.60;proto=http;by=203.0.113.43`` -> ``192.0.2.60``. Parameter
    names are case-insensitive. Returns ``""`` when the element has no ``for``
    parameter, so the hop counts as invalid instead of being guessed at.
    """
    for pair in element.split(";"):
        key, sep, val = pair.partition("=")
        if sep and key.strip().lower() == "for":
            return val.strip()
    return ""


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

    Order is preserved left-to-right as it appears in the header. Tokens in
    RFC 7239 form (``for=...;proto=...``) are reduced to their ``for`` value;
    obfuscated identifiers such as ``for=unknown`` or ``for=_hidden`` are not
    IPs and count as invalid. In strict mode, any invalid or empty token makes
    the whole chain invalid (returns None), since a malformed header should not
    be trusted. Otherwise invalid and empty tokens are skipped.
    """
    if not raw:
        return []
    result: list[IpAddressType] = []
    for token in raw.split(","):
        # No plain IP token contains "=", only RFC 7239 Forwarded elements do.
        candidate = forwarded_for(token) if "=" in token else token
        ip = parse_ip(candidate)
        if ip is not None:
            result.append(ip)
        elif strict:
            return None
    return result


def is_valid_ip(value: Optional[str]) -> bool:
    return parse_ip(value) is not None
