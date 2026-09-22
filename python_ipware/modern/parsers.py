"""Framework-agnostic IP parsing helpers for the modern engine.

Pure stdlib. Knows how to clean raw header tokens, strip ports/brackets,
read RFC 7239 ``Forwarded`` elements, validate IPv4/IPv6, and split proxy
chains.
"""

import ipaddress
from typing import Optional, Union

IpAddressType = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IpNetworkType = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# RFC 6052 well-known NAT64 prefix; the low 32 bits are the IPv4 client.
_NAT64_WKP = ipaddress.IPv6Network("64:ff9b::/96")
# RFC 8215 local-use NAT64 prefix. The IPv4 position depends on the operator's
# chosen prefix length, so it is not unwrapped; it is ranked as private.
_NAT64_LOCAL = ipaddress.IPv6Network("64:ff9b:1::/48")
# IPv4-mapped IPv6 space. Hops in it are unwrapped to IPv4.
_IPV4_MAPPED = ipaddress.IPv6Network("::ffff:0:0/96")
# RFC 1122 "this network": never a valid source address.
_THIS_NETWORK = ipaddress.IPv4Network("0.0.0.0/8")

# How good an address is as a client IP; higher wins. REJECT is never returned.
TIER_REJECT = 0
TIER_LOOPBACK = 1
TIER_LINK_LOCAL = 2
TIER_PRIVATE = 3  # RFC 1918, ULA, CGNAT 100.64/10, documentation ranges, ...
TIER_GLOBAL = 4


def ip_tier(ip: IpAddressType) -> int:
    """Rank ``ip`` as a client address candidate.

    Check order matters: Python reports multicast (``224.0.0.1``, ``ff02::1``),
    site-local ``fec0::/10`` and the deprecated ``::a.b.c.d`` form as
    ``is_global``, and ``::1`` and ``64:ff9b:1::/48`` as ``is_reserved``, so
    those are resolved before ``is_reserved`` / ``is_global`` are trusted.
    Unspecified, ``0.0.0.0/8``, multicast, broadcast and reserved addresses can
    never be a real client and are rejected outright. NAT64 well-known-prefix
    addresses never reach here: ``parse_ip`` unwraps them to IPv4 first.

    Global/private classification comes from the running Python's
    ``ipaddress`` tables, which changed in 3.12 (e.g. 6to4 ``2002::/16`` is
    global on 3.11 but private on 3.12+).
    """
    if ip.is_unspecified or ip.is_multicast:
        return TIER_REJECT
    if isinstance(ip, ipaddress.IPv4Address) and ip in _THIS_NETWORK:
        return TIER_REJECT
    if ip.is_loopback:
        return TIER_LOOPBACK
    if isinstance(ip, ipaddress.IPv6Address) and ip in _NAT64_LOCAL:
        return TIER_PRIVATE  # Python calls it reserved (it sits in ::/8)
    if ip.is_reserved:  # 240.0.0.0/4 incl. 255.255.255.255; unallocated IPv6
        return TIER_REJECT
    if isinstance(ip, ipaddress.IPv6Address) and ip.is_site_local:
        return TIER_PRIVATE  # deprecated fec0::/10, which Python calls global
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


def split_unquoted(value: str, sep: str) -> list[str]:
    """Split ``value`` on ``sep``, ignoring separators inside double quotes.

    RFC 7239 values may be quoted strings (``by="a,b"``), and a separator
    inside one must not start a new hop or parameter. Backslash escapes inside
    quotes are honoured. An unclosed quote swallows the rest of the value, so
    that token fails to parse instead of leaking a fragment as a fake hop.
    """
    if '"' not in value:
        return value.split(sep)
    parts: list[str] = []
    buf: list[str] = []
    quoted = escaped = False
    for ch in value:
        if escaped:
            escaped = False
        elif quoted and ch == "\\":
            escaped = True
        elif ch == '"':
            quoted = not quoted
        elif ch == sep and not quoted:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    parts.append("".join(buf))
    return parts


def forwarded_for(element: str) -> str:
    """Return the ``for=`` value of one RFC 7239 ``Forwarded`` element.

    ``for=192.0.2.60;proto=http;by=203.0.113.43`` -> ``192.0.2.60``. Parameter
    names are case-insensitive, and ``;`` inside quoted values is not a
    separator. Returns ``""`` when the element has no ``for`` parameter, so the
    hop counts as invalid instead of being guessed at.
    """
    for pair in split_unquoted(element, ";"):
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
    """Return a validated ip_address object, or None.

    Unwraps IPv4-mapped IPv6 (``::ffff:a.b.c.d``) and the RFC 6052 NAT64
    well-known prefix (``64:ff9b::a.b.c.d``) to the embedded IPv4 client.
    """
    cleaned = clean_ip(value)
    if not cleaned:
        return None
    try:
        return unwrap_ipv4(ipaddress.ip_address(cleaned))
    except ValueError:
        return None


def unwrap_ipv4(ip: IpAddressType) -> IpAddressType:
    """Return the IPv4 address embedded in an IPv4-mapped or NAT64-WKP address."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip in _NAT64_WKP:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip


def unwrap_ipv4_network(net: IpNetworkType) -> IpNetworkType:
    """IPv4 network embedded in a /96-or-longer IPv4-mapped or NAT64-WKP network.

    Hops in those ranges are unwrapped to IPv4 before matching, so a trusted
    proxy written as ``::ffff:10.0.0.0/104`` must match the IPv4 hop too.
    """
    if isinstance(net, ipaddress.IPv6Network) and net.prefixlen >= 96:
        for embedding in (_IPV4_MAPPED, _NAT64_WKP):
            if net.subnet_of(embedding):
                return ipaddress.IPv4Network((int(net.network_address) & 0xFFFFFFFF, net.prefixlen - 96))
    return net


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
    for token in split_unquoted(raw, ","):
        # No plain IP token contains "=", only RFC 7239 Forwarded elements do.
        candidate = forwarded_for(token) if "=" in token else token
        ip = parse_ip(candidate)
        if ip is not None:
            result.append(ip)
        elif strict:
            return None
    return result
