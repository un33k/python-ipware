# python-ipware 4.1.0

The first 4.x release on PyPI. 4.0.0 was tagged internally but never published, so this
release carries everything since 3.0.0: a pluggable algorithm router with a new default
engine, a better best-match for the client IP, tighter trusted-proxy matching, and a much
larger test suite. Existing code keeps working: `from python_ipware import IpWare` is
unchanged.

## Upgrade in one minute

- **Python 3.9 or newer** is required (3.7 and 3.8 are end of life). Tested on 3.9–3.14 and PyPy.
- **The default engine is now `modern`.** For normal, well-formed headers it returns the same
  address as 3.x. It differs where 3.x picked a worse address, see below.
- **Need the exact 3.x behavior?** `IpWare(algorithm="legacy")` runs the frozen v3 algorithm.
- **`proxy_list` is stricter.** A complete IP entry now matches exactly, not as a prefix. If you
  relied on `"1.2.3.4"` also matching `1.2.3.45`, use a CIDR or a prefix ending in `.`.
- **Misconfiguration now raises** `ValueError` when `IpWare(...)` is created instead of silently
  trusting the wrong thing: an empty `proxy_list` entry, a bare string instead of a list, a non-IP
  entry, or a negative / non-integer `proxy_count`.

## What changed since 3.0.0

### Algorithm router

`IpWare(algorithm="auto" | "modern" | "legacy")`. `auto` (the default) resolves to `modern`.
`legacy` keeps the v3 algorithm byte for byte, validated by the original v3 test suite.

### Best match for the client IP (modern)

- Every address is ranked: **public > private > link-local > loopback**. Unspecified, `0.0.0.0/8`,
  multicast, broadcast and reserved addresses are never returned. (Python reports multicast as
  global, so 3.x could return `224.0.0.1` as the client.)
- Without proxy settings, the **first public hop** of a chain wins, not just the first hop:
  `10.0.0.1, 177.139.233.139` now yields `177.139.233.139`. With `leftmost=False` the chain is
  scanned from the right. That public hop may be an upstream proxy; set `proxy_count` or
  `proxy_list` when you must identify private (intranet / VPN) clients.
- With `proxy_count` / `proxy_list`, the client position is fixed exactly as in 3.x, and
  `trusted_route` is now `True` for private clients behind trusted proxies too.

### Parsing (modern)

- RFC 7239 `Forwarded` is parsed by its `for=` value, quote-aware, including `for="[2001:db8::1]:4711"`.
- IPv4-mapped (`::ffff:1.2.3.4`) and NAT64 (`64:ff9b::1.2.3.4`) addresses unwrap to plain IPv4.
- Malformed tokens are rejected instead of truncated: `[::1`, `[::1]junk`, `1.2.3.4:abc`, `1.2.3.4:70000`.
- Header names match case-insensitively (`-` and `_` equivalent), so lowercase keys such as AWS
  Lambda's work. The dash spelling always wins, whatever the dict order, so a client-sent
  `x_forwarded_for` cannot shadow the proxy's `x-forwarded-for`.
- Non-string header values are skipped instead of crashing.

### Trusted proxies (modern)

- `proxy_list` entries: a **CIDR network** (IPv4 or IPv6, by membership), a **complete IP**
  (exact), or an **IP prefix** matched on whole octets / groups (`"10.1"` matches `10.1.x.x`, not
  `10.100.x.x`). IPv6 entries ignore case and leading zeros.
- IPv4-mapped and NAT64 CIDR entries (`::ffff:10.0.0.0/104`) match the unwrapped IPv4 hops.

### Default headers (modern)

Added, in order of arrival: `True-Client-IP`, `Fastly-Client-IP`, `Fly-Client-IP`, App Engine
`X-AppEngine-User-IP`, Azure `X-Client-IP`, Azure Front Door `X-Azure-ClientIP`, DigitalOcean
`DO-Connecting-IP`, Envoy `X-Envoy-External-Address`. Headers released earlier never move; new
ones sit just above `REMOTE_ADDR`, so an upgrade never lets a new header outrank one that already
resolved your requests.

### Packaging and CI

- PEP 621 `pyproject.toml` with the Hatchling backend; the version lives in `__version__.py`.
- CI runs the test matrix, then builds, then publishes on `v*` tags via PyPI trusted publishing.

### Tests

182 tests. The modern engine has 100% line and branch coverage, checked by an exhaustive matrix
against an independent reference model, a never-worse-than-legacy differential over the whole
matrix, formatting-invariance and fuzz runs, and mutation checks. The original v3 suite passes on
both engines.

## Thanks

@griffi-gh (#26, CIDR proxy entries), @mdalp (#23, Fly.io), @iloveitaly (#24, #25).

Full details: [CHANGELOG.md](https://github.com/un33k/python-ipware/blob/main/CHANGELOG.md).
