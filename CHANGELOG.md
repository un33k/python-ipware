## 4.1.0

Best match (modern engine only; legacy is unchanged). Results can differ from 4.0.0 on well-formed input,
always toward a better address; use `algorithm="legacy"` for exact v3 results:
- Addresses are ranked public > private > link-local > loopback. Unspecified (`0.0.0.0`, `::`),
  multicast, broadcast, and reserved addresses are never returned. Python reports multicast as
  `is_global`, so v3 could return `224.0.0.1` as the client.
- Without `proxy_count` / `proxy_list`, the first public hop of a chain wins, not only the first hop:
  `10.0.0.1, 177.139.233.139` now yields `177.139.233.139`. With `leftmost=False` the scan runs from the
  right. With proxy settings, the client position is fixed exactly as before. Note that the public hop
  may be an upstream proxy: if you must identify private (intranet / VPN) clients, set `proxy_count` or
  `proxy_list`.
- NAT64 well-known-prefix addresses (`64:ff9b::a.b.c.d`, RFC 6052) are unwrapped to the embedded IPv4
  client, like IPv4-mapped addresses. v3 returned the IPv6 form.
- `trusted_route` is `True` for any address resolved through a matching proxy config, including private
  clients; v3 reported `False` for them.
- New exhaustive tests: every 1–3 hop chain over ten address kinds, in every leftmost / strict / proxy
  configuration, checked against an independent reference model; every header assignment and dict order;
  every spelling of a hop; never-worse-than-legacy across the whole matrix; seeded fuzzing.

Enhance (modern engine only; legacy is unchanged):
- Parse RFC 7239 `Forwarded` elements by their `for=` value, including quoted, bracketed IPv6 with a port.
  Previously `Forwarded` never produced an IP, so when it is present it can now resolve at its existing
  precedence slot, which is above the CDN headers. Like `X-Forwarded-For`, a client can send it; behind a
  CDN, pass an explicit `precedence` naming that CDN's header. Obfuscated hops (`for=unknown`, `for=_hidden`) count as invalid tokens.
- New default headers, added only between the 4.0.0 entries and `REMOTE_ADDR`, so none outranks a header
  that resolved requests before: Azure Front Door `X-Azure-ClientIP`, DigitalOcean `DO-Connecting-IP`,
  Envoy/Istio `X-Envoy-External-Address`, plus the missing `HTTP_X_CLIENT_IP` and raw `X-AppEngine-User-IP`
  forms of headers already on the list.
- Header names match case-insensitively (`-` and `_` equivalent), so lowercase keys such as AWS Lambda's
  work. Exact keys still take priority. When several spellings fold to the same header, the dash spelling
  wins, whatever the dict order, so a client-sent `x_forwarded_for` cannot shadow the proxy's
  `x-forwarded-for`. Dash spellings that disagree are treated as absent.

Harden (modern engine only):
- Reject malformed tokens instead of truncating them: unclosed brackets (`[::1`), text after a bracket
  (`[::1]junk`), and non-numeric, empty, or out-of-range ports (`1.2.3.4:abc`, `1.2.3.4:70000`). Note v3
  accepted `1.2.3.4:abc` as `1.2.3.4`.
- Non-string header values (`None`, bytes) are skipped instead of raising `AttributeError`.
- `proxy_list` entries are stripped of whitespace. An empty entry now raises `ValueError`: it used to match
  every address and mark any spoofed chain as trusted.
- Trusted-proxy matching is tighter. A complete IP entry is matched exactly: v3 prefix-matched it, so
  `"1.2.3.4"` also trusted `1.2.3.45`, letting that host forge the client IP. Prefixes match on whole
  octets or groups (`"10.1"` matches `10.1.x.x`, not `10.100.x.x`). IPv6 entries are case- and
  zero-insensitive. An entry ending in `:` stays a prefix, so `"2001:db8::"` behaves as in 4.0.0.
  IPv4-mapped and NAT64 CIDR entries (`::ffff:10.0.0.0/104`) match the unwrapped IPv4 hops.
- Configuration errors raise `ValueError` at construction instead of misbehaving silently: `proxy_list`
  or `precedence` passed as a bare string (each character became an entry), a non-IP `proxy_list` entry
  such as `"foo"`, or a `proxy_count` that is a bool, a float, or a string. `precedence` and `proxy_list`
  are copied, so later changes to the caller's lists have no effect.
- A `meta` that is not a mapping raises `TypeError` with a clear message. Non-string keys are skipped.
- RFC 7239 `Forwarded` parsing is quote-aware: a `,` or `;` inside a quoted value no longer splits a hop,
  so `ext="x,8.8.8.8"` cannot smuggle in a fake address or a fake proxy hop.
- More address classes: `0.0.0.0/8` is never returned. Deprecated site-local `fec0::/10` ranks as
  private, since Python reports it as global. RFC 8215 local-use NAT64 `64:ff9b:1::/48` ranks as private,
  since Python reports it as reserved.
- The unused `is_valid_ip` helper was removed from `python_ipware.modern.parsers`. It was never exported.
- Test suite: 100% line and branch coverage of the modern engine.

CI:
- Bump `actions/upload-artifact` to v7 and `actions/download-artifact` to v8, which run on Node 24.

## 4.0.0

Community (thank you!):
- Trusted proxies in `proxy_list` can now be CIDR networks, IPv4 or IPv6 (e.g. `100.64.0.0/10`), matched by
  real network membership; plain prefixes still work. Modern engine only. Requested by @griffi-gh (#26).
- Added Fly.io's `Fly-Client-IP` header to the modern default precedence. Suggested by @mdalp (#23).
- README now shows how to put a CDN header such as Cloudflare's first via `precedence`, when all traffic
  comes through that CDN. Suggested by @iloveitaly (#25).
- CI covers Python 3.13 and newer. Suggested by @iloveitaly (#24).

Enhance:
- Introduce a pluggable algorithm router: `IpWare(algorithm=...)` with `"auto"` (default), `"modern"`, and `"legacy"`.
  - `"auto"` resolves to `"modern"` — the enhanced engine and the forward-moving default.
  - `"legacy"` is an explicit escape hatch that runs the frozen v3 algorithm byte-for-byte.
- New `modern` engine: hardened IPv6 / bracketed-port / IPv4-mapped parsing and an expanded default header
  precedence list (adds `True-Client-IP`, `Fastly-Client-IP`, App Engine, Azure `X-Client-IP`).
- The frozen v3 algorithm is preserved unchanged under `python_ipware.legacy`; the original v3 test suite
  passes against both the legacy and modern engines.

Modernize:
- Migrate packaging to PEP 621 with the Hatchling build backend; version is read from `__version__.py`.
- Drop end-of-life Python 3.7 / 3.8; requires Python 3.9+, tested on 3.9–3.14.
- Bump ruff config to the `lint.*` table layout.

Note:
- No source change is required for existing users: `from python_ipware import IpWare` continues to work and
  now defaults to the modern engine. On well-formed headers modern returns the same result as v3 (the full
  v3 suite and a legacy-vs-modern differential test pass). It differs only on malformed values:
  - quoted addresses such as `"1.2.3.4"` are accepted (v3 ignored them);
  - a value with more than one port-like suffix, such as `1.2.3.4:80:90`, is rejected (v3 took `1.2.3.4`).
  Use `IpWare(algorithm="legacy")` if you depend on the exact v3 handling of those inputs.

## 3.0.0

Fix:
- Release major version, as there is a possibility of api change causing minimal backward incompatibly

## 2.0.5

Enhance:
- AI assisted clean up

## 2.0.4

Enhance:
- Added `proxy_count=0` as an option (@FraKraBa)

## 2.0.3

Enhance:
- Added `HTTP_CF_CONNECTING_IP` to list of known ip headers (Adam M.)

## 2.0.2

Enhance:
- Added logger name

## 2.0.1

Issue:
- Remove `HTTP_VIA` header support (unreliable IP information) (@yourcelf)

Enhance:
- Include support for python 3.12

## 2.0.0

- Introduced breaking changes to avoid conflicts with the `django-ipware` package.
- Renamed the imported module from `ipware` to `python_ipware` in the `python-ipware` package.
  - Old usage: `from ipware import IpWare`
  - New usage: `from python_ipware import IpWare`

## 1.0.5

- Enhance: Readme updates

## 1.0.0

Features:

- Added `X-CLIENT-IP` header support
- Adds PEP 561 Compatibility (@stumpylog)
- Streamline pyproject.toml & add trusted publishing (@stumpylog)
- Publish version 1.0.0

## 0.9.0

Features:

- Initial Release
