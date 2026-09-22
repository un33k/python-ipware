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
