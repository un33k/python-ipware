# python-ipware 4.0.0

> DRAFT — for review only. Not published. When ready, this becomes the GitHub
> release body for tag `v4.0.0`.

A major release that introduces a pluggable algorithm router and modernizes the
packaging. The new **modern** engine is the default and is a verified behavioral
superset of the v3 algorithm — the full v3 test suite passes against it. The
**legacy** v3 algorithm is preserved byte-for-byte as an explicit escape hatch.

## Highlights

- **Algorithm router.** `IpWare(algorithm=...)` selects the engine:
  - `modern` (new default, also via `auto`) — hardened IPv6 / bracketed-port /
    IPv4-mapped parsing and an expanded default header precedence list
    (adds True-Client-IP, Fastly, App Engine, Azure).
  - `legacy` — the exact v3 algorithm, frozen byte-for-byte. Requested explicitly only.
- **Modern packaging.** PEP 621 `pyproject.toml` with the Hatchling backend,
  dynamic version, SPDX license metadata, refreshed classifiers.
- **Cleaner modern code.** Native builtin generics (`list`, `dict`, `tuple`);
  no `from __future__ import annotations`.

## Python support

Python 3.9+ (tested on 3.9 – 3.14). Dropped end-of-life Python 3.7 and 3.8.

## Upgrading

Existing `IpWare()` callers get the modern engine by default. If you require
byte-for-byte v3 results, pin the legacy engine:

```python
from python_ipware import IpWare

ipw = IpWare(algorithm="legacy")
ip, trusted = ipw.get_client_ip(request.META)
```

**Full Changelog**: https://github.com/un33k/python-ipware/compare/v3.0.0...v4.0.0

🚀 Generated with [Dojo](https://heydojo.ai) ⛩️
