"""Public ``IpWare`` facade with an algorithm router.

python-ipware 4.x ships two engines:

* ``legacy``  -> the frozen, byte-compatible v3 algorithm.
* ``modern``  -> the enhanced v4 algorithm (more headers, hardened parsing).

The ``algorithm`` selector chooses between them. ``"auto"`` (the default) is a
clean alias for ``"modern"`` — the enhanced engine is where development moves
forward. It passes the full v3 suite, and a differential test checks it never
returns a worse address than v3. It picks better where v3 did not: a public
hop behind a private first hop, no multicast / unspecified results, and
``trusted_route`` for private clients behind trusted proxies (see CHANGELOG).
``legacy`` remains available as an explicit escape hatch for projects that
need byte-for-byte v3 behavior. There is no silent runtime fallback, so
behavior stays predictable.

    from python_ipware import IpWare

    IpWare()                      # auto -> modern (the forward-moving default)
    IpWare(algorithm="modern")    # explicit modern
    IpWare(algorithm="legacy")    # frozen v3 behavior (escape hatch)
"""

from typing import Literal, Optional

from .legacy import LegacyIpWare
from .modern import ModernIpWare

Algorithm = Literal["auto", "modern", "legacy"]
_VALID = ("auto", "modern", "legacy")


class IpWare:
    """Best-effort client IP resolver with a pluggable algorithm."""

    def __init__(
        self,
        precedence: Optional[tuple[str, ...]] = None,
        leftmost: bool = True,
        proxy_count: Optional[int] = None,
        proxy_list: Optional[list[str]] = None,
        algorithm: Algorithm = "auto",
    ) -> None:
        if algorithm not in _VALID:
            msg = f"algorithm must be one of {_VALID}, got {algorithm!r}"
            raise ValueError(msg)

        self.algorithm: Algorithm = algorithm
        # "auto" resolves to "modern": the enhanced engine is the forward-moving
        # default. "legacy" stays available as an explicit escape hatch.
        resolved = "modern" if algorithm == "auto" else algorithm
        self.resolved_algorithm = resolved

        if resolved == "legacy":
            self._impl = LegacyIpWare(
                precedence=precedence,
                leftmost=leftmost,
                proxy_count=proxy_count,
                proxy_list=proxy_list,
            )
        else:
            self._impl = ModernIpWare(
                precedence=precedence,
                leftmost=leftmost,
                proxy_count=proxy_count,
                proxy_list=proxy_list,
            )

    @property
    def engine(self) -> "LegacyIpWare | ModernIpWare":
        """The concrete engine instance selected by ``algorithm`` (read-only)."""
        return self._impl

    def get_client_ip(self, meta, strict: bool = False):
        """Delegate to the resolved engine. Returns ``(ip, trusted_route)``."""
        return self._impl.get_client_ip(meta, strict)

    def __repr__(self) -> str:
        return (
            f"IpWare(algorithm={self.algorithm!r} -> "
            f"{self.resolved_algorithm!r})"
        )
