"""Frozen v3 algorithm.

This subpackage preserves the exact behavior of python-ipware 3.x. It is kept
byte-for-byte stable so that projects upgrading to 4.x can pin
``algorithm="legacy"`` and get identical results to what they had before.

Do not "improve" this module. New behavior belongs in ``python_ipware.modern``.
"""

from .engine import IpWare as LegacyIpWare

__all__ = ["LegacyIpWare"]
