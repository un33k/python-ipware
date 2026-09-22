"""Run the untouched v3 test suite against the frozen legacy engine.

The original v3 test files (``tests_ipv4.py``, ``tests_ipv6.py``) are kept
byte-for-byte and import ``from python_ipware import IpWare`` — which now
resolves to the *modern* engine by default. This runner rebinds that name to
the legacy engine so the frozen algorithm is validated against its own
original test suite, without modifying the test files.

Usage::

    python -m tests.legacy.run_against_legacy
"""

from __future__ import annotations

import functools
import sys
import unittest

from python_ipware import IpWare

from . import tests_ipv4, tests_ipv6

LegacyBound = functools.partial(IpWare, algorithm="legacy")


def build_suite() -> unittest.TestSuite:
    # Rebind the IpWare symbol the untouched test modules use.
    tests_ipv4.IpWare = LegacyBound  # type: ignore[attr-defined]
    tests_ipv6.IpWare = LegacyBound  # type: ignore[attr-defined]

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromModule(tests_ipv4))
    suite.addTests(loader.loadTestsFromModule(tests_ipv6))
    return suite


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=1).run(build_suite())
    sys.exit(0 if result.wasSuccessful() else 1)
