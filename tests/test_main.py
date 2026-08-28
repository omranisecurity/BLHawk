"""Smoke tests for the BLHawk package.

The original single-file entry point has been refactored into the ``blhawk``
package. A full CLI regression test lives in ``tests/test_cli.py``.
"""
from __future__ import annotations

import blhawk
from blhawk.core.models import Verdict


def test_package_exposes_version():
    assert isinstance(blhawk.__version__, str)
    assert blhawk.__version__


def test_verdict_ordering_404_never_exceeds_dead_resource():
    # A plain dead resource must rank below any takeover verdict.
    assert Verdict.DEAD_RESOURCE.rank < Verdict.LIKELY_TAKEOVER.rank
    assert Verdict.NOT_VULNERABLE.rank < Verdict.UNKNOWN.rank
