#!/usr/bin/env python3
"""Backward-compatible launcher for BLHawk.

The implementation now lives in the ``blhawk`` package. This shim keeps the
historical ``python blhawk.py ...`` invocation working by delegating to the
package CLI (``blhawk.cli.main``). Prefer the installed ``blhawk`` console
script or ``python -m blhawk``.
"""
from __future__ import annotations

from blhawk.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
