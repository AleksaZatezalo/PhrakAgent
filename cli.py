#!/usr/bin/env python3
"""Thin shim so ``python cli.py ...`` keeps working after packaging.

The real CLI lives in :mod:`appsec.cli` (exposed as the ``phrak`` console script).
"""

from appsec.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
