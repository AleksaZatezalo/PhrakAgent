#!/usr/bin/env python3
"""
Description: Thin shim so ``python cli.py ...`` keeps working after packaging.
Author: Aleksa Zatezalo
Date Created: 07-29-2026
"""

from appsec.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
