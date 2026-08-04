"""
Description: Opengrep wrappers — static analysis and secrets scanning via Opengrep.
Author: Aleksa Zatezalo
Date Created: 07-30-2026
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from langchain_core.tools import tool

from ..runtime import require_config
from .common import ANALYSIS_MAX, run_cli, workspace

DEFAULT_TIMEOUT = 300
# Default rule surface. `auto` selects Opengrep's curated security rules; callers
# can pass a local rules path/dir or a registry id for offline / targeted scans.
DEFAULT_CONFIG = "auto"
SECRETS_CONFIG = "p/secrets"
# Per-worker memory cap (MB). Opengrep skips an oversized file instead of getting
# OOM-killed by the OS — an OOM kill surfaces as a bare `exit 2` with no output.
MAX_MEMORY_MB = 2000
# Fewer parallel workers → lower peak RAM when the box is already loaded
# (e.g. a local LLM holding most of memory).
JOBS = 2


def _opengrep_bin() -> str:
    return os.environ.get("PHRAK_OPENGREP_BIN", "opengrep")


def _exclude_args() -> list[str]:
    """`--exclude` flags for every dir we never want to scan.

    This isn't a git repo in the common case, so Opengrep won't honour
    ``.gitignore``; without these it walks ``venv``/``site-packages`` (tens of
    thousands of files) and can OOM. We reuse the same exclude list the RAG
    index uses so scanning and indexing agree, plus PHRAK's own state dir.
    """
    try:
        dirs = list(require_config().rag.exclude_dirs)
    except Exception:  # pragma: no cover - defensive: config not yet loaded
        dirs = ["venv", ".venv", "node_modules", "__pycache__", "site-packages"]
    dirs += ["workspace", ".phrack"]  # analyzer state / PHRAK state, never targets
    args: list[str] = []
    for d in dict.fromkeys(dirs):  # de-dupe, preserve order
        args += ["--exclude", d]
    return args


def _run(path: str, config: str) -> tuple[dict | None, str | None]:
    target = (workspace() / path).resolve()
    if not target.exists():
        return None, f"Path not found: {path}"
    cmd = [
        _opengrep_bin(),
        "scan",
        "--config",
        config,
        "--json",
        "--quiet",
        "--timeout",
        "60",
        "--max-memory",
        str(MAX_MEMORY_MB),
        "--jobs",
        str(JOBS),
        *_exclude_args(),
        str(target),
    ]
    res = run_cli(cmd, timeout=DEFAULT_TIMEOUT)
    if res.error:
        if "not installed" in res.error:
            return None, (
                "opengrep is not installed / not on PATH. Install Opengrep "
                "(https://opengrep.dev) to enable this tool, or set "
                "$PHRAK_OPENGREP_BIN to its path."
            )
        return None, res.error
    # Exit 2 = Opengrep's own fatal/internal error (OOM-killed worker, parse
    # crash, bad ruleset). It is NOT "found issues" — Opengrep uses 0 even with
    # findings. Surface the real reason (stderr) instead of a misleading
    # "no output / needs network" message.
    if res.returncode not in (0, 1) and not res.stdout.strip():
        err = res.stderr.strip()
        return None, (
            f"opengrep failed (exit {res.returncode}): "
            + (
                err[:400]
                if err
                else "internal error — likely out of memory "
                "on a large tree; scan a narrower path (e.g. ./target)."
            )
        )
    if not res.stdout.strip():
        err = res.stderr.strip()
        return None, (
            "opengrep produced no output"
            + (
                f": {err[:400]}"
                if err
                else " (ruleset may need network access; "
                "point --config at a local rules path for offline scans)"
            )
        )
    try:
        return json.loads(res.stdout), None
    except json.JSONDecodeError:
        return None, f"could not parse opengrep output: {res.stderr[:400]}"


def _format(data: dict, config: str) -> str:
    root = workspace()
    results = data.get("results", [])
    if not results:
        errs = data.get("errors", [])
        note = f" ({len(errs)} scan error(s))" if errs else ""
        return f"No findings from opengrep ({config}).{note}"

    # sort by severity so the worst show first
    order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    results.sort(key=lambda r: order.get(r.get("extra", {}).get("severity", ""), 3))

    lines = [f"{len(results)} finding(s) from opengrep ({config}):"]
    for r in results:
        p = r.get("path", "")
        try:
            p = str(Path(p).resolve().relative_to(root))
        except ValueError:
            pass
        line = r.get("start", {}).get("line", "?")
        extra = r.get("extra", {})
        sev = extra.get("severity", "")
        check = (r.get("check_id", "") or "").split(".")[-1]
        msg = " ".join((extra.get("message", "") or "").split())
        lines.append(f"- {p}:{line} [{sev}] {check}\n    {msg[:220]}")
    return "\n".join(lines)[:ANALYSIS_MAX]


@tool
def opengrep_scan(path: str = ".", config: str = DEFAULT_CONFIG) -> str:
    """Run Opengrep static analysis over the code and return findings.

    `config` is an Opengrep ruleset: 'auto' (default, curated security rules), a
    registry id (e.g. 'p/owasp-top-ten', 'p/python'), or a path to a local rules
    file/directory (best for fully-offline scans). Findings come back as
    file:line [severity] rule -> message."""
    data, err = _run(path, config)
    if err:
        return err
    return _format(data, config)


@tool
def scan_secrets(path: str = ".") -> str:
    """Scan for hardcoded secrets/credentials with Opengrep's secrets ruleset:
    API keys, tokens, private keys, etc. Returns file:line matches."""
    data, err = _run(path, SECRETS_CONFIG)
    if err:
        return err
    return _format(data, SECRETS_CONFIG)


def opengrep_tools() -> list:
    return [opengrep_scan, scan_secrets]
