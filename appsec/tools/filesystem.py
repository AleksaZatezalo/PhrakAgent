"""
Description: Read-only filesystem tools, sandboxed to the configured workspace root.
Author: Aleksa Zatezalo
Date Created: 07-30-2026
"""

from __future__ import annotations

from langchain_core.tools import tool

from .common import FILE_READ_MAX, excluded_dirs, resolve_in_workspace, run_cli


@tool
def list_dir(path: str = ".") -> str:
    """List files and directories under a path within the workspace."""
    try:
        p = resolve_in_workspace(path)
    except ValueError as e:
        return str(e)
    if not p.exists():
        return f"Not found: {path}"
    entries = [f"{c.name}{'/' if c.is_dir() else ''}" for c in sorted(p.iterdir())]
    return "\n".join(entries) or "(empty)"


@tool
def read_file(path: str) -> str:
    """Read a text file (truncated to 60KB) from within the workspace."""
    try:
        p = resolve_in_workspace(path)
    except ValueError as e:
        return str(e)
    if not p.exists() or not p.is_file():
        return f"Not a file: {path}"
    try:
        data = p.read_text(errors="replace")
    except Exception as e:
        return f"Error reading {path}: {e}"
    if len(data) > FILE_READ_MAX:
        return data[:FILE_READ_MAX] + f"\n... [truncated, {len(data)} bytes total]"
    return data


@tool
def search_code(pattern: str, path: str = ".") -> str:
    """Search files for a regex pattern (ripgrep if available, else grep).

    Returns matching lines as file:line:text. Use for finding functions,
    routes, secrets patterns, dangerous calls, etc."""
    try:
        p = resolve_in_workspace(path)
    except ValueError as e:
        return str(e)
    excludes = excluded_dirs()
    # Skip noise/self dirs so a search hits the target's code, not PHRAK's own
    # skill files (.phrack), the vcs dir, or vendored deps (node_modules/venv).
    rg_globs = [g for d in excludes for g in ("-g", f"!{d}")]
    grep_excludes = [f"--exclude-dir={d}" for d in excludes]
    candidates = [
        [
            "rg",
            "-n",
            "--no-heading",
            "-S",
            "--hidden",
            *rg_globs,
            "--max-count",
            "200",
            pattern,
            str(p),
        ],
        ["grep", "-rniE", "--max-count=200", *grep_excludes, pattern, str(p)],
    ]
    last = len(candidates) - 1
    for i, cmd in enumerate(candidates):
        # Every candidate but the last is a probe we fall back from, so a missing
        # binary logs as a dim note (rg -> grep) rather than a red failure.
        res = run_cli(cmd, timeout=60, optional=(i < last))
        if res.error:
            continue  # tool not installed / timed out — try the next
        if res.returncode in (0, 1):  # 1 = no matches
            result = res.stdout.strip()
            return result[:FILE_READ_MAX] if result else "(no matches)"
    return "No search tool (rg/grep) available."


def read_only_tools() -> list:
    """The shared read-only toolset most agents want."""
    return [list_dir, read_file, search_code]
