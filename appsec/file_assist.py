"""Helpers that keep an agent moving when a weak local model stalls.

Two behaviours, extracted from the Agent loop so they're independently testable:

* :func:`workspace_overview` — a listing of the real files in the workspace,
  front-loaded into the first turn so the model reads actual files instead of
  hallucinating names (e.g. asking for a non-existent ``app.py``).
* :func:`maybe_satisfy_file_request` — when the model asks the human to *paste*
  code instead of calling ``read_file``, read the referenced (or, failing that,
  the workspace's) source files itself and pack them for re-feeding.

These operate on a plain list of tools, so they can be unit-tested without an
Agent, an LLM, or the checkpointer.
"""

from __future__ import annotations

import os
import re
from typing import Optional

# Source-ish extensions worth auto-reading when the model asks for code.
_CODE_EXTS = {
    "py", "js", "mjs", "cjs", "ts", "tsx", "jsx", "php", "rb", "go", "java",
    "kt", "c", "cc", "cpp", "h", "hpp", "cs", "rs", "sql", "html", "htm",
    "yaml", "yml", "json", "toml", "ini", "cfg", "conf", "env", "sh", "bash",
    "xml", "tf", "gradle", "pl", "scala", "swift", "vue", "svelte", "erb", "ejs",
}
# Dirs to skip when building a workspace overview (noise / huge / non-source).
_SKIP_DIRS = {
    ".git", "venv", ".venv", "env", "__pycache__", "node_modules", ".mypy_cache",
    ".ruff_cache", ".pytest_cache", "data", ".phrack", ".idea", ".vscode",
    "dist", "build", ".tox", "site-packages",
}
# Prose that means "the model gave up and is asking the user to hand it code"
# instead of reading it with the read_file tool.
_FILE_REQUEST = re.compile(
    r"(please\s+)?(provide|share|paste|give|show|send|upload|attach|supply|"
    r"post)\b[^.\n]{0,60}\b(content|contents|code|file|files|source)\b"
    r"|contents?\s+of\s+[`'\"]?[\w./-]+"
    r"|\bneed\s+(the\s+|to\s+see\s+the\s+)?[\w\s]{0,20}"
    r"(content|contents|code|file|source)\b",
    re.I,
)
# File-path-looking tokens, e.g. `app.py`, src/main.go.
_PATHISH = re.compile(r"[`'\"(\[]?([\w][\w./-]*\.[A-Za-z0-9]{1,6})")

MAX_FILES = 12
BUDGET = 40_000


def find_tool(tools: list, name: str):
    """Return the tool named ``name`` from ``tools``, or None."""
    for t in tools:
        if getattr(t, "name", "") == name:
            return t
    return None


def workspace_files(max_entries: int = 300) -> list[str]:
    """Workspace-relative file paths, skipping noise/huge dirs."""
    from .runtime import require_config

    try:
        root = require_config().paths.workspace
    except Exception:
        return []
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        return []
    files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")
        ]
        rel_dir = os.path.relpath(dirpath, root)
        for fn in sorted(filenames):
            rel = fn if rel_dir == "." else os.path.join(rel_dir, fn)
            files.append(rel)
            if len(files) >= max_entries:
                return files
    return files


def workspace_overview(tools: list) -> str:
    """A listing of real files, so the model reads them (no hallucinating).

    Empty string if the agent has no ``read_file`` tool or the workspace is empty.
    """
    if not find_tool(tools, "read_file"):
        return ""
    files = workspace_files()
    if not files:
        return ""
    listed = "\n".join(f"- {f}" for f in files)
    return (
        "Files that actually exist in the workspace (paths are relative to the "
        "workspace root — read any of them with read_file, and do NOT ask the "
        "user to paste code):\n" + listed
    )


def maybe_satisfy_file_request(tools: list, answer: str) -> Optional[str]:
    """If the model asked the user for file contents, read them itself.

    Returns a message injecting the requested files' contents (so the next round
    can continue), or None if ``answer`` doesn't look like such a request.
    """
    read = find_tool(tools, "read_file")
    if not read or not _FILE_REQUEST.search(answer or ""):
        return None

    named: list[str] = []
    for m in _PATHISH.finditer(answer or ""):
        tok = m.group(1)
        ext = tok.rsplit(".", 1)[-1].lower()
        if ext in _CODE_EXTS and tok not in named:
            named.append(tok)
    workspace_src = [
        f for f in workspace_files()
        if f.rsplit(".", 1)[-1].lower() in _CODE_EXTS
    ]
    # Try the files it named; if none are readable (e.g. it hallucinated
    # "app.py"), fall back to the real workspace source files.
    packed = read_and_pack(read, named) if named else None
    if packed is None:
        packed = read_and_pack(read, workspace_src)
    return packed


def read_and_pack(
    read, paths: list[str], max_files: int = MAX_FILES, budget: int = BUDGET
) -> Optional[str]:
    """Read up to ``max_files`` paths via the read tool and pack them for re-feeding.

    Skips paths the read tool couldn't resolve. Returns None if nothing readable.
    """
    blocks, used = [], 0
    for p in paths[:max_files]:
        try:
            content = read.invoke({"path": p})
        except Exception as e:  # tool raised — skip this path
            content = f"(could not read: {e})"
        content = content if isinstance(content, str) else str(content)
        low = content.lower()
        if (low.startswith("not a file") or low.startswith("not found")
                or content.startswith("Path '")):
            continue
        snippet = content[: max(2000, budget - used)]
        used += len(snippet)
        blocks.append(f"### {p}\n```\n{snippet}\n```")
        if used >= budget:
            break
    if not blocks:
        return None
    return (
        "You asked for file contents — but you can read files yourself with "
        "read_file, so NEVER ask the user to paste code. Here are the relevant "
        "workspace files:\n\n" + "\n\n".join(blocks) +
        "\n\nNow continue the analysis using this code, read any other files you "
        "need with read_file, and produce the COMPLETE final report."
    )
