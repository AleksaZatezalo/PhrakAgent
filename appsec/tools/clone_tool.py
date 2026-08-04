"""
Description: Guarded ``git_clone`` tool (Phase 9) — off unless ``enable_git_clone``.
Author: Aleksa Zatezalo
Date Created: 07-30-2026
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..runtime import require_config


@tool
def git_clone(url: str, dest: str = "") -> str:
    """Shallow-clone a git repository into the workspace clones area for analysis.

    Only https:// or git@host:path URLs are accepted (no inline credentials, no
    local paths). The clone is shallow, hooks are disabled, submodules are not
    fetched, and it is size-capped and confined to <workspace>/clones. Returns the
    local path on success. Use this to bring a dependency's source in-tree so the
    read-only file tools can inspect it."""
    from ..clone import clone_repo

    res = clone_repo(require_config(), url, dest)
    return res.message


def git_clone_tools(config) -> list:
    """The git_clone tool iff enabled in config, else an empty list."""
    return [git_clone] if getattr(config, "enable_git_clone", False) else []
