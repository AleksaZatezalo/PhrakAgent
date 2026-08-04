"""Deterministic repo cloning (Phase 9) — ``phrak clone`` / ``/clone``.

Shallow-clones a remote repository into a sandboxed clones area under the
workspace, so a target can be pulled in for analysis with no model in the loop.
Guardrails (all enforced here, not left to the caller):

* HTTPS/SSH URLs only — no ``file://`` or local-path clones, no inline creds.
* Shallow + single-branch by default (``--depth 1``).
* git hooks disabled on clone (``core.hooksPath=/dev/null``); submodules are
  NOT fetched unless ``recurse=True``.
* a wall-clock timeout and a post-clone size cap.
* the clone lands strictly inside ``<workspace>/<clones_dir>`` — a destination
  that escapes it is refused.

Cloned code is treated like any other workspace target: the same read-only tools
and loopback/subprocess sandboxes apply.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from .tools.common import run_cli

# Accept https:// and scp-style / ssh:// git remotes; reject everything else
# (notably file:// and bare local paths, and any URL carrying inline creds).
_HTTPS_RE = re.compile(r"^https://[\w.-]+(:\d+)?/[\w./~-]+?(\.git)?$")
_SSH_RE = re.compile(r"^(ssh://)?git@[\w.-]+:[\w./~-]+?(\.git)?$")

DEFAULT_TIMEOUT = 120
DEFAULT_MAX_MB = 500


@dataclass
class CloneResult:
    ok: bool
    dest: str = ""
    message: str = ""


def _repo_name(url: str) -> str:
    tail = url.rstrip("/").split("/")[-1].split(":")[-1]
    tail = tail[:-4] if tail.endswith(".git") else tail
    return re.sub(r"[^A-Za-z0-9._-]", "_", tail) or "repo"


def valid_git_url(url: str) -> bool:
    url = (url or "").strip()
    if "@" in url and url.startswith(("http://", "https://")):
        return False  # inline creds in an http(s) URL — refuse (would get logged)
    return bool(_HTTPS_RE.match(url) or _SSH_RE.match(url))


def _dir_size_mb(path: Path) -> float:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            continue
    return total / (1024 * 1024)


def clone_repo(
    config,
    url: str,
    dest: str = "",
    *,
    depth: int = 1,
    recurse: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    max_mb: int = DEFAULT_MAX_MB,
) -> CloneResult:
    """Shallow-clone ``url`` into ``<workspace>/<clones_dir>/<dest>``.

    Returns a :class:`CloneResult`; never raises for expected failures (bad URL,
    git missing, escape attempt, oversize, timeout)."""
    url = (url or "").strip()
    if not valid_git_url(url):
        return CloneResult(False, message=(
            f"[REFUSED] '{url}' is not an accepted git URL. Use https:// or "
            "git@host:path (no inline credentials, no file:// / local paths)."))

    clones_root = config.clones_dir()
    clones_root.mkdir(parents=True, exist_ok=True)
    target = (clones_root / (dest or _repo_name(url))).resolve()
    if clones_root.resolve() != target and clones_root.resolve() not in target.parents:
        return CloneResult(False, message=(
            f"[REFUSED] destination escapes the clones area {clones_root}."))
    if target.exists():
        return CloneResult(False, message=(
            f"[REFUSED] destination already exists: {target}. Remove it or pick "
            "another name."))

    cmd = [
        "git", "-c", "core.hooksPath=/dev/null",  # never run hooks from a clone
        "clone", "--depth", str(max(1, depth)), "--single-branch",
    ]
    if recurse:
        cmd += ["--recurse-submodules", "--shallow-submodules"]
    cmd += [url, str(target)]

    res = run_cli(cmd, timeout=timeout)
    if res.error:
        return CloneResult(False, message=f"[ERROR] clone failed: {res.error}")
    if res.returncode != 0:
        return CloneResult(False, message=(
            f"[ERROR] git clone exited {res.returncode}: "
            f"{(res.stderr or res.stdout).strip()[:400]}"))

    size = _dir_size_mb(target)
    if size > max_mb:
        shutil.rmtree(target, ignore_errors=True)
        return CloneResult(False, message=(
            f"[REFUSED] clone is {size:.0f} MB, over the {max_mb} MB cap; removed. "
            "Raise --max-mb if this is expected."))
    return CloneResult(True, dest=str(target),
                       message=f"Cloned into {target} ({size:.1f} MB, shallow).")
