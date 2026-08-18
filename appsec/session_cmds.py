"""
Description: Pure helpers for the interactive session commands (Phase 9).
Author: Aleksa Zatezalo
Date Created: 07-30-2026
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

_AT_REF = re.compile(r"(?<!\w)@([\w./~-]+)")
_MAX_INLINE = 8_000


def at_ref_names(text: str) -> list[str]:
    """The distinct ``@path`` references in ``text``, in order of appearance."""
    return list(dict.fromkeys(_AT_REF.findall(text or "")))


def _resolve_ref(root: Path, ref: str) -> tuple[Optional[Path], str]:
    """Resolve one ``@ref`` against the workspace root.

    Returns ``(path, "")`` for a readable file inside the workspace, else
    ``(None, reason)``. The reason is short enough to both show the user and
    leave inline as a ``[note]`` for the model.
    """
    try:
        p = (root / ref).resolve()
    except (OSError, ValueError):
        return None, "invalid path"
    if root != p and root not in p.parents:
        return None, "outside workspace — not inlined"
    if not p.is_file():
        return None, "not a file"
    return p, ""


def expand_at_refs(text: str, workspace: Path) -> str:
    """Inline the contents of any ``@relative/path`` reference in ``text``.

    Only files inside the workspace are inlined (path traversal is refused); a
    missing/oversize/outside file is left as a short ``[note]`` so the model
    still sees the intent. Returns ``text`` unchanged if it has no refs."""
    refs = at_ref_names(text)
    if not refs:
        return text
    root = Path(workspace).resolve()
    blocks = []
    for ref in refs:
        p, problem = _resolve_ref(root, ref)
        if problem:
            blocks.append(f"[@{ref}: {problem}]")
            continue
        try:
            data = p.read_text(errors="replace")
        except OSError:
            blocks.append(f"[@{ref}: unreadable]")
            continue
        if len(data) > _MAX_INLINE:
            data = data[:_MAX_INLINE] + f"\n... [truncated, {len(data)} bytes]"
        blocks.append(f"--- {ref} ---\n{data}")
    if not blocks:
        return text
    return text + "\n\nReferenced files:\n" + "\n\n".join(blocks)


def describe_at_refs(text: str, workspace: Path) -> list[str]:
    """One short status line per ``@ref`` — what got attached and what didn't.

    The chat loop prints these before the model answers, so a typo'd path or a
    refused traversal is visible immediately rather than only as a confused
    reply a minute later.
    """
    root = Path(workspace).resolve()
    out: list[str] = []
    for ref in at_ref_names(text):
        p, problem = _resolve_ref(root, ref)
        if problem:
            out.append(f"@{ref} ({problem})")
            continue
        try:
            size = p.stat().st_size
        except OSError:
            out.append(f"@{ref} (unreadable)")
            continue
        trunc = ", truncated" if size > _MAX_INLINE else ""
        out.append(f"@{ref} ({size:,} B{trunc})")
    return out


def list_tools_grouped(app) -> str:
    """A grouped catalog of every tool each agent exposes (for ``/tools``)."""
    lines = ["Tools by agent:"]
    for spec in app.registry.specs():
        try:
            names = sorted({t.name for t in spec.tool_factory()})
        except Exception:
            names = []
        lines.append(f"  {spec.name}: {', '.join(names) or '(none)'}")
    return "\n".join(lines)


def tool_detail(app, name: str) -> str:
    """Show one tool's description + signature (for ``/tool <name>``)."""
    for spec in app.registry.specs():
        try:
            tools = spec.tool_factory()
        except Exception:
            continue
        for t in tools:
            if t.name == name:
                args = ", ".join((getattr(t, "args", None) or {}).keys())
                return (
                    f"{t.name}({args})\n  agent: {spec.name}\n\n"
                    f"{(t.description or '').strip()}"
                )
    return f"No tool named '{name}'. Try /tools to list them."


# ------------------------------------------------------------ findings triage
# Agents write every finding into the durable store (see base_agent); these are
# the read/triage side of that store — the commands that let a human actually
# work the backlog instead of re-reading a report each run.
FINDINGS_USAGE = (
    "usage: /findings [--severity critical|high|medium|low|info] "
    "[--status <status>] [--resurfaced]"
)


def _store(app):
    from .store import FindingStore

    return FindingStore(app.config)


def parse_findings_flags(rest: str) -> tuple[dict, str]:
    """Parse ``/findings`` filter flags into ``findings_list`` kwargs.

    Only checks the *shape* of the flags; the filter values are validated by
    :func:`findings_list`, so the ``phrak findings`` subcommand — which gets its
    values from argparse rather than from here — is validated identically.
    Returns ``(kwargs, error_message)``.
    """
    toks = (rest or "").split()
    out = {"severity": "", "status": "", "resurfaced": False}
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok in ("--severity", "-s") and i + 1 < len(toks):
            out["severity"] = toks[i + 1]
            i += 2
        elif tok == "--status" and i + 1 < len(toks):
            out["status"] = toks[i + 1]
            i += 2
        elif tok == "--resurfaced":
            out["resurfaced"] = True
            i += 1
        else:
            return {}, f"unknown or incomplete option '{tok}'.\n{FINDINGS_USAGE}"
    return out, ""


def findings_list(
    app, severity: str = "", status: str = "", resurfaced: bool = False
) -> str:
    """Render the durable finding store, optionally filtered.

    An unknown severity/status is an error rather than an empty list — silently
    matching nothing reads as "you have no high-severity findings", which is the
    opposite of what a typo'd filter should tell you.
    """
    from .models.findings import SEVERITIES, STATUSES
    from .store import render_finding_list

    severity = (severity or "").strip().lower()
    status = (status or "").strip().lower().replace("-", "_")
    if severity and severity not in SEVERITIES:
        return f"Unknown severity '{severity}' (of {', '.join(SEVERITIES)})."
    if status and status not in STATUSES:
        return f"Unknown status '{status}' (of {', '.join(STATUSES)})."

    records = _store(app).list()
    kept = []
    for r in records:
        f = r.as_finding()
        if severity and f.severity.lower() != severity:
            continue
        if status and f.effective_status().lower() != status:
            continue
        if resurfaced and not r.resurfaced:
            continue
        kept.append(r)
    # render_finding_list's empty message assumes an empty *store*; say something
    # truer when a filter is what emptied the list.
    if records and not kept:
        return f"No findings match that filter ({len(records)} recorded overall)."
    return render_finding_list(kept)


def finding_detail(app, ident: str) -> str:
    """Full detail for one finding, including its history and reviewer notes."""
    from .store import render_finding_detail

    ident = (ident or "").strip()
    if not ident:
        return "usage: /finding <id>"
    rec = _store(app).get(ident)
    if rec is None:
        return f"No finding matching '{ident}'. Try /findings to list them."
    return render_finding_detail(rec)


def triage_finding(app, rest: str) -> str:
    """Record a human verdict on a finding: ``/triage <id> <status> [note]``."""
    from .models.findings import STATUSES

    toks = (rest or "").split(maxsplit=2)
    statuses = ", ".join(STATUSES)
    if len(toks) < 2:
        return f"usage: /triage <id> <status> [note]\n  statuses: {statuses}"
    ident, status = toks[0], toks[1].lower().replace("-", "_")
    if status not in STATUSES:
        return f"Unknown status '{status}'.\n  statuses: {statuses}"
    note = toks[2] if len(toks) > 2 else ""
    _, message = _store(app).set_status(ident, status, actor="human", note=note)
    return message


def note_finding(app, rest: str) -> str:
    """Attach a reviewer note to a finding: ``/note <id> <text>``."""
    toks = (rest or "").split(maxsplit=1)
    if len(toks) < 2:
        return "usage: /note <id> <text>"
    _, message = _store(app).add_note(toks[0], toks[1])
    return message


def findings_json(app) -> str:
    """The whole store as JSON — for piping into a tracker or CI gate."""
    import json

    return json.dumps([r.to_dict() for r in _store(app).list()], indent=2, default=str)


def copy_to_clipboard(text: str) -> bool:
    """Best-effort clipboard copy via a platform tool; False if none available."""
    if not text:
        return False
    for cmd in (
        ["pbcopy"],
        ["wl-copy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
    ):
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode(), check=True, timeout=5)
                return True
            except (subprocess.SubprocessError, OSError):
                continue
    return False
