"""Pure helpers for the interactive session commands (Phase 9).

Kept dependency-light and side-effect-free where possible so they're unit
testable: inline ``@path`` expansion, the ``/tools`` + ``/tool`` catalog, and the
``/copy`` clipboard shim. The stateful bits (rebuilding the chat graph, history
search) live on :class:`~appsec.chat.ChatSession` / in the REPL loop.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

_AT_REF = re.compile(r"(?<!\w)@([\w./~-]+)")
_MAX_INLINE = 8_000


def expand_at_refs(text: str, workspace: Path) -> str:
    """Inline the contents of any ``@relative/path`` reference in ``text``.

    Only files inside the workspace are inlined (path traversal is refused); a
    missing/oversize/outside file is left as a short ``[note]`` so the model
    still sees the intent. Returns ``text`` unchanged if it has no refs."""
    refs = _AT_REF.findall(text or "")
    if not refs:
        return text
    root = Path(workspace).resolve()
    blocks = []
    for ref in dict.fromkeys(refs):
        try:
            p = (root / ref).resolve()
        except (OSError, ValueError):
            blocks.append(f"[@{ref}: invalid path]")
            continue
        if root != p and root not in p.parents:
            blocks.append(f"[@{ref}: outside workspace — not inlined]")
            continue
        if not p.is_file():
            blocks.append(f"[@{ref}: not a file]")
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
                return (f"{t.name}({args})\n  agent: {spec.name}\n\n"
                        f"{(t.description or '').strip()}")
    return f"No tool named '{name}'. Try /tools to list them."


def copy_to_clipboard(text: str) -> bool:
    """Best-effort clipboard copy via a platform tool; False if none available."""
    if not text:
        return False
    for cmd in (["pbcopy"], ["wl-copy"], ["xclip", "-selection", "clipboard"],
                ["xsel", "--clipboard", "--input"]):
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode(), check=True, timeout=5)
                return True
            except (subprocess.SubprocessError, OSError):
                continue
    return False
