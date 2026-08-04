"""
Description: Curated, agent-scoped skills bundled with PHRAK.
Author: Aleksa Zatezalo
Date Created: 07-29-2026
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

SKILLS_ROOT = Path(__file__).parent / "skills"


@dataclass(frozen=True)
class Skill:
    name: str
    when_to_use: str
    body: str


def _parse(path: Path) -> Skill:
    """Parse a ``---`` frontmatter + markdown-body skill file."""
    text = path.read_text(encoding="utf-8")
    meta: dict = {}
    body = text
    if text.startswith("---"):
        _, _, rest = text.partition("---")
        front, sep, body = rest.partition("---")
        if sep:
            try:
                meta = yaml.safe_load(front) or {}
            except yaml.YAMLError:
                meta = {}
        else:
            body = text
    return Skill(
        name=str(meta.get("name") or path.stem),
        when_to_use=str(meta.get("when_to_use") or "").strip(),
        body=body.strip(),
    )


def for_agent(agent: str) -> list[Skill]:
    """All curated skills for ``agent`` (empty if the agent has none), sorted."""
    d = SKILLS_ROOT / agent
    if not d.is_dir():
        return []
    return sorted(
        (_parse(p) for p in d.glob("*.md")), key=lambda s: s.name
    )


def index(agent: str) -> str:
    """A one-line-per-skill index for injecting into the system prompt."""
    skills = for_agent(agent)
    if not skills:
        return ""
    lines = [f"- {s.name} — {s.when_to_use}" for s in skills]
    return (
        "## Your skills (call load_skill(\"<name>\") to read the full "
        "procedure before you do that part of the work)\n" + "\n".join(lines)
    )


def playbook(agent: str) -> str:
    """Every curated skill for ``agent``, full body inlined.

    Unlike :func:`index` (a one-liner the agent may or may not act on), this
    front-loads the complete procedures so the agent runs ALL the skills it has
    access to on every task, not just the ones it decides to load."""
    skills = for_agent(agent)
    if not skills:
        return ""
    parts = [
        "## Your skills — APPLY EVERY ONE OF THESE during this task",
        "You have the skill procedures below. Work through and apply each one in "
        "turn; do not skip any. They define the methodology you are expected to "
        "follow to completion.",
    ]
    for s in skills:
        head = f"### Skill: {s.name}"
        if s.when_to_use:
            head += f"\n_When to use: {s.when_to_use}_"
        parts.append(f"{head}\n\n{s.body}")
    return "\n\n".join(parts)


def load(agent: str, name: str) -> Optional[Skill]:
    """Return the named skill for ``agent`` (case-insensitive), or None."""
    name = (name or "").strip().lower().removesuffix(".md")
    for s in for_agent(agent):
        if s.name.lower() == name:
            return s
    return None
