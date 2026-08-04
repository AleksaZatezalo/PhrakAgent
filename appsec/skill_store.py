"""
Description: Learned-skills store — agent-authored procedures saved as markdown files.
Author: Aleksa Zatezalo
Date Created: 08-01-2026
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from .config import Config

# User-level PHRAK home — skills written here with ``--global`` become part of
# the agent itself and apply to every subsequent workspace.
GLOBAL_PHRAK_DIR = Path.home() / ".phrak"


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:60] or "skill"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class SkillStore:
    """Read/write learned skills as markdown files.

    Skills resolve from two scopes: the per-workspace ``paths.skills_dir`` and the
    user-level ``~/.phrak/skills`` (global). A workspace skill overrides a global
    one of the same name; both are visible to :meth:`list_skills`.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        config.ensure_dirs()
        self.skills_dir = config.skills_dir()
        self.global_dir = GLOBAL_PHRAK_DIR / "skills"

    def _dir_for(self, scope: str) -> Path:
        d = self.global_dir if scope == "global" else self.skills_dir
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ---------------------------------------------------------------- read
    def list_skills(self) -> list[str]:
        names = {p.stem for p in self.skills_dir.glob("*.md")}
        if self.global_dir.is_dir():
            names |= {p.stem for p in self.global_dir.glob("*.md")}
        return sorted(names)

    def read_skill(self, name: str) -> str:
        # workspace overrides global
        for base in (self.skills_dir, self.global_dir):
            p = base / f"{_slug(name)}.md"
            if p.exists():
                return p.read_text()
        return ""

    def relevant_skills(self, query: str, k: int = 2) -> list[str]:
        """The ``k`` skills whose text overlaps ``query`` most (lexical, cheap)."""
        names = self.list_skills()
        if not names:
            return []
        q_words = set(re.findall(r"[a-z0-9]+", query.lower()))
        scored: list[tuple[int, str]] = []
        for n in names:
            text = self.read_skill(n)
            words = set(re.findall(r"[a-z0-9]+", text.lower()))
            scored.append((len(q_words & words), text))
        scored.sort(key=lambda t: t[0], reverse=True)
        return [text for score, text in scored[:k] if score > 0]

    def skills_block(self, query: str) -> str:
        """Formatted relevant-skills section for injecting into a system prompt."""
        skills = self.relevant_skills(query)
        if not skills:
            return ""
        return "## Applicable skills (reusable procedures)\n" + "\n\n".join(skills)

    # --------------------------------------------------------------- write
    def write_skill(self, name: str, when_to_use: str, steps: list[str],
                    scope: str = "workspace") -> str:
        name = _slug(name)
        body = (
            f"# {name}\n\n"
            f"**When to use:** {when_to_use}\n\n"
            f"_Created {_now()}_\n\n"
            "## Steps\n"
            + "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))
            + "\n"
        )
        path = self._dir_for(scope) / f"{name}.md"
        path.write_text(body)
        return str(path)

    def add_skill(self, name: str, body: str, scope: str = "workspace") -> str:
        """Write a raw-markdown skill (from a file / stdin) at the given scope."""
        name = _slug(name)
        if not body.lstrip().startswith("#"):
            body = f"# {name}\n\n_Added {_now()}_\n\n{body}"
        path = self._dir_for(scope) / f"{name}.md"
        path.write_text(body if body.endswith("\n") else body + "\n")
        return str(path)

    def remove_skill(self, name: str, scope: str = "workspace") -> bool:
        """Delete a skill at the given scope. Returns True if a file was removed."""
        path = self._dir_for(scope) / f"{_slug(name)}.md"
        if path.exists():
            path.unlink()
            return True
        return False

    def skill_scopes(self, name: str) -> list[str]:
        """Which scopes ('workspace' / 'global') currently define ``name``."""
        out = []
        if (self.skills_dir / f"{_slug(name)}.md").exists():
            out.append("workspace")
        if (self.global_dir / f"{_slug(name)}.md").exists():
            out.append("global")
        return out
