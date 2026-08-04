"""The ``load_skill`` tool — lets an agent read one of its curated skills.

The agent sees only a one-line index of its skills in the system prompt (cheap);
this tool returns the full procedure for a named skill on demand, scoped to the
currently-active agent so one specialist can't load another's playbook.
"""

from __future__ import annotations

from langchain_core.tools import tool

from .. import skill_library
from ..runtime import active_agent


@tool
def load_skill(name: str) -> str:
    """Load the full procedure for one of YOUR skills by name.

    Call this before performing the part of the task the skill covers (its name
    and one-line purpose are listed under 'Your skills' in your instructions).
    Returns the skill's step-by-step guidance."""
    agent = active_agent()
    skill = skill_library.load(agent, name)
    if skill:
        return skill.body
    available = [s.name for s in skill_library.for_agent(agent)]
    if not available:
        return f"You have no curated skills to load (agent '{agent}')."
    return (
        f"No skill named '{name}' for {agent}. Available: "
        f"{', '.join(available)}."
    )


def skill_tools() -> list:
    return [load_skill]
