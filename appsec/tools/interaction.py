"""
Description: Tools that let an agent pause to talk to the human without ending its run.
Author: Aleksa Zatezalo
Date Created: 08-01-2026
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..runtime import active_agent


@tool
def ask_user(question: str) -> str:
    """Ask the human operator a clarifying question and get their answer.

    Use ONLY when you genuinely cannot proceed without input (ambiguous scope,
    missing credentials/paths, a judgment call). Otherwise keep working. Returns
    the user's answer as a string."""
    from ..ui import styled_question

    return styled_question(active_agent(), question)


@tool
def request_permission(action: str, detail: str = "") -> str:
    """Ask the human for permission before a sensitive or far-reaching action.

    Returns 'GRANTED' or 'DENIED: <reason>'. Respect the answer."""
    from ..ui import styled_permission

    return styled_permission(active_agent(), action, detail)


def interaction_tools() -> list:
    return [ask_user, request_permission]
