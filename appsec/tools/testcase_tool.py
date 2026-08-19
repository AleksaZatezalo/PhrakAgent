"""
Description: The ``report_test_case`` tool — structured, trackable security test cases.
Author: Aleksa Zatezalo
Date Created: 08-18-2026
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..models.testcases import SecurityTestCase, validate_test_case
from ..runtime import active_agent, record_test_case


def _steps(raw: str) -> list[str]:
    """Split authored steps into a list, dropping any numbering the author added.

    Accepts real newlines, ``' | '``, and a *literal* two-character ``\\n`` —
    the last because ``--steps "a\\nb"`` in a shell passes a backslash and an
    'n', and silently keeping that as one step is worse than the vanishingly
    rare case of a step that genuinely wanted those characters.
    """
    import re

    parts: list[str] = []
    for chunk in re.split(r"\n|\\n|\s\|\s", raw or ""):
        s = re.sub(r"^\s*(?:\d+[.)]|[-*])\s*", "", chunk).strip()
        if s:
            parts.append(s)
    return parts


@tool
def report_test_case(
    title: str,
    target: str,
    steps: str,
    expected_result: str,
    severity: str = "medium",
    objective: str = "",
    preconditions: str = "",
    finding_id: str = "",
    threat_ref: str = "",
) -> str:
    """Record ONE security test case as a structured, trackable item (call once
    per distinct test, in addition to writing it into your report).

    These land in the operator's test-case backlog, where they can be marked
    new / in progress / complete and linked to a finding — so author each one as
    a real unit of work, not a restatement of the finding.

    ``target`` must name what is actually under test: an endpoint, a parameter,
    or a ``file:line``. ``steps`` are the numbered actions to perform — separate
    them with newlines (or ' | '). ``expected_result`` is what proves the issue
    present or absent. ``severity`` is critical/high/medium/low/info.

    Set ``finding_id`` (e.g. "FND-ab12cd34ef") when this test verifies a finding
    you reported, or ``threat_ref`` for a threat-model element with no id.
    Returns the test-case id, or a REJECTED message to fix and resubmit."""
    case = SecurityTestCase(
        title=title,
        objective=objective,
        target=target,
        preconditions=preconditions,
        steps=_steps(steps),
        expected_result=expected_result,
        severity=(severity or "").strip().lower() or "medium",
        finding_id=finding_id.strip(),
        threat_ref=threat_ref.strip(),
        status="new",
        source_agent=active_agent(),
    ).ensure_identity()

    errs = validate_test_case(case)
    if errs:
        return (
            "REJECTED (not recorded): "
            + "; ".join(errs)
            + ". Fix these and call report_test_case again."
        )

    if not record_test_case(case):
        return (
            f"NOT RECORDED ({case.id}) — no active run is collecting test cases. "
            "Include it in your written report instead."
        )
    link = case.finding_id or case.threat_ref or "nothing yet"
    return (
        f"RECORDED ({case.id}, severity={case.severity}, verifies {link}). "
        "Continue with the next test case."
    )


def test_case_tools() -> list:
    return [report_test_case]
