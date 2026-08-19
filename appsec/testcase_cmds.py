"""
Description: Non-agentic test-case backlog commands (list, triage, link, add by hand).
Author: Aleksa Zatezalo
Date Created: 08-18-2026

The ``test_case`` agent authors test cases; everything in this module is the
operator's side of that backlog and involves no model at any point. Statuses,
results, notes, finding links, and hand-written test cases are exactly what the
user typed.
"""

from __future__ import annotations

from typing import Optional

from .models.testcases import (
    TEST_RESULTS,
    TEST_STATUSES,
    SecurityTestCase,
    normalize_result,
    normalize_status,
    validate_test_case,
)

TESTCASES_USAGE = (
    "usage: /testcases [--status new|in_progress|complete] "
    "[--severity critical|high|medium|low|info] [--finding <id>] [--unlinked]"
)

_STATUS_LIST = ", ".join(TEST_STATUSES)
_RESULT_LIST = ", ".join(r for r in TEST_RESULTS if r)


def _store(app):
    from .store import TestCaseStore

    return TestCaseStore(app.config)


# --------------------------------------------------------------------- listing
def parse_testcase_flags(rest: str) -> tuple[dict, str]:
    """Parse ``/testcases`` filter flags. Returns ``(kwargs, error_message)``.

    Shape only — values are validated by :func:`test_cases_list`, so the
    ``phrak testcases`` subcommand is validated identically.
    """
    toks = (rest or "").split()
    out = {"status": "", "severity": "", "finding_id": "", "unlinked": False}
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok == "--status" and i + 1 < len(toks):
            out["status"] = toks[i + 1]
            i += 2
        elif tok in ("--severity", "-s") and i + 1 < len(toks):
            out["severity"] = toks[i + 1]
            i += 2
        elif tok in ("--finding", "-f") and i + 1 < len(toks):
            out["finding_id"] = toks[i + 1]
            i += 2
        elif tok == "--unlinked":
            out["unlinked"] = True
            i += 1
        else:
            return {}, f"unknown or incomplete option '{tok}'.\n{TESTCASES_USAGE}"
    return out, ""


def test_cases_list(
    app,
    status: str = "",
    severity: str = "",
    finding_id: str = "",
    unlinked: bool = False,
) -> str:
    """Render the test-case backlog, optionally filtered."""
    from .models.findings import SEVERITIES
    from .store import render_test_case_list

    severity = (severity or "").strip().lower()
    if severity and severity not in SEVERITIES:
        return f"Unknown severity '{severity}' (of {', '.join(SEVERITIES)})."
    if status:
        normalized = normalize_status(status)
        if not normalized:
            return f"Unknown status '{status}' (of {_STATUS_LIST})."
        status = normalized

    cases = _store(app).list()
    kept = []
    for tc in cases:
        if status and tc.status != status:
            continue
        if severity and tc.severity.lower() != severity:
            continue
        if finding_id and tc.finding_id.lower() != finding_id.strip().lower():
            continue
        if unlinked and (tc.finding_id or tc.threat_ref):
            continue
        kept.append(tc)
    if cases and not kept:
        return f"No test cases match that filter ({len(cases)} recorded overall)."
    return render_test_case_list(kept)


def test_case_detail(app, ident: str) -> str:
    """Full detail for one test case."""
    from .store import render_test_case_detail

    ident = (ident or "").strip()
    if not ident:
        return "usage: /testcase <id>"
    tc = _store(app).get(ident)
    if tc is None:
        return f"No test case matching '{ident}'. Try /testcases to list them."
    return render_test_case_detail(tc)


def test_cases_json(app) -> str:
    """The whole backlog as JSON — for a tracker import or a CI gate."""
    import json

    return json.dumps([t.to_dict() for t in _store(app).list()], indent=2, default=str)


# -------------------------------------------------------------------- progress
def set_test_case_status(app, rest: str) -> str:
    """``/testcase-status <id> <new|in_progress|complete> [pass|fail|blocked|...]``."""
    toks = (rest or "").split()
    if len(toks) < 2:
        return (
            f"usage: /testcase-status <id> <status> [result]\n"
            f"  statuses: {_STATUS_LIST}\n  results: {_RESULT_LIST}"
        )
    ident, raw_status = toks[0], toks[1]
    status = normalize_status(raw_status)
    if not status:
        return f"Unknown status '{raw_status}'.\n  statuses: {_STATUS_LIST}"
    result = ""
    if len(toks) > 2:
        result = normalize_result(toks[2])
        if result == "!":
            return f"Unknown result '{toks[2]}'.\n  results: {_RESULT_LIST}"
    _, message = _store(app).set_status(ident, status, result)
    return message


def link_test_case(app, rest: str) -> str:
    """``/testcase-link <id> <FND-...|none>`` — tie a test to the finding it verifies."""
    toks = (rest or "").split()
    if len(toks) < 2:
        return "usage: /testcase-link <testcase-id> <finding-id|none>"
    ident, finding_id = toks[0], toks[1].strip()
    if finding_id.lower() in ("none", "-", "clear"):
        _, message = _store(app).link_finding(ident, "")
        return message

    # Resolve the finding first: a link to an id that doesn't exist is a typo
    # the operator wants to hear about now, not when they read the report.
    from .store import FindingStore

    record = FindingStore(app.config).get(finding_id)
    if record is None:
        return (
            f"No finding matching '{finding_id}'. Run /findings to list them, "
            "or use 'none' to clear the link."
        )
    _, message = _store(app).link_finding(ident, record.id)
    if message.startswith("no test case"):
        return message
    return f"{message} ({record.as_finding().title[:60]})"


def note_test_case(app, rest: str) -> str:
    """``/testcase-note <id> <text>`` — record what happened when you ran it."""
    toks = (rest or "").split(maxsplit=1)
    if len(toks) < 2:
        return "usage: /testcase-note <id> <text>"
    _, message = _store(app).add_note(toks[0], toks[1])
    return message


# ----------------------------------------------------- manual (non-agentic) add
TESTCASE_FIELDS = [
    # (attribute, prompt, required)
    ("title", "Title", True),
    ("target", "Target (endpoint / parameter / file:line)", True),
    ("steps", "Steps (one per line, blank line to finish)", True),
    ("expected_result", "Expected result — what proves it present or absent", True),
    ("severity", "Severity [critical/high/medium/low/info]", False),
    ("objective", "Objective", False),
    ("preconditions", "Preconditions", False),
    ("finding_id", "Verifies finding id (blank for none)", False),
]


def prompt_for_test_case(ask=input) -> Optional[dict]:
    """Collect a test case's fields interactively. None if the user aborts.

    ``ask`` is injected so the flow is testable without a terminal. The steps
    field reads repeatedly until a blank line, since a test case is mostly steps.
    """
    values: dict = {}
    for attr, label, required in TESTCASE_FIELDS:
        if attr == "steps":
            steps: list[str] = []
            print(f"  {label}:")
            while True:
                try:
                    line = (ask(f"    {len(steps) + 1}. ") or "").strip()
                except (EOFError, KeyboardInterrupt):
                    return None
                if not line:
                    if steps:
                        break
                    print("    at least one step is required.")
                    continue
                steps.append(line)
            values["steps"] = "\n".join(steps)
            continue
        suffix = "" if required else " (optional)"
        while True:
            try:
                raw = (ask(f"  {label}{suffix}: ") or "").strip()
            except (EOFError, KeyboardInterrupt):
                return None
            if raw or not required:
                values[attr] = raw
                break
            print("    required — enter a value, or Ctrl-C to cancel.")
    return values


def add_manual_test_case(
    app,
    title: str,
    target: str,
    steps: str,
    expected_result: str,
    severity: str = "medium",
    objective: str = "",
    preconditions: str = "",
    finding_id: str = "",
) -> str:
    """Add a hand-written test case to the backlog. Returns a result message.

    The id is derived from title + target, so the same test written twice
    collapses onto one backlog entry instead of quietly duplicating.
    """
    from .models.findings import SEVERITIES
    from .tools.testcase_tool import _steps as split_steps

    severity = (severity or "").strip().lower() or "medium"
    if severity not in SEVERITIES:
        return f"Unknown severity '{severity}' (of {', '.join(SEVERITIES)})."

    finding_id = (finding_id or "").strip()
    if finding_id:
        from .store import FindingStore

        record = FindingStore(app.config).get(finding_id)
        if record is None:
            return (
                f"No finding matching '{finding_id}'. Add the test case without "
                "a link, then attach one with /testcase-link."
            )
        finding_id = record.id

    case = SecurityTestCase(
        title=title.strip(),
        objective=objective.strip(),
        target=target.strip(),
        preconditions=preconditions.strip(),
        steps=split_steps(steps),
        expected_result=expected_result.strip(),
        severity=severity,
        finding_id=finding_id,
        status="new",
        source_agent="",  # empty marks it as hand-written
    ).ensure_identity()

    errs = validate_test_case(case)
    if errs:
        return "Not added: " + "; ".join(errs) + "."
    _, message = _store(app).add(case)
    return message
