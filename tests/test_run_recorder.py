"""
Description: RunRecorder — capture, prompt building, persistence, prose fallback.
Author: Aleksa Zatezalo
Date Created: 09-03-2026
"""

from __future__ import annotations

from types import SimpleNamespace

from appsec.run_recorder import RunRecorder


def _tools(*names):
    return [SimpleNamespace(name=n) for n in names]


def _rec(config=None, tools=(), notes=None):
    sink = notes if notes is not None else []
    return RunRecorder("code_review", config, list(tools), sink.append)


# --------------------------------------------------------------- capability
def test_tool_names_filters_to_capture_tools():
    rec = _rec(tools=_tools("read_file", "report_finding", "report_test_case"))
    assert rec.tool_names() == ["report_finding", "report_test_case"]
    assert rec.can_record() is True


def test_no_capture_tools_means_cannot_record():
    rec = _rec(tools=_tools("read_file", "search_code"))
    assert rec.tool_names() == []
    assert rec.can_record() is False


# ------------------------------------------------------------ prompt builders
def test_reminder_lists_tools_or_is_empty():
    assert _rec(tools=_tools("read_file")).reminder() == ""
    reminder = _rec(tools=_tools("report_finding")).reminder()
    assert "report_finding" in reminder and "not" in reminder and "recorded" in reminder


def test_writeup_prompt_none_without_capture_tools():
    assert _rec(tools=_tools("read_file")).writeup_prompt() is None


def test_writeup_prompt_lists_only_the_agents_tools():
    p = _rec(tools=_tools("read_file", "report_test_case")).writeup_prompt()
    assert p is not None
    assert "report_test_case" in p and "report_finding" not in p
    assert "RECORD" in p


def test_transcription_prompt_none_when_nothing_to_do(runtime):
    from appsec.runtime import begin_findings, record_finding

    # no capture tools -> None
    assert _rec(tools=_tools("read_file")).transcription_prompt("a report") is None
    # no prose -> None
    begin_findings()
    assert _rec(tools=_tools("report_finding")).transcription_prompt("  ") is None
    # already recorded -> None
    record_finding(_finding())
    assert _rec(tools=_tools("report_finding")).transcription_prompt("prose") is None


def test_transcription_prompt_embeds_and_truncates(runtime):
    from appsec.runtime import begin_findings

    begin_findings()  # empty collector -> nothing_recorded() is True
    rec = _rec(config=runtime, tools=_tools("report_finding"))
    long_report = "X" * 500_000
    p = rec.transcription_prompt(long_report)
    assert p is not None
    assert "--- REPORT ---" in p
    assert "truncated for the recording pass" in p
    assert len(p) < len(long_report)  # capped to the model's budget


# --------------------------------------------------------- append + persist
def _finding():
    from appsec.models.findings import SecurityFinding

    return SecurityFinding(
        title="SQLi in /user",
        category="a03-injection",
        severity="high",
        description="tainted id reaches the query",
    ).ensure_identity()


def test_append_findings_renders_and_persists(runtime):
    from appsec.runtime import begin_findings, record_finding
    from appsec.store import FindingStore

    notes: list[str] = []
    rec = _rec(config=runtime, tools=_tools("report_finding"), notes=notes)
    rec.run_id = "run-abc"
    begin_findings()
    record_finding(_finding())
    out = rec.append_findings("PROSE BODY")

    assert "PROSE BODY" in out
    assert "## Structured Findings (validated)" in out
    assert "SQLi in /user" in out
    # persisted under the run id
    stored = FindingStore(runtime).list()
    assert len(stored) == 1
    assert stored[0].runs[0]["run_id"] == "run-abc"
    assert any("recorded 1 structured finding" in n for n in notes)


def test_append_findings_warns_when_capable_but_empty(runtime):
    from appsec.runtime import begin_findings

    notes: list[str] = []
    rec = _rec(config=runtime, tools=_tools("report_finding"), notes=notes)
    begin_findings()
    out = rec.append_findings("body")
    assert out == "body"  # unchanged
    assert any("no structured findings recorded" in n for n in notes)


def test_append_findings_silent_when_agent_cannot_record(runtime):
    from appsec.runtime import begin_findings

    notes: list[str] = []
    rec = _rec(config=runtime, tools=_tools("read_file"), notes=notes)
    begin_findings()
    assert rec.append_findings("body") == "body"
    assert notes == []


def test_persist_failure_is_reported_not_raised():
    # config=None -> FindingStore(None) blows up inside the best-effort guard.
    from appsec.runtime import begin_findings, record_finding

    notes: list[str] = []
    begin_findings()
    record_finding(_finding())
    rec = _rec(config=None, tools=_tools("report_finding"), notes=notes)
    out = rec.append_findings("body")  # must not raise
    assert "## Structured Findings (validated)" in out  # still rendered
    assert any("could not write finding history" in n for n in notes)


# --------------------------------------------------------- prose fallback
def test_record_from_prose_populates_collectors(runtime):
    from appsec.runtime import begin_findings, peek_findings

    begin_findings()
    rec = _rec(config=runtime, tools=_tools("report_finding"))
    report = (
        "Title: SQL Injection in login\n"
        "Category: a03-injection\n"
        "Severity: High\n"
        "Description: Unsanitized username reaches the query.\n"
        "File: vuln_app.py\n"
        "Line: 11\n"
    )
    rec.record_from_prose(report)
    assert len(peek_findings()) == 1
