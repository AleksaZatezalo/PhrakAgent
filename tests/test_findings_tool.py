"""
Description: The report_finding tool: validation, workspace grounding, and capture.
Author: Aleksa Zatezalo
Date Created: 07-29-2026
"""

from __future__ import annotations

import pytest

from appsec import runtime as rt
from appsec.tools.findings_tool import report_finding


@pytest.fixture
def capture(runtime):
    """Start a run-scoped findings capture bound to the temp workspace."""
    lst = rt.begin_findings()
    yield lst
    rt.take_findings()


def _call(**over):
    args = dict(
        title="SQL injection in get_user",
        category="SQL injection",
        severity="high",
        description="user id concatenated into SQL",
        file="vuln_app.py",
        line=13,  # conftest vuln_app.py has the SQLi around here
        recommendation="use parameterized queries",
        disproof="the query uses a bound parameter",
        cwe="CWE-89",
        confidence=0.8,
    )
    args.update(over)
    return report_finding.invoke(args)


def test_records_grounded_finding(capture):
    out = _call()
    assert out.startswith("RECORDED (")
    assert len(capture) == 1
    f = capture[0]
    assert f.status == "new"
    assert f.cwe_ids == ["CWE-89"]
    assert f.affected_files == ["vuln_app.py"]


def test_downgrades_when_file_missing(capture):
    out = _call(file="does_not_exist.py")
    assert "UNCONFIRMED" in out
    assert capture[0].status == "unconfirmed"
    assert capture[0].confidence <= 0.4


def test_downgrades_on_path_escape(capture):
    out = _call(file="../../etc/passwd")
    assert "UNCONFIRMED" in out
    assert capture[0].status == "unconfirmed"


def test_downgrades_on_out_of_range_line(capture):
    out = _call(line=99999)
    assert "UNCONFIRMED" in out
    assert capture[0].status == "unconfirmed"


def test_rejects_bad_severity_without_recording(capture):
    out = _call(severity="apocalyptic")
    assert out.startswith("REJECTED")
    assert capture == []


def test_taint_path_attached_for_dataflow(capture):
    _call(sink_file="vuln_app.py", sink_line=13, line=11)
    f = capture[0]
    assert len(f.taint_paths) == 1
    assert f.taint_paths[0].completeness == "partial"
    assert f.taint_paths[0].sink.path == "vuln_app.py"


def test_report_appended_to_agent_output(runtime, monkeypatch):
    # An Agent.run should render captured findings into its returned report.
    from appsec.base_agent import Agent, AgentSpec

    spec = AgentSpec("code_review", "d", "sys prompt", tool_factory=lambda: [])

    class _Skills:
        def skills_block(self, q):
            return ""

    agent = Agent.__new__(Agent)  # bypass tool wiring
    agent.spec = spec
    agent.skills = _Skills()

    rt.begin_findings()
    _call()  # record one grounded finding
    out = agent._append_structured_findings("original report body")
    assert "original report body" in out
    assert "## Structured Findings (validated)" in out
    assert "CWE-89" in out
