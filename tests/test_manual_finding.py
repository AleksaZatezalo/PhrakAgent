"""
Description: Hand-entered verified findings (non-agentic) — /finding-add.
Author: Aleksa Zatezalo
Date Created: 08-18-2026
"""

from __future__ import annotations

from types import SimpleNamespace

from appsec.session_cmds import add_manual_finding, prompt_for_finding
from appsec.store import FindingStore


def _app(config):
    return SimpleNamespace(config=config)


def _add(config, **over):
    fields = dict(
        title="Auth bypass on /admin",
        category="broken access control",
        severity="critical",
        file="vuln_app.py",
        line=10,
        description="no session check before rendering the admin page",
    )
    fields.update(over)
    return add_manual_finding(_app(config), **fields)


# ------------------------------------------------------------------ recording
def test_manual_finding_gets_a_generated_id(config, workspace):
    out = _add(config)
    assert "Recorded FND-" in out
    records = FindingStore(config).list()
    assert len(records) == 1
    assert records[0].id.startswith("FND-")
    assert records[0].as_finding().title == "Auth bypass on /admin"


def test_manual_finding_is_recorded_as_human_confirmed(config, workspace):
    """It's a finding *you verified* — the human track carries that verdict."""
    _add(config)
    f = FindingStore(config).list()[0].as_finding()
    assert f.human_status == "confirmed"
    assert f.effective_status() == "confirmed"
    assert f.status == "new"  # the agent track is not forged on its behalf
    assert f.source_agent == "human"
    assert f.source_tools == ["manual"]


def test_manual_finding_survives_a_later_agent_run(config, workspace):
    """A human verdict outranks whatever an agent later says about the same code."""
    from appsec.models.findings import FindingEvidence, SecurityFinding

    _add(config)
    fingerprint = FindingStore(config).list()[0].fingerprint

    # the same issue, re-observed by an agent that is less sure about it
    agent_view = SecurityFinding(
        title="Auth bypass on /admin",
        category="broken access control",
        severity="critical",
        confidence=0.3,
        status="unconfirmed",
        affected_files=["vuln_app.py"],
        evidence=[FindingEvidence(path="vuln_app.py", start_line=10, reason="maybe")],
        source_agent="code_review",
    ).ensure_identity()
    assert agent_view.fingerprint == fingerprint  # same issue, same identity
    FindingStore(config).upsert([agent_view], run_id="r2")

    f = FindingStore(config).list()[0].as_finding()
    assert f.human_status == "confirmed"
    assert f.effective_status() == "confirmed"


def test_re_adding_the_same_finding_updates_one_record(config, workspace):
    _add(config)
    _add(config, description="restated")
    assert len(FindingStore(config).list()) == 1


def test_optional_fields_are_carried_through(config, workspace):
    _add(config, cwe="CWE-284, CWE-862", owasp="A01:2021", disproof="a session check")
    f = FindingStore(config).list()[0].as_finding()
    assert f.cwe_ids == ["CWE-284", "CWE-862"]
    assert f.owasp_categories == ["A01:2021"]
    assert f.disproof == "a session check"


def test_end_line_defaults_to_the_start_line(config, workspace):
    _add(config)
    ev = FindingStore(config).list()[0].as_finding().evidence[0]
    assert ev.start_line == 10 and ev.end_line == 10
    _add(config, title="Another", line=10, end_line=14)
    other = [
        r for r in FindingStore(config).list() if r.as_finding().title == "Another"
    ]
    assert other[0].as_finding().evidence[0].end_line == 14


# ----------------------------------------------------------------- validation
def test_bad_severity_and_line_are_rejected(config, workspace):
    assert "Unknown severity" in _add(config, severity="spicy")
    assert "Line must be a number" in _add(config, line="ten")
    assert "End line must be a number" in _add(config, end_line="x")
    assert FindingStore(config).list() == []


def test_missing_title_is_rejected(config, workspace):
    assert "Not recorded" in _add(config, title="")
    assert FindingStore(config).list() == []


def test_ungrounded_evidence_warns_but_still_records(config, workspace):
    """A human verdict is the authority — an unresolvable path is a warning,
    not a downgrade the way it is for an agent-reported finding."""
    out = _add(config, file="does_not_exist.py")
    assert "Recorded FND-" in out
    assert "⚠ evidence not found in the workspace" in out
    f = FindingStore(config).list()[0].as_finding()
    assert f.effective_status() == "confirmed"  # NOT downgraded to unconfirmed


# ---------------------------------------------------------------- interactive
def test_prompt_collects_every_field_in_order():
    answers = iter(
        [
            "SSRF in webhook",  # title
            "SSRF",  # category
            "high",  # severity
            "hooks.py",  # file
            "42",  # line
            "",  # end line
            "user-controlled URL fetched server-side",  # description
            "allowlist the host",  # recommendation
            "CWE-918",  # cwe
            "",  # owasp
            "",  # disproof
        ]
    )
    fields = prompt_for_finding(ask=lambda _p: next(answers))
    assert fields["title"] == "SSRF in webhook"
    assert fields["severity"] == "high"
    assert fields["line"] == "42"
    assert fields["end_line"] == ""
    assert fields["cwe"] == "CWE-918"


def test_prompt_reasks_until_a_required_field_is_given():
    answers = iter(
        ["", "  ", "Real title", "cat", "low", "a.py", "1", "", "", "", "", "", ""]
    )
    fields = prompt_for_finding(ask=lambda _p: next(answers))
    assert fields["title"] == "Real title"


def test_prompt_aborts_on_interrupt():
    def _ask(_p):
        raise KeyboardInterrupt

    assert prompt_for_finding(ask=_ask) is None


def test_prompted_fields_feed_straight_into_the_recorder(config, workspace):
    """The prompt's output keys must match add_manual_finding's parameters."""
    answers = iter(["T", "cat", "low", "vuln_app.py", "3", "", "d", "r", "", "", ""])
    fields = prompt_for_finding(ask=lambda _p: next(answers))
    assert "Recorded FND-" in add_manual_finding(_app(config), **fields)
