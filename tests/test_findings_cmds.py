"""
Description: Findings triage commands + @file attachment feedback (session_cmds).
Author: Aleksa Zatezalo
Date Created: 08-18-2026
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from appsec.models.findings import FindingEvidence, SecurityFinding
from appsec.session_cmds import (
    at_ref_names,
    describe_at_refs,
    finding_detail,
    findings_json,
    findings_list,
    note_finding,
    parse_findings_flags,
    triage_finding,
)
from appsec.store import FindingStore


def _finding(**over) -> SecurityFinding:
    base = dict(
        title="SQL injection in /user",
        category="SQL injection",
        severity="high",
        confidence=0.8,
        status="new",
        affected_files=["vuln_app.py"],
        evidence=[
            FindingEvidence(path="vuln_app.py", start_line=11, reason="tainted execute")
        ],
        source_agent="code_review",
    )
    base.update(over)
    return SecurityFinding(**base).ensure_identity()


def _app(config, findings=()):
    """An App-shaped stub whose store is seeded with ``findings``."""
    if findings:
        FindingStore(config).upsert(list(findings), run_id="r1")
    return SimpleNamespace(config=config)


# ------------------------------------------------------------------- listing
def test_findings_list_empty_store(config):
    out = findings_list(_app(config))
    assert "No findings recorded yet" in out


def test_findings_list_renders_each_record(config):
    app = _app(
        config,
        [_finding(), _finding(title="XSS in /search", severity="medium")],
    )
    out = findings_list(app)
    assert "2 finding(s)" in out
    assert "SQL injection in /user" in out and "XSS in /search" in out


def test_findings_list_filters_by_severity_and_status(config):
    app = _app(
        config,
        [_finding(), _finding(title="XSS in /search", severity="medium")],
    )
    assert "XSS" not in findings_list(app, severity="high")
    assert "SQL injection" not in findings_list(app, severity="medium")
    # every seeded finding starts at "new"
    assert "2 finding(s)" in findings_list(app, status="new")


def test_findings_list_distinguishes_empty_filter_from_empty_store(config):
    app = _app(config, [_finding()])
    out = findings_list(app, severity="low")
    assert "No findings match that filter" in out
    assert "1 recorded overall" in out


def test_findings_list_resurfaced_filter(config):
    app = _app(config, [_finding()])
    assert "No findings match that filter" in findings_list(app, resurfaced=True)


def test_findings_list_normalizes_filter_values(config):
    app = _app(config, [_finding()])
    assert "SQL injection" in findings_list(app, severity=" HIGH ")
    assert "SQL injection" in findings_list(app, status="New")


def test_findings_list_rejects_unknown_filter_values(config):
    """A typo'd filter must not read as 'you have no such findings'."""
    app = _app(config, [_finding()])
    out = findings_list(app, severity="spicy")
    assert "Unknown severity 'spicy'" in out and "critical" in out
    assert "No findings match" not in out
    assert "Unknown status 'maybe'" in findings_list(app, status="maybe")


# -------------------------------------------------------------- flag parsing
def test_parse_findings_flags_ok():
    kwargs, err = parse_findings_flags("--severity HIGH --status false-positive")
    assert err == ""
    assert kwargs == {
        "severity": "HIGH",  # normalization is findings_list's job
        "status": "false-positive",
        "resurfaced": False,
    }


def test_parse_findings_flags_rejects_malformed_flags():
    assert "unknown or incomplete" in parse_findings_flags("--nope")[1]
    # a flag missing its value is incomplete, not silently ignored
    assert "unknown or incomplete" in parse_findings_flags("--severity")[1]
    assert parse_findings_flags("--resurfaced")[0]["resurfaced"] is True


# -------------------------------------------------------------------- detail
def test_finding_detail_by_id_and_prefix(config):
    f = _finding()
    app = _app(config, [f])
    out = finding_detail(app, f.id)
    assert "SQL injection in /user" in out
    assert "First seen:" in out
    # a fingerprint prefix resolves too
    assert "SQL injection in /user" in finding_detail(app, f.fingerprint[:8])


def test_finding_detail_missing_and_usage(config):
    app = _app(config, [_finding()])
    assert "usage: /finding" in finding_detail(app, "")
    assert "No finding matching 'nope'" in finding_detail(app, "nope")


# -------------------------------------------------------------------- triage
def test_triage_records_human_verdict(config):
    f = _finding()
    app = _app(config, [f])
    msg = triage_finding(app, f"{f.id} false_positive not reachable from any route")
    assert "human_status -> false_positive" in msg

    rec = FindingStore(config).get(f.id)
    assert rec.as_finding().effective_status() == "false_positive"
    assert rec.as_finding().status == "new"  # the agent track is left alone
    entry = rec.history[-1]
    assert entry["actor"] == "human"
    assert entry["note"] == "not reachable from any route"


def test_triage_accepts_hyphenated_status(config):
    f = _finding()
    app = _app(config, [f])
    assert "false_positive" in triage_finding(app, f"{f.id} false-positive")


def test_triage_rejects_unknown_status_and_shows_vocabulary(config):
    f = _finding()
    app = _app(config, [f])
    out = triage_finding(app, f"{f.id} wontfix")
    assert "Unknown status 'wontfix'" in out
    assert "accepted_risk" in out  # the real vocabulary is offered


def test_triage_usage_and_missing_finding(config):
    app = _app(config, [_finding()])
    assert "usage: /triage" in triage_finding(app, "")
    assert "usage: /triage" in triage_finding(app, "only-an-id")
    assert "no finding matching" in triage_finding(app, "nope confirmed")


# --------------------------------------------------------------------- notes
def test_note_finding(config):
    f = _finding()
    app = _app(config, [f])
    assert "note added" in note_finding(app, f"{f.id} check the ORM wrapper")
    assert FindingStore(config).get(f.id).notes[-1]["text"] == "check the ORM wrapper"


def test_note_usage_and_missing_finding(config):
    app = _app(config, [_finding()])
    assert "usage: /note" in note_finding(app, "just-an-id")
    assert "no finding matching" in note_finding(app, "nope some text")


# ---------------------------------------------------------------------- json
def test_findings_json_is_parseable(config):
    f = _finding()
    data = json.loads(findings_json(_app(config, [f])))
    assert len(data) == 1
    assert data[0]["id"] == f.id
    assert data[0]["finding"]["title"] == "SQL injection in /user"


def test_findings_json_empty_store(config):
    assert json.loads(findings_json(_app(config))) == []


# ------------------------------------------------------------- @file refs
def test_at_ref_names_dedupes_in_order():
    assert at_ref_names("@b.py then @a.py and @b.py again") == ["b.py", "a.py"]
    assert at_ref_names("no refs, and email@example.com") == []


def test_describe_at_refs_reports_size_and_problems(config, workspace):
    lines = describe_at_refs("@vuln_app.py @missing.py @../outside.txt", workspace)
    assert len(lines) == 3
    assert lines[0].startswith("@vuln_app.py (") and " B" in lines[0]
    assert lines[1] == "@missing.py (not a file)"
    assert "outside workspace" in lines[2]


def test_describe_at_refs_empty_without_refs(config, workspace):
    assert describe_at_refs("plain question", workspace) == []
