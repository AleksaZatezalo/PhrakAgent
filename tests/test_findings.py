"""
Description: Structured finding & taint-path models (appsec.models.findings).
Author: Aleksa Zatezalo
Date Created: 07-30-2026
"""

from __future__ import annotations

from appsec.models.findings import (
    FindingEvidence,
    SecurityFinding,
    TaintNode,
    TaintPathReference,
    TaintStep,
    dedupe_findings,
    status_transition_allowed,
    validate_against_workspace,
    validate_finding,
)


def _sqli_taint_path(complete: bool = True) -> TaintPathReference:
    return TaintPathReference(
        source=TaintNode(path="app.py", line=3, expression="request.args['id']",
                         kind="source"),
        sink=TaintNode(path="app.py", line=5, expression="cursor.execute(q)",
                       kind="sink"),
        steps=[TaintStep(path="app.py", line=4, operation="assignment",
                         from_expression="uid", to_expression="q")],
        completeness="complete" if complete else "partial",
        analysis_mode="intra_procedural",
        confidence=0.9 if complete else 0.4,
    )


def _finding(**over) -> SecurityFinding:
    base = dict(
        title="SQL injection in /user",
        category="SQL injection",
        severity="high",
        confidence=0.9,
        affected_files=["app.py"],
        affected_symbols=["get_user"],
        evidence=[FindingEvidence(path="app.py", start_line=5, reason="tainted execute",
                                  evidence_type="taint_step")],
        taint_paths=[_sqli_taint_path()],
        source_agent="code_review",
    )
    base.update(over)
    return SecurityFinding(**base)


# --------------------------------------------------------------- fingerprint
def test_fingerprint_is_stable_across_instances():
    a = _finding().ensure_identity()
    b = _finding().ensure_identity()
    assert a.fingerprint == b.fingerprint
    assert a.id == b.id and a.id.startswith("FND-")


def test_fingerprint_changes_with_sink_location():
    a = _finding().ensure_identity()
    tp = _sqli_taint_path()
    tp.sink.line = 999
    b = _finding(taint_paths=[tp]).ensure_identity()
    assert a.fingerprint != b.fingerprint


def test_taint_path_id_is_stable():
    assert _sqli_taint_path().compute_id() == _sqli_taint_path().compute_id()
    assert _sqli_taint_path().compute_id().startswith("TP-")


# --------------------------------------------------------------- validation
def test_confidence_bounds_enforced():
    errs = validate_finding(_finding(confidence=1.5))
    assert any("confidence" in e for e in errs)


def test_bad_severity_and_status_rejected():
    errs = validate_finding(_finding(severity="apocalyptic", status="weird"))
    assert any("severity" in e for e in errs)
    assert any("status" in e for e in errs)


def test_finding_without_evidence_or_path_is_invalid():
    f = SecurityFinding(title="x", category="misc", severity="low")
    assert any("no evidence" in e for e in validate_finding(f))


def test_dataflow_confirmed_requires_supporting_path():
    # 'confirmed' + data-flow category + only a partial path -> invalid
    f = _finding(status="confirmed", taint_paths=[_sqli_taint_path(complete=False)])
    assert any("without a complete" in e for e in validate_finding(f))
    # a complete path clears it
    assert validate_finding(_finding(status="confirmed")) == []


def test_status_transitions():
    assert status_transition_allowed("new", "confirmed")
    assert status_transition_allowed("confirmed", "fixed")
    assert not status_transition_allowed("fixed", "new")
    assert not status_transition_allowed("new", "bogus")


# --------------------------------------------------------------- serialization
def test_serialization_round_trip():
    f = _finding().ensure_identity()
    again = SecurityFinding.from_dict(f.to_dict())
    assert again.fingerprint == f.fingerprint
    assert again.taint_paths[0].source.expression == "request.args['id']"
    assert again.evidence[0].path == "app.py"
    assert again.severity == "high"


def test_markdown_contains_key_sections():
    md = _finding().to_markdown()
    assert "Severity: High" in md
    assert "Confidence: 0.90" in md
    assert "CWE:" in md
    assert "Source:" in md and "Sink:" in md and "Taint path:" in md


# --------------------------------------------------------------- dedup
def test_dedupe_merges_by_fingerprint_and_keeps_highest_confidence():
    low = _finding(confidence=0.3, source_tools=["opengrep"])
    high = _finding(confidence=0.95, source_tools=["taint_trace"])
    merged = dedupe_findings([low, high])
    assert len(merged) == 1
    assert merged[0].confidence == 0.95
    assert set(merged[0].source_tools) == {"opengrep", "taint_trace"}


# --------------------------------------------------------------- workspace grounding
def test_validate_against_workspace_flags_escape_and_missing(tmp_path):
    (tmp_path / "app.py").write_text("a\nb\nuid = request.args['id']\nq=uid\ncur.execute(q)\n")
    # valid finding grounded in the real file
    ok = _finding(evidence=[FindingEvidence(path="app.py", start_line=5,
                                            snippet="cur.execute", reason="sink")])
    assert validate_against_workspace(ok, tmp_path) == []

    # path escaping the workspace
    esc = _finding(evidence=[FindingEvidence(path="../../etc/passwd", start_line=1,
                                             reason="x")], taint_paths=[])
    assert any("escapes workspace" in e for e in validate_against_workspace(esc, tmp_path))

    # missing file
    miss = _finding(evidence=[FindingEvidence(path="nope.py", start_line=1, reason="x")],
                    taint_paths=[])
    assert any("not found" in e for e in validate_against_workspace(miss, tmp_path))

    # out-of-range line
    oor = _finding(evidence=[FindingEvidence(path="app.py", start_line=999, reason="x")],
                   taint_paths=[])
    assert any("out of range" in e for e in validate_against_workspace(oor, tmp_path))
