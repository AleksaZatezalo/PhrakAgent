"""
Description: The verify agent's runtime-verdict wiring (record_poc_result).
Author: Aleksa Zatezalo
Date Created: 08-20-2026

A landed PoC has to actually MOVE the finding on the runtime track — otherwise
the verify agent runs sandboxed exploits and changes nothing. These pin that the
tool promotes / refutes an existing finding and that the runtime track folds into
effective_status with the documented precedence.
"""

from __future__ import annotations

import pytest

from appsec.models.findings import FindingEvidence, SecurityFinding
from appsec.store import FindingStore
from appsec.tools.verify_tool import record_poc_result, verify_tools


def _seed(config, status: str = "new") -> SecurityFinding:
    f = SecurityFinding(
        title="SQL injection in get_user",
        category="a03-injection",
        severity="high",
        description="user id concatenated into SQL",
        status=status,
        confidence=0.6,
        affected_files=["vuln_app.py"],
        evidence=[FindingEvidence(path="vuln_app.py", start_line=13, end_line=13)],
    ).ensure_identity()
    FindingStore(config).upsert([f], run_id="code_review")
    return f


def _call(**kw) -> str:
    return record_poc_result.invoke(kw)


def test_tool_exposed_only_when_enabled(config):
    config.enable_verify = False
    assert verify_tools(config) == []
    config.enable_verify = True
    names = {t.name for t in verify_tools(config)}
    assert names == {"run_poc", "record_poc_result"}


def test_landed_poc_promotes_runtime_status(runtime):
    f = _seed(runtime)
    out = _call(
        finding_id=f.id,
        outcome="confirmed",
        note="leaked all rows with ' OR '1'='1",
        poc="import sqlite3\n...",
    )
    assert "RECORDED runtime verdict" in out
    rec = FindingStore(runtime).get(f.id)
    stored = rec.as_finding()
    assert stored.runtime_status == "confirmed"
    assert stored.effective_status() == "confirmed"
    assert stored.confidence >= 0.95  # a landed PoC raises confidence


def test_non_landing_poc_marks_false_positive(runtime):
    f = _seed(runtime)
    out = _call(finding_id=f.id, outcome="false_positive", note="payload never fired")
    assert "RECORDED runtime verdict" in out
    stored = FindingStore(runtime).get(f.id).as_finding()
    assert stored.runtime_status == "false_positive"


def test_inconclusive_records_a_note_without_changing_status(runtime):
    f = _seed(runtime)
    out = _call(finding_id=f.id, outcome="inconclusive", note="needs full app stack")
    assert "inconclusive" in out.lower()
    stored = FindingStore(runtime).get(f.id).as_finding()
    assert stored.runtime_status == ""  # unchanged
    assert stored.effective_status() == "new"


def test_human_verdict_outranks_runtime(runtime):
    f = _seed(runtime)
    _call(finding_id=f.id, outcome="confirmed", note="landed")
    # a human later dismisses it — human track wins in effective_status
    FindingStore(runtime).set_status(f.id, "false_positive", actor="human")
    stored = FindingStore(runtime).get(f.id).as_finding()
    assert stored.runtime_status == "confirmed"
    assert stored.human_status == "false_positive"
    assert stored.effective_status() == "false_positive"


def test_unknown_finding_id_is_reported_not_raised(runtime):
    _seed(runtime)
    out = _call(finding_id="FND-doesnotexist", outcome="confirmed")
    assert "NOT RECORDED" in out


def test_bad_outcome_is_rejected(runtime):
    f = _seed(runtime)
    out = _call(finding_id=f.id, outcome="maybe")
    assert out.startswith("REJECTED")
