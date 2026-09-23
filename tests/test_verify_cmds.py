"""
Description: `/verify <id>` task builder + PoC persistence (no container needed).
Author: Aleksa Zatezalo
Date Created: 09-22-2026
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from appsec.models.findings import FindingEvidence, SecurityFinding
from appsec.poc_store import PocStore
from appsec.store import FindingStore
from appsec.tools.verify_tool import record_poc_result
from appsec.verify_cmds import build_verify_task


def _seed_finding(config) -> str:
    f = SecurityFinding(
        title="SQL injection in /user",
        category="injection",
        severity="critical",
        cwe_ids=["CWE-89"],
        affected_files=["vuln_app.py"],
        evidence=[FindingEvidence(path="vuln_app.py", start_line=13, reason="taint")],
    )
    rec = FindingStore(config).upsert([f], run_id="r1")[0]
    return rec.id


def _app(config, verify_names=("verify", "code_review")):
    return SimpleNamespace(
        config=config, registry=SimpleNamespace(names=lambda: list(verify_names))
    )


# ---------------------------------------------------------------- PoC storage
def test_record_poc_result_persists_and_promotes(runtime):
    config = runtime
    fid = _seed_finding(config)
    msg = record_poc_result.invoke(
        {
            "finding_id": fid,
            "outcome": "confirmed",
            "note": "leaked rows",
            "poc": "print('rows: 1,2,3')",
        }
    )
    assert "RECORDED" in msg and "poc POC-" in msg
    # the finding is now runtime-confirmed
    rec = FindingStore(config).get(fid)
    assert rec.as_finding().runtime_status == "confirmed"
    # exactly one PoC landed in the store, linked to the finding
    pocs = PocStore(config).list()
    assert len(pocs) == 1
    assert pocs[0].finding_id == fid
    assert pocs[0].outcome == "confirmed"
    assert "rows" in PocStore(config).read_script(pocs[0])


def test_record_poc_result_unknown_id(runtime):
    msg = record_poc_result.invoke(
        {"finding_id": "FND-nope", "outcome": "confirmed", "poc": "x"}
    )
    assert "NOT RECORDED" in msg
    assert PocStore(runtime).list() == []  # nothing persisted for a bad id


# ------------------------------------------------------------ task building
def test_build_verify_task_off_by_default(config):
    assert config.enable_verify is False
    task, err = build_verify_task(_app(config), "FND-abc")
    assert task == "" and "enable_verify" in err


def test_build_verify_task_requires_id(config):
    config.enable_verify = True
    task, err = build_verify_task(_app(config), "")
    assert task == "" and "usage" in err


def test_build_verify_task_unknown_finding(config):
    config.enable_verify = True
    task, err = build_verify_task(_app(config), "FND-nope")
    assert task == "" and "no finding matching" in err


def test_build_verify_task_scopes_to_one_finding(runtime):
    config = runtime
    config.enable_verify = True
    fid = _seed_finding(config)
    task, err = build_verify_task(_app(config), fid)
    assert err == ""
    assert fid in task
    assert "Verify ONLY" in task
    assert "record_poc_result" in task
