"""
Description: Persistent finding & taint history store (appsec.store) — Phase 7.
Author: Aleksa Zatezalo
Date Created: 07-31-2026
"""

from __future__ import annotations

from appsec.models.findings import (
    FindingEvidence,
    SecurityFinding,
    TaintNode,
    TaintPathReference,
)
from appsec.store import (
    FindingStore,
    TaintStore,
    render_finding_detail,
    render_finding_list,
)


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
        taint_paths=[
            TaintPathReference(
                source=TaintNode(path="vuln_app.py", line=10, kind="source"),
                sink=TaintNode(path="vuln_app.py", line=11, kind="sink"),
                completeness="partial",
                analysis_mode="syntactic",
                confidence=0.5,
            )
        ],
        source_agent="code_review",
    )
    base.update(over)
    return SecurityFinding(**base).ensure_identity()


# --------------------------------------------------------------- effective status
def test_effective_status_precedence():
    f = _finding(status="unconfirmed")
    assert f.effective_status() == "unconfirmed"
    f.runtime_status = "confirmed"
    assert f.effective_status() == "confirmed"  # runtime wins over agent
    f.human_status = "false_positive"
    assert f.effective_status() == "false_positive"  # human wins over runtime


def test_effective_status_ignores_empty_tracks():
    f = _finding(status="new")
    f.runtime_status = ""
    f.human_status = ""
    assert f.effective_status() == "new"  # falls back to the agent track


# --------------------------------------------------------------- upsert / dedup
def test_upsert_creates_then_updates_same_fingerprint(config):
    store = FindingStore(config)
    store.upsert([_finding(confidence=0.5)], run_id="r1")
    recs = store.list()
    assert len(recs) == 1
    assert recs[0].first_seen and recs[0].last_seen
    assert len(recs[0].runs) == 1

    # same finding again in a second run -> updates, doesn't duplicate
    store.upsert([_finding(confidence=0.7)], run_id="r2")
    recs = store.list()
    assert len(recs) == 1
    assert len(recs[0].runs) == 2
    assert recs[0].as_finding().confidence == 0.7


def test_human_verdict_preserved_across_runs(config):
    store = FindingStore(config)
    store.upsert([_finding(confidence=0.5)], run_id="r1")
    fid = store.list()[0].id
    store.set_status(fid, "false_positive", actor="human", note="not reachable")

    # a later run re-reports the same finding with materially higher confidence;
    # the human verdict must survive but the record should re-surface.
    store.upsert([_finding(confidence=0.85)], run_id="r2")
    rec = store.get(fid)
    f = rec.as_finding()
    assert f.human_status == "false_positive"
    assert f.effective_status() == "false_positive"
    # confidence rose materially -> re-surfaced for another look
    assert rec.resurfaced is True


def test_runtime_track_is_independent(config):
    store = FindingStore(config)
    store.upsert([_finding(status="new")], run_id="r1")
    fid = store.list()[0].id
    rec, msg = store.set_status(
        fid,
        "false_positive",
        actor="runtime",
        note="html.escape not relevant but input is bound",
        confidence=0.2,
    )
    assert rec is not None and "runtime_status" in msg
    f = store.get(fid).as_finding()
    assert f.runtime_status == "false_positive"
    assert f.status == "new"  # agent track untouched
    assert f.confidence == 0.2  # the re-check adjusted confidence
    # the rationale stays attributable on the history entry
    assert rec.history[-1]["note"].startswith("html.escape")


def test_set_status_rejects_unknown_actor(config):
    store = FindingStore(config)
    store.upsert([_finding()], run_id="r1")
    rec, msg = store.set_status(store.list()[0].id, "confirmed", actor="verifier")
    assert rec is None and "unknown actor" in msg


def test_note_appended(config):
    store = FindingStore(config)
    store.upsert([_finding()], run_id="r1")
    fid = store.list()[0].id
    store.add_note(fid, "double-check the ORM layer")
    assert store.get(fid).notes[0]["text"] == "double-check the ORM layer"


# --------------------------------------------------------------- rendering
def test_render_helpers_smoke(config):
    store = FindingStore(config)
    assert "No findings" in render_finding_list([])
    store.upsert([_finding()], run_id="r1")
    store.upsert([_finding(confidence=0.95)], run_id="r2")
    rec = store.list()[0]
    assert rec.id in render_finding_list([rec])
    assert "Status history" in render_finding_detail(rec)


# --------------------------------------------------------------- taint store
def test_taint_store_tracks_completeness_changes(config):
    tstore = TaintStore(config)
    tstore.upsert([_finding()], run_id="r1")
    recs = tstore.list()
    assert len(recs) == 1
    tid = recs[0]["id"]

    # promote completeness in a later run
    f2 = _finding()
    f2.taint_paths[0].completeness = "runtime_confirmed"
    tstore.upsert([f2], run_id="r2")
    recs = tstore.list()
    assert len(recs) == 1 and recs[0]["id"] == tid  # same path, not a new record
    assert recs[0]["completeness"] == "runtime_confirmed"
    assert len(recs[0]["history"]) == 2
