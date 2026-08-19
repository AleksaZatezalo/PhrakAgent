"""
Description: Finding/taint store concurrency — no lost updates, atomic writes.
Author: Aleksa Zatezalo
Date Created: 08-18-2026
"""

from __future__ import annotations

import json
import threading

from appsec.models.findings import FindingEvidence, SecurityFinding
from appsec.store import FindingStore, TaintStore, _write_jsonl


def _finding(i: int, **over) -> SecurityFinding:
    base = dict(
        title=f"Issue {i}",
        category="SQL injection",
        severity="high",
        confidence=0.7,
        affected_files=["a.py"],
        evidence=[FindingEvidence(path="a.py", start_line=i, reason=f"reason {i}")],
        source_agent="code_review",
    )
    base.update(over)
    return SecurityFinding(**base).ensure_identity()


def _run_threads(target, args_list):
    threads = [threading.Thread(target=target, args=a) for a in args_list]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


# ------------------------------------------------------------ lost updates
def test_parallel_upserts_lose_nothing(config):
    """The DAG runs agents in threads; each persists at the end of its run.

    Without locking the load-modify-save cycle, the last writer wins and the
    other agents' findings are silently dropped.
    """
    store = FindingStore(config)
    store.upsert([_finding(i) for i in range(1000, 1100)], run_id="prior")
    before = len(store.list())

    barrier = threading.Barrier(3)

    def agent(base):
        batch = [_finding(i) for i in range(base, base + 5)]
        barrier.wait()  # make all three collide on the write
        FindingStore(config).upsert(batch, run_id=f"agent-{base}")

    _run_threads(agent, [(0,), (100,), (200,)])
    assert len(FindingStore(config).list()) == before + 15


def test_many_sequential_upserts_from_several_threads(config):
    def worker(base):
        store = FindingStore(config)
        for i in range(base, base + 20):
            store.upsert([_finding(i)], run_id=f"w{base}")

    _run_threads(worker, [(0,), (100,), (200,)])
    assert len(FindingStore(config).list()) == 60


def test_parallel_taint_upserts_lose_nothing(config):
    from appsec.models.findings import TaintNode, TaintPathReference

    def taint_finding(i):
        return _finding(
            i,
            taint_paths=[
                TaintPathReference(
                    source=TaintNode(path="a.py", line=i, kind="source"),
                    sink=TaintNode(path="b.py", line=i, kind="sink"),
                    completeness="partial",
                    analysis_mode="syntactic",
                    confidence=0.5,
                )
            ],
        )

    barrier = threading.Barrier(3)

    def agent(base):
        batch = [taint_finding(i) for i in range(base, base + 5)]
        barrier.wait()
        TaintStore(config).upsert(batch, run_id=f"agent-{base}")

    _run_threads(agent, [(0,), (100,), (200,)])
    assert len(TaintStore(config).list()) == 15


def test_concurrent_triage_keeps_every_history_entry(config):
    """Notes and status changes race against each other too — one note or
    verdict silently dropped is the same lost-update bug in triage clothing."""
    findings = [_finding(i) for i in range(5)]
    FindingStore(config).upsert(findings, run_id="r1")
    ids = [f.id for f in findings]

    barrier = threading.Barrier(len(ids) * 2)  # one note + one triage per finding

    def note(ident):
        barrier.wait()
        FindingStore(config).add_note(ident, f"note for {ident}")

    def triage(ident):
        barrier.wait()
        FindingStore(config).set_status(ident, "confirmed", actor="human")

    threads = [threading.Thread(target=note, args=(i,)) for i in ids]
    threads += [threading.Thread(target=triage, args=(i,)) for i in ids]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
        assert not t.is_alive(), "a triage thread deadlocked"

    store = FindingStore(config)
    for ident in ids:
        rec = store.get(ident)
        assert rec is not None
        assert len(rec.notes) == 1
        assert rec.as_finding().human_status == "confirmed"


# --------------------------------------------------------------- atomicity
def test_write_jsonl_is_atomic_and_leaves_no_temp_files(config, tmp_path):
    path = tmp_path / "records.jsonl"
    _write_jsonl(path, [{"id": "a"}, {"id": "b"}])
    assert [json.loads(x) for x in path.read_text().splitlines() if x] == [
        {"id": "a"},
        {"id": "b"},
    ]
    # a second write fully replaces the first, with no leftover scratch files
    _write_jsonl(path, [{"id": "c"}])
    assert [json.loads(x) for x in path.read_text().splitlines() if x] == [{"id": "c"}]
    assert [p.name for p in tmp_path.iterdir() if ".tmp" in p.name] == []


def test_store_survives_a_corrupt_trailing_line(config):
    """A store truncated by an older non-atomic write must still load."""
    store = FindingStore(config)
    store.upsert([_finding(1), _finding(2)], run_id="r1")
    with store.path.open("a") as fh:
        fh.write('{"fingerprint": "half-written"')  # no newline, unparseable
    assert len(FindingStore(config).list()) == 2
