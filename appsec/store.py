"""
Description: Persistent finding, taint-path & test-case history (Phase 7).
Author: Aleksa Zatezalo
Date Created: 07-31-2026
"""

from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .config import Config
from .models.findings import (
    SecurityFinding,
    dedupe_findings,
    status_transition_allowed,
)
from .models.testcases import SecurityTestCase, dedupe_test_cases

# Actors allowed to change a status track. Each maps to the finding field the
# change is written to; "agent" writes the base ``status``.
ACTOR_FIELD = {
    "agent": "status",
    "runtime": "runtime_status",
    "human": "human_status",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # tolerate a partially-written trailing line
    return out


def _write_jsonl(path: Path, records: list[dict]) -> None:
    """Replace ``path`` atomically.

    Written to a temp file in the same directory and renamed over the target, so
    a reader never sees a half-written store and a crash mid-write can't truncate
    the existing one. The temp name carries the PID *and* thread id: callers hold
    :func:`_exclusive` so writes are already serialized, but a unique scratch
    name means an unlocked caller degrades to a lost update rather than to two
    writers clobbering one temp file mid-rename.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(json.dumps(r, default=str) for r in records) + "\n"
    tmp = path.parent / f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        tmp.write_text(body)
        os.replace(tmp, path)  # atomic on POSIX and Windows
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


# --------------------------------------------------------------------- locking
# Every mutation is read-modify-write over the whole file, so two agents writing
# at once would silently lose one side's findings. The DAG orchestrator runs
# agents in THREADS (orchestrator.max_concurrency, default 3) and each persists
# at the end of its run, so this is the default path, not an edge case.
#
# The threading lock covers that; the file lock additionally covers two `phrak`
# processes pointed at one workspace. Locks are keyed by path because callers
# build a fresh store object per write (see base_agent._persist_findings).
_PATH_LOCKS: dict[str, threading.Lock] = {}
_PATH_LOCKS_GUARD = threading.Lock()


def _thread_lock_for(path: Path) -> threading.Lock:
    key = str(path)
    with _PATH_LOCKS_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _PATH_LOCKS[key] = lock
        return lock


@contextmanager
def _exclusive(path: Path):
    """Serialize a read-modify-write cycle on ``path`` across threads and processes.

    The advisory file lock is best-effort: platforms without ``fcntl`` (Windows)
    and filesystems that refuse ``flock`` (some NFS mounts) fall back to the
    in-process lock alone, which still covers the parallel-agent case.
    """
    with _thread_lock_for(path):
        path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = path.parent / f"{path.name}.lock"
        handle = None
        try:
            handle = open(lock_path, "w")
        except OSError:
            yield  # can't create a lockfile — the thread lock is what we have
            return
        try:
            try:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            except (ImportError, OSError):
                pass
            yield
        finally:
            try:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except (ImportError, OSError):
                pass
            handle.close()


# =====================================================================finding
@dataclass
class FindingRecord:
    """A finding's durable history, keyed by its stable fingerprint."""

    fingerprint: str
    id: str
    finding: dict  # latest SecurityFinding snapshot
    first_seen: str = ""
    last_seen: str = ""
    runs: list[dict] = field(default_factory=list)  # per-run observations
    history: list[dict] = field(default_factory=list)  # status/evidence changes
    notes: list[dict] = field(default_factory=list)  # reviewer notes
    resurfaced: bool = False  # material evidence change vs a human verdict

    def as_finding(self) -> SecurityFinding:
        return SecurityFinding.from_dict(self.finding)

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "id": self.id,
            "finding": self.finding,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "runs": self.runs,
            "history": self.history,
            "notes": self.notes,
            "resurfaced": self.resurfaced,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "FindingRecord":
        return cls(
            fingerprint=raw.get("fingerprint", ""),
            id=raw.get("id", ""),
            finding=raw.get("finding", {}) or {},
            first_seen=raw.get("first_seen", ""),
            last_seen=raw.get("last_seen", ""),
            runs=list(raw.get("runs") or []),
            history=list(raw.get("history") or []),
            notes=list(raw.get("notes") or []),
            resurfaced=bool(raw.get("resurfaced", False)),
        )


class FindingStore:
    """Durable, fingerprint-keyed finding history under ``.phrack/findings``."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.dir = config.phrack_dir / "findings"
        self.path = self.dir / "findings.jsonl"

    # ------------------------------------------------------------- load/save
    def _load(self) -> dict[str, FindingRecord]:
        recs = [FindingRecord.from_dict(r) for r in _read_jsonl(self.path)]
        return {r.fingerprint: r for r in recs if r.fingerprint}

    def _save(self, records: dict[str, FindingRecord]) -> None:
        ordered = sorted(records.values(), key=lambda r: r.last_seen, reverse=True)
        _write_jsonl(self.path, [r.to_dict() for r in ordered])

    # ------------------------------------------------------------- write path
    def upsert(
        self, findings: list[SecurityFinding], run_id: str = "", ts: str = ""
    ) -> list[FindingRecord]:
        """Merge a run's findings into the durable store.

        New findings are added; known ones (same fingerprint) update their
        snapshot and last-seen. Human and runtime verdicts are **preserved**
        across runs, but if the re-observed finding materially changed
        (confidence rose, or a supporting taint path newly appeared) the record
        is flagged ``resurfaced`` so a previously-dismissed issue gets a fresh
        look.

        Load-merge-save runs under :func:`_exclusive` — parallel agents each
        persist at the end of their run, and without it the later writer would
        drop the earlier one's findings.
        """
        ts = ts or _now_iso()
        with _exclusive(self.path):
            return self._upsert_locked(findings, run_id, ts)

    def _upsert_locked(
        self, findings: list[SecurityFinding], run_id: str, ts: str
    ) -> list[FindingRecord]:
        records = self._load()
        touched: list[FindingRecord] = []
        for f in dedupe_findings(list(findings)):
            f.ensure_identity()
            existing = records.get(f.fingerprint)
            if existing is None:
                snap = f.to_dict()
                rec = FindingRecord(
                    fingerprint=f.fingerprint,
                    id=f.id,
                    finding=snap,
                    first_seen=ts,
                    last_seen=ts,
                    runs=[self._run_entry(f, run_id, ts)],
                    history=[
                        {
                            "ts": ts,
                            "actor": f.source_agent or "agent",
                            "change": "created",
                            "to": f.status,
                            "run_id": run_id,
                        }
                    ],
                )
                records[f.fingerprint] = rec
                touched.append(rec)
                continue
            # known finding — preserve human/runtime verdicts already recorded.
            prev = existing.as_finding()
            material = self._materially_changed(prev, f)
            if prev.human_status:
                f.human_status = prev.human_status
            if prev.runtime_status and not f.runtime_status:
                f.runtime_status = prev.runtime_status
            existing.finding = f.to_dict()
            existing.last_seen = ts
            existing.runs.append(self._run_entry(f, run_id, ts))
            if material and prev.human_status in ("false_positive", "accepted_risk"):
                existing.resurfaced = True
                existing.history.append(
                    {
                        "ts": ts,
                        "actor": "system",
                        "change": "resurfaced",
                        "note": "material evidence change vs prior human verdict "
                        f"'{prev.human_status}'",
                        "run_id": run_id,
                    }
                )
            touched.append(existing)
        self._save(records)
        return touched

    @staticmethod
    def _run_entry(f: SecurityFinding, run_id: str, ts: str) -> dict:
        return {
            "run_id": run_id,
            "ts": ts,
            "confidence": round(f.confidence, 3),
            "status": f.status,
            "severity": f.severity,
            "n_evidence": len(f.evidence),
            "has_supporting_taint": f.has_supporting_taint_path(),
        }

    @staticmethod
    def _materially_changed(prev: SecurityFinding, cur: SecurityFinding) -> bool:
        if cur.confidence - prev.confidence >= 0.2:
            return True
        if cur.has_supporting_taint_path() and not prev.has_supporting_taint_path():
            return True
        if cur.severity != prev.severity:
            return True
        return False

    # ------------------------------------------------------------- triage
    def set_status(
        self,
        ident: str,
        new_status: str,
        actor: str = "human",
        note: str = "",
        confidence: Optional[float] = None,
    ) -> tuple[Optional[FindingRecord], str]:
        """Record a status change on one track. Returns (record, message).

        ``confidence`` (optional) also updates the finding's confidence, for a
        re-check that raises or lowers it. ``note`` is kept on the history entry
        so the rationale for every change stays attributable to its actor.
        """
        actor = actor.lower()
        if actor not in ACTOR_FIELD:
            return None, f"unknown actor '{actor}' (use {', '.join(ACTOR_FIELD)})"
        with _exclusive(self.path):
            return self._set_status_locked(ident, new_status, actor, note, confidence)

    def _set_status_locked(
        self,
        ident: str,
        new_status: str,
        actor: str,
        note: str,
        confidence: Optional[float],
    ) -> tuple[Optional[FindingRecord], str]:
        records = self._load()
        rec = self._find(records, ident)
        if rec is None:
            return None, f"no finding matching '{ident}'"
        f = rec.as_finding()
        current = f.effective_status()
        # The automated tracks obey the transition graph; human triage may move
        # a finding anywhere (it is the authority of last resort).
        if actor != "human" and not status_transition_allowed(current, new_status):
            return rec, (
                f"transition {current} -> {new_status} not allowed for "
                f"actor '{actor}'"
            )
        setattr(f, ACTOR_FIELD[actor], new_status)
        if confidence is not None:
            f.confidence = max(0.0, min(float(confidence), 1.0))
        f.updated_at = datetime.now(timezone.utc)
        if actor == "human":
            rec.resurfaced = False  # a fresh human decision clears the re-surface flag
        rec.finding = f.to_dict()
        rec.history.append(
            {
                "ts": _now_iso(),
                "actor": actor,
                "change": "status",
                "field": ACTOR_FIELD[actor],
                "to": new_status,
                "note": note,
                **({"confidence": f.confidence} if confidence is not None else {}),
            }
        )
        records[rec.fingerprint] = rec
        self._save(records)
        return rec, (
            f"{rec.id}: {ACTOR_FIELD[actor]} -> {new_status} "
            f"(effective: {f.effective_status()})"
        )

    def add_note(self, ident: str, text: str) -> tuple[Optional[FindingRecord], str]:
        with _exclusive(self.path):
            records = self._load()
            rec = self._find(records, ident)
            if rec is None:
                return None, f"no finding matching '{ident}'"
            rec.notes.append({"ts": _now_iso(), "text": text})
            records[rec.fingerprint] = rec
            self._save(records)
            return rec, f"note added to {rec.id}"

    # ------------------------------------------------------------- read path
    def list(self) -> list[FindingRecord]:
        return sorted(self._load().values(), key=lambda r: r.last_seen, reverse=True)

    def get(self, ident: str) -> Optional[FindingRecord]:
        return self._find(self._load(), ident)

    @staticmethod
    def _find(records: dict[str, FindingRecord], ident: str) -> Optional[FindingRecord]:
        ident = (ident or "").strip()
        if not ident:
            return None
        for r in records.values():
            if ident in (r.id, r.fingerprint):
                return r
        # short prefix on id or fingerprint
        low = ident.lower()
        for r in records.values():
            if r.id.lower().endswith(low) or r.fingerprint.lower().startswith(low):
                return r
        return None


# =======================================================================taint
class TaintStore:
    """Durable history of taint paths, keyed by their stable id."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.dir = config.phrack_dir / "taint"
        self.path = self.dir / "taint.jsonl"

    def _load(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for r in _read_jsonl(self.path):
            tid = r.get("id")
            if tid:
                out[tid] = r
        return out

    def _save(self, records: dict[str, dict]) -> None:
        ordered = sorted(
            records.values(), key=lambda r: r.get("last_seen", ""), reverse=True
        )
        _write_jsonl(self.path, ordered)

    def upsert(
        self, findings: list[SecurityFinding], run_id: str = "", ts: str = ""
    ) -> list[dict]:
        """Merge a run's taint paths in. Locked for the same reason as
        :meth:`FindingStore.upsert` — parallel agents write this file too."""
        ts = ts or _now_iso()
        with _exclusive(self.path):
            return self._upsert_locked(findings, run_id, ts)

    def _upsert_locked(
        self, findings: list[SecurityFinding], run_id: str, ts: str
    ) -> list[dict]:
        records = self._load()
        touched: list[dict] = []
        for f in findings:
            for tp in f.taint_paths:
                tid = tp.ensure_id()
                snap = {
                    "id": tid,
                    "finding_id": f.id,
                    "source": tp.source.label(),
                    "sink": tp.sink.label(),
                    "completeness": tp.completeness,
                    "analysis_mode": tp.analysis_mode,
                    "confidence": round(tp.confidence, 3),
                    "n_steps": len(tp.steps),
                }
                existing = records.get(tid)
                if existing is None:
                    rec = {
                        **snap,
                        "first_seen": ts,
                        "last_seen": ts,
                        "history": [
                            {
                                "ts": ts,
                                "completeness": tp.completeness,
                                "run_id": run_id,
                            }
                        ],
                    }
                    records[tid] = rec
                    touched.append(rec)
                else:
                    changed = existing.get("completeness") != tp.completeness
                    existing.update(snap)
                    existing["last_seen"] = ts
                    if changed:
                        existing.setdefault("history", []).append(
                            {
                                "ts": ts,
                                "completeness": tp.completeness,
                                "run_id": run_id,
                            }
                        )
                    touched.append(existing)
        self._save(records)
        return touched

    def list(self) -> list[dict]:
        return sorted(
            self._load().values(), key=lambda r: r.get("last_seen", ""), reverse=True
        )


# ===================================================================test cases
class TestCaseStore:
    """Durable test-case backlog under ``.phrack/testcases``.

    Unlike findings — which the agents own and a human triages — test cases are
    a **work list the operator drives**. The ``test_case`` agent authors them,
    but status, results, notes, and the link to a finding are all human edits,
    and they are preserved when a later run re-authors the same test.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.dir = config.phrack_dir / "testcases"
        self.path = self.dir / "testcases.jsonl"

    # ------------------------------------------------------------- load/save
    def _load(self) -> dict[str, SecurityTestCase]:
        out: dict[str, SecurityTestCase] = {}
        for raw in _read_jsonl(self.path):
            tc = SecurityTestCase.from_dict(raw)
            tc.ensure_identity()
            if tc.fingerprint:
                out[tc.fingerprint] = tc
        return out

    def _save(self, records: dict[str, SecurityTestCase]) -> None:
        ordered = sorted(
            records.values(), key=lambda t: (t.created_at, t.id), reverse=False
        )
        _write_jsonl(self.path, [t.to_dict() for t in ordered])

    # ------------------------------------------------------------ write path
    def upsert(self, cases: list[SecurityTestCase]) -> list[SecurityTestCase]:
        """Merge authored test cases in, preserving operator progress.

        A re-authored test keeps its ``status``, ``result``, ``notes`` and any
        ``finding_id`` the operator set by hand — re-running ``test_case``
        refreshes the *instructions*, never your progress through them.
        """
        with _exclusive(self.path):
            records = self._load()
            touched: list[SecurityTestCase] = []
            for tc in dedupe_test_cases(list(cases)):
                tc.ensure_identity()
                prev = records.get(tc.fingerprint)
                if prev is not None:
                    tc.status = prev.status
                    tc.result = prev.result
                    tc.notes = list(prev.notes)
                    tc.finding_id = prev.finding_id or tc.finding_id
                    tc.created_at = prev.created_at
                tc.updated_at = datetime.now(timezone.utc)
                records[tc.fingerprint] = tc
                touched.append(tc)
            self._save(records)
            return touched

    def add(self, tc: SecurityTestCase) -> tuple[Optional[SecurityTestCase], str]:
        """Add ONE hand-written test case. Refuses a duplicate fingerprint."""
        tc.ensure_identity()
        with _exclusive(self.path):
            records = self._load()
            if tc.fingerprint in records:
                existing = records[tc.fingerprint]
                return existing, (
                    f"a test case with the same title+target already exists "
                    f"({existing.id}) — edit it instead"
                )
            records[tc.fingerprint] = tc
            self._save(records)
            return tc, f"added {tc.id}: {tc.title}"

    def set_status(
        self, ident: str, status: str, result: str = ""
    ) -> tuple[Optional[SecurityTestCase], str]:
        """Move a test case along the work list. ``result`` is optional."""
        with _exclusive(self.path):
            records = self._load()
            tc = self._find(records, ident)
            if tc is None:
                return None, f"no test case matching '{ident}'"
            tc.status = status
            if result:
                tc.result = result
            tc.updated_at = datetime.now(timezone.utc)
            records[tc.fingerprint] = tc
            self._save(records)
            suffix = f", result={tc.result}" if tc.result else ""
            return tc, f"{tc.id}: status -> {status}{suffix}"

    def link_finding(
        self, ident: str, finding_id: str
    ) -> tuple[Optional[SecurityTestCase], str]:
        """Point a test case at the finding it verifies (or clear the link)."""
        with _exclusive(self.path):
            records = self._load()
            tc = self._find(records, ident)
            if tc is None:
                return None, f"no test case matching '{ident}'"
            tc.finding_id = finding_id
            tc.updated_at = datetime.now(timezone.utc)
            records[tc.fingerprint] = tc
            self._save(records)
            if not finding_id:
                return tc, f"{tc.id}: finding link cleared"
            return tc, f"{tc.id}: now verifies {finding_id}"

    def add_note(self, ident: str, text: str) -> tuple[Optional[SecurityTestCase], str]:
        with _exclusive(self.path):
            records = self._load()
            tc = self._find(records, ident)
            if tc is None:
                return None, f"no test case matching '{ident}'"
            tc.notes.append(f"{_now_iso()}  {text}")
            tc.updated_at = datetime.now(timezone.utc)
            records[tc.fingerprint] = tc
            self._save(records)
            return tc, f"note added to {tc.id}"

    # ------------------------------------------------------------- read path
    def list(self) -> list[SecurityTestCase]:
        return sorted(self._load().values(), key=lambda t: (t.created_at, t.id))

    def get(self, ident: str) -> Optional[SecurityTestCase]:
        return self._find(self._load(), ident)

    @staticmethod
    def _find(
        records: dict[str, SecurityTestCase], ident: str
    ) -> Optional[SecurityTestCase]:
        ident = (ident or "").strip()
        if not ident:
            return None
        for t in records.values():
            if ident in (t.id, t.fingerprint):
                return t
        low = ident.lower()
        for t in records.values():
            if t.id.lower().endswith(low) or t.fingerprint.lower().startswith(low):
                return t
        return None


# =====================================================================rendering
def render_finding_list(records: list[FindingRecord]) -> str:
    """A compact, one-line-per-finding overview of the durable store."""
    if not records:
        return "No findings recorded yet. Run code_review to populate the store."
    rows = []
    for r in records:
        f = r.as_finding()
        eff = f.effective_status()
        flag = " ⟲ re-surfaced" if r.resurfaced else ""
        n_runs = len(r.runs)
        loc = f.evidence[0].location() if f.evidence else "?"
        rows.append(
            f"{f.id}  [{f.severity:<8}] {eff:<14} c={f.confidence:.2f} "
            f"runs={n_runs}  {f.title[:48]}  @ {loc}{flag}"
        )
    header = (
        f"{len(records)} finding(s) — id / severity / effective-status / confidence:\n"
    )
    return header + "\n".join(rows)


def render_finding_detail(rec: FindingRecord) -> str:
    """Full detail for one finding: the finding + its history and notes."""
    f = rec.as_finding()
    parts = [
        f.to_markdown(),
        "",
        "---",
        f"First seen: {rec.first_seen}   Last seen: {rec.last_seen}   "
        f"Runs: {len(rec.runs)}",
    ]
    if rec.resurfaced:
        parts.append(
            "**⟲ Re-surfaced** — evidence changed materially since a "
            "prior human verdict; needs re-triage."
        )
    if rec.history:
        parts.append("\nStatus history:")
        for h in rec.history:
            note = f" — {h['note']}" if h.get("note") else ""
            fld = f" [{h['field']}]" if h.get("field") else ""
            parts.append(
                f"- {h['ts']}  {h['actor']}: {h['change']}"
                f"{fld} → {h.get('to', '')}{note}"
            )
    if rec.notes:
        parts.append("\nReviewer notes:")
        for n in rec.notes:
            parts.append(f"- {n['ts']}  {n['text']}")
    return "\n".join(parts)


_STATUS_MARK = {"new": "☐", "in_progress": "◐", "complete": "☑"}


def render_test_case_list(cases: list["SecurityTestCase"]) -> str:
    """A compact checklist view — the operator's work list, in authoring order."""
    if not cases:
        return (
            "No test cases recorded yet. Run test_case to author them, or add "
            "one by hand with /testcase-add."
        )
    rows = []
    for tc in cases:
        mark = _STATUS_MARK.get(tc.status, "☐")
        link = tc.finding_id or tc.threat_ref or "—"
        result = f" [{tc.result}]" if tc.result else ""
        rows.append(
            f"{mark} {tc.id}  [{tc.severity:<8}] {tc.status:<12}"
            f"{result:<14} {tc.title[:46]:<46}  verifies {link}"
        )
    done = sum(1 for t in cases if t.status == "complete")
    doing = sum(1 for t in cases if t.status == "in_progress")
    header = (
        f"{len(cases)} test case(s) — {done} complete, {doing} in progress, "
        f"{len(cases) - done - doing} new:\n"
    )
    return header + "\n".join(rows)


def render_test_case_detail(tc: "SecurityTestCase") -> str:
    """Full detail for one test case, plus where it came from."""
    origin = tc.source_agent or "added by hand"
    return "\n".join(
        [
            tc.to_markdown(),
            "",
            "---",
            f"Origin: {origin}   Created: {tc.created_at.isoformat(timespec='seconds')}"
            f"   Updated: {tc.updated_at.isoformat(timespec='seconds')}",
        ]
    )
