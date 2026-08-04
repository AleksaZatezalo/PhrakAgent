"""
Description: Persistent finding & taint-path history (Phase 7).
Author: Aleksa Zatezalo
Date Created: 07-31-2026
"""

from __future__ import annotations

import json
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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r, default=str) for r in records) + "\n")


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
        """
        ts = ts or _now_iso()
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
        ts = ts or _now_iso()
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
