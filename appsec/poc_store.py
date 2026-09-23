"""
Description: Durable store for the PoC scripts the verify agent runs. Each PoC is
    saved to ``.phrack/pocs/<POC-id>.<py|sh>`` with a row in ``index.jsonl`` so it
    can be listed (`/poc`), inspected (`/poc POC-…`), and re-run against a live
    target (`/poc-run POC-…`).
Author: Aleksa Zatezalo
Date Created: 09-22-2026
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import Config
from .store import JsonlStore, _exclusive


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _infer_kind(script: str) -> str:
    """python | sh, from a shebang; defaults to python (the common PoC)."""
    first = (script or "").strip().splitlines()[0] if (script or "").strip() else ""
    return "sh" if re.match(r"^#!.*\b(sh|bash|zsh)\b", first) else "python"


@dataclass
class PocRecord:
    id: str
    finding_id: str
    filename: str
    kind: str = "python"  # python | sh
    outcome: str = ""  # confirmed | false_positive | inconclusive | ""
    note: str = ""
    target: str = ""  # last target URL it was run against, if any
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> "PocRecord":
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in (raw or {}).items() if k in allowed})


class PocStore(JsonlStore):
    """PoC scripts + a JSONL index under ``.phrack/pocs``."""

    def __init__(self, config: Config) -> None:
        super().__init__(config, "pocs", "index.jsonl")

    # ------------------------------------------------------------- read path
    def _records(self) -> dict[str, PocRecord]:
        return {
            r.id: r for r in (PocRecord.from_dict(d) for d in self._read()) if r.id
        }

    def list(self) -> list[PocRecord]:
        return sorted(
            self._records().values(), key=lambda r: r.created_at, reverse=True
        )

    def get(self, ident: str) -> Optional[PocRecord]:
        """Resolve ``ident`` to a PoC: exact id, then id-suffix, then finding id."""
        ident = (ident or "").strip()
        if not ident:
            return None
        recs = self._records()
        if ident in recs:
            return recs[ident]
        low = ident.lower()
        for r in recs.values():
            if r.id.lower().endswith(low):
                return r
        # fall back to the most recent PoC for a given finding id
        for r in sorted(recs.values(), key=lambda r: r.created_at, reverse=True):
            if r.finding_id.lower() == low or r.finding_id.lower().endswith(low):
                return r
        return None

    def script_path(self, rec: PocRecord) -> Path:
        return self.dir / rec.filename

    def read_script(self, rec: PocRecord) -> str:
        try:
            return self.script_path(rec).read_text()
        except OSError:
            return ""

    # ------------------------------------------------------------- write path
    def save(
        self,
        finding_id: str,
        script: str,
        *,
        outcome: str = "",
        note: str = "",
        target: str = "",
    ) -> Optional[PocRecord]:
        """Persist a PoC script and index it. Returns the record (None if empty)."""
        script = (script or "").strip()
        if not script:
            return None
        kind = _infer_kind(script)
        ext = "sh" if kind == "sh" else "py"
        created = _now_iso()
        poc_id = "POC-" + hashlib.sha256(
            f"{finding_id}|{created}|{script}".encode()
        ).hexdigest()[:10]
        rec = PocRecord(
            id=poc_id,
            finding_id=finding_id,
            filename=f"{poc_id}.{ext}",
            kind=kind,
            outcome=outcome,
            note=note,
            target=target,
            created_at=created,
        )
        with _exclusive(self.path):
            self.dir.mkdir(parents=True, exist_ok=True)
            (self.dir / rec.filename).write_text(script)
            rows = self._read()
            rows.append(rec.to_dict())
            self._write(rows)
        return rec

    def set_target(self, rec: PocRecord, target: str) -> None:
        """Record the last live target a PoC was run against (best-effort)."""
        with _exclusive(self.path):
            rows = self._read()
            for row in rows:
                if row.get("id") == rec.id:
                    row["target"] = target
                    break
            self._write(rows)


# ------------------------------------------------------------------ rendering
def render_list(records: list[PocRecord]) -> str:
    if not records:
        return (
            "No PoCs recorded yet. Run the verify agent on a finding "
            "(`phrak verify <FND-id>` / `/verify <FND-id>`) to produce one."
        )
    headers = ["poc id", "finding", "kind", "outcome", "created"]
    rows = [
        [r.id, r.finding_id or "—", r.kind, r.outcome or "—", r.created_at]
        for r in records
    ]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt(cells: list[str]) -> str:
        return "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells))

    out = [fmt(headers), "-" * (sum(widths) + 2 * (len(widths) - 1))]
    out += [fmt(r) for r in rows]
    out.append("")
    out.append("`/poc <POC-id>` to view one · `/poc-run <POC-id> <target-url>` to run it")
    return "\n".join(out)


def render_detail(rec: PocRecord, script: str) -> str:
    lang = "bash" if rec.kind == "sh" else "python"
    lines = [
        f"### PoC `{rec.id}`",
        "",
        f"- Finding: `{rec.finding_id or '—'}`",
        f"- Kind: {rec.kind}",
        f"- Outcome: {rec.outcome or '—'}",
        f"- Created: {rec.created_at}",
    ]
    if rec.target:
        lines.append(f"- Last target: {rec.target}")
    if rec.note:
        lines += ["", rec.note]
    lines += ["", f"```{lang}", script or "(script file missing)", "```"]
    return "\n".join(lines)
