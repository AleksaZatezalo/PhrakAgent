"""
Description: Structured security-finding & taint-path models.
Author: Aleksa Zatezalo
Date Created: 07-31-2026
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

# --------------------------------------------------------------- vocabularies
SEVERITIES = ("critical", "high", "medium", "low", "info")

# A finding's lifecycle status.
STATUSES = (
    "new", "confirmed", "unconfirmed", "false_positive", "accepted_risk", "fixed",
)

# How much of a taint path we actually established.
COMPLETENESS = (
    "complete", "partial", "approximate", "runtime_confirmed", "invalidated",
)

# The technique that produced a taint result — never overstate precision.
ANALYSIS_MODES = (
    "syntactic", "intra_procedural", "inter_procedural",
    "framework_assisted", "hybrid_static", "runtime_confirmed",
)

TAINT_NODE_KINDS = ("source", "sink", "propagator", "sanitizer")

EVIDENCE_TYPES = (
    "source_reference", "taint_step", "sanitizer", "analyzer_hit",
    "runtime_observation", "config", "test", "note",
)

# Allowed status transitions. Human triage may move a finding anywhere, but the
# automated pipeline is constrained to these edges.
_STATUS_TRANSITIONS: dict[str, set[str]] = {
    "new": {"new", "confirmed", "unconfirmed", "false_positive", "accepted_risk"},
    "unconfirmed": {"unconfirmed", "confirmed", "false_positive", "accepted_risk"},
    "confirmed": {"confirmed", "fixed", "accepted_risk", "false_positive"},
    "false_positive": {"false_positive", "unconfirmed", "confirmed"},
    "accepted_risk": {"accepted_risk", "confirmed", "fixed"},
    "fixed": {"fixed", "unconfirmed", "confirmed"},
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _norm(text: str | None) -> str:
    """Normalize free text for stable fingerprints (lowercase, collapse spaces)."""
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def status_transition_allowed(current: str, new: str) -> bool:
    if new not in STATUSES:
        return False
    return new in _STATUS_TRANSITIONS.get(current, set())


# ------------------------------------------------------------------- taint models
@dataclass
class TaintNode:
    """A source, sink, propagator, or sanitizer location."""

    path: str = ""
    line: int | None = None
    symbol: str | None = None
    expression: str | None = None
    kind: str = "source"                    # one of TAINT_NODE_KINDS

    def label(self) -> str:
        loc = self.path + (f":{self.line}" if self.line else "")
        expr = f" — {self.expression}" if self.expression else ""
        return f"{loc}{expr}".strip(" —")


@dataclass
class TaintStep:
    """One propagation hop along a taint path."""

    path: str = ""
    line: int | None = None
    symbol: str | None = None
    operation: str = ""                     # e.g. "assignment", "call", "return"
    from_expression: str | None = None
    to_expression: str | None = None

    def label(self) -> str:
        loc = self.path + (f":{self.line}" if self.line else "")
        op = f" — {self.operation}" if self.operation else ""
        return f"{loc}{op}"


@dataclass
class TaintPathReference:
    """A serializable source->sink taint path with its provenance."""

    id: str = ""
    source: TaintNode = field(default_factory=TaintNode)
    sink: TaintNode = field(default_factory=lambda: TaintNode(kind="sink"))
    steps: list[TaintStep] = field(default_factory=list)
    sanitizers_encountered: list[TaintNode] = field(default_factory=list)
    sanitizers_bypassed: list[TaintNode] = field(default_factory=list)
    confidence: float = 0.0
    completeness: str = "partial"           # one of COMPLETENESS
    analysis_mode: str = "syntactic"        # one of ANALYSIS_MODES

    def compute_id(self) -> str:
        basis = "|".join([
            _norm(self.source.path), str(self.source.line or ""),
            _norm(self.sink.path), str(self.sink.line or ""),
            _norm(self.source.expression), _norm(self.sink.expression),
        ])
        return "TP-" + hashlib.sha256(basis.encode()).hexdigest()[:12]

    def ensure_id(self) -> str:
        if not self.id:
            self.id = self.compute_id()
        return self.id

    def is_supporting(self) -> bool:
        """True when the path corroborates (not refutes) exploitability."""
        return self.completeness in ("complete", "runtime_confirmed")

    def to_markdown(self) -> str:
        lines = [
            f"**Taint path** `{self.id or self.compute_id()}` "
            f"(mode: {self.analysis_mode}, completeness: {self.completeness}, "
            f"confidence: {self.confidence:.2f})",
            "",
            f"Source:\n- {self.source.label()}",
            "",
            f"Sink:\n- {self.sink.label()}",
        ]
        if self.steps:
            lines.append("")
            lines.append("Steps:")
            for i, s in enumerate(self.steps, 1):
                lines.append(f"{i}. {s.label()}")
        san = self.sanitizers_encountered
        lines.append("")
        if san:
            bypassed = {id(x) for x in self.sanitizers_bypassed}
            lines.append("Sanitizers:")
            for s in san:
                note = " (bypassed / ineffective)" if id(s) in bypassed else " (effective)"
                lines.append(f"- {s.label()}{note}")
        else:
            lines.append("Sanitizers:\n- None observed")
        return "\n".join(lines)


# --------------------------------------------------------------- evidence model
@dataclass
class FindingEvidence:
    path: str = ""
    start_line: int | None = None
    end_line: int | None = None
    symbol: str | None = None
    snippet: str | None = None
    reason: str = ""
    evidence_type: str = "source_reference"   # one of EVIDENCE_TYPES

    def location(self) -> str:
        if self.start_line and self.end_line and self.end_line != self.start_line:
            return f"{self.path}:{self.start_line}-{self.end_line}"
        if self.start_line:
            return f"{self.path}:{self.start_line}"
        return self.path


# --------------------------------------------------------------- finding model
@dataclass
class SecurityFinding:
    title: str = ""
    description: str = ""
    category: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    status: str = "new"
    impact: str = ""
    recommendation: str = ""
    id: str = ""
    fingerprint: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    owasp_categories: list[str] = field(default_factory=list)
    affected_files: list[str] = field(default_factory=list)
    affected_symbols: list[str] = field(default_factory=list)
    evidence: list[FindingEvidence] = field(default_factory=list)
    taint_paths: list[TaintPathReference] = field(default_factory=list)
    attack_scenario: str | None = None
    references: list[str] = field(default_factory=list)
    source_agent: str = ""
    source_tools: list[str] = field(default_factory=list)
    # what would disprove this finding (spec §3 requirement)
    disproof: str = ""
    # Separate assessment tracks (Phase 7) — kept apart for auditability so a
    # runtime result or human decision is never conflated with the reporting
    # agent's original claim. ``status`` remains the agent's asserted status
    # (back-compat); ``effective_status`` folds the tracks together with human
    # precedence.
    runtime_status: str = ""      # from a live test / runtime correlation
    human_status: str = ""        # human triage — highest precedence
    created_at: datetime = field(default_factory=_now)
    updated_at: datetime = field(default_factory=_now)

    # -- fingerprint / id ----------------------------------------------------
    def compute_fingerprint(self) -> str:
        """Stable across runs for the *same* vulnerability (for history/dedup)."""
        src = self.taint_paths[0].source if self.taint_paths else None
        sink = self.taint_paths[0].sink if self.taint_paths else None
        first_ev = self.evidence[0] if self.evidence else None
        basis = "|".join([
            _norm(self.category),
            _norm(src.path) if src else (first_ev.path if first_ev else ""),
            str((src.line if src else None) or ""),
            _norm(sink.path) if sink else "",
            str((sink.line if sink else None) or ""),
            _norm(self.affected_symbols[0]) if self.affected_symbols else "",
            _norm(self.title),
        ])
        return hashlib.sha256(basis.encode()).hexdigest()[:16]

    def ensure_identity(self) -> "SecurityFinding":
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()
        if not self.id:
            self.id = f"FND-{self.fingerprint[:10]}"
        for tp in self.taint_paths:
            tp.ensure_id()
        return self

    # -- data-flow support state --------------------------------------------
    def has_supporting_taint_path(self) -> bool:
        return any(tp.is_supporting() for tp in self.taint_paths)

    def is_dataflow_category(self) -> bool:
        cat = _norm(self.category)
        return any(k in cat for k in (
            "injection", "traversal", "ssrf", "deserial", "xss", "command",
            "sql", "template", "redirect", "ldap", "xpath",
        ))

    # -- multi-track status --------------------------------------------------
    @property
    def agent_status(self) -> str:
        """The reporting agent's asserted status (alias of ``status``)."""
        return self.status

    def effective_status(self) -> str:
        """Fold the separate assessment tracks into one status.

        Precedence (highest first): human triage, then runtime observation (an
        actual local execution), then the reporting agent. Empty tracks are
        skipped — a track only counts once someone/something has recorded a
        verdict on it.
        """
        for s in (self.human_status, self.runtime_status, self.status):
            if s:
                return s
        return "new"

    # -- serialization -------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        self.ensure_identity()
        d = asdict(self)
        d["created_at"] = self.created_at.isoformat()
        d["updated_at"] = self.updated_at.isoformat()
        return d

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SecurityFinding":
        raw = dict(raw or {})
        ev = [FindingEvidence(**e) for e in raw.pop("evidence", []) or []]
        tps = [_taint_from_dict(t) for t in raw.pop("taint_paths", []) or []]
        for key in ("created_at", "updated_at"):
            if isinstance(raw.get(key), str):
                try:
                    raw[key] = datetime.fromisoformat(raw[key])
                except ValueError:
                    raw[key] = _now()
        allowed = {f.name for f in cls.__dataclass_fields__.values()}
        raw = {k: v for k, v in raw.items() if k in allowed}
        return cls(evidence=ev, taint_paths=tps, **raw)

    # -- rendering -----------------------------------------------------------
    def to_markdown(self) -> str:
        self.ensure_identity()
        cwe = ", ".join(self.cwe_ids) or "—"
        out = [
            f"### {self.title or '(untitled finding)'}  `{self.id}`",
            "",
            f"Severity: {self.severity.title()}",
            f"Confidence: {self.confidence:.2f}",
            f"Status: {self.status.replace('_', ' ').title()}",
            f"CWE: {cwe}",
        ]
        eff = self.effective_status()
        if eff != self.status or self.runtime_status or self.human_status:
            tracks = []
            for label, val in (("agent", self.status),
                               ("runtime", self.runtime_status),
                               ("human", self.human_status)):
                if val:
                    tracks.append(f"{label}={val.replace('_', ' ')}")
            out.append(
                f"Effective status: {eff.replace('_', ' ').title()} "
                f"({', '.join(tracks)})"
            )
        if self.owasp_categories:
            out.append(f"OWASP: {', '.join(self.owasp_categories)}")
        if self.taint_paths:
            tp = self.taint_paths[0]
            out += [
                "",
                f"Source:\n- {tp.source.label()}",
                "",
                f"Sink:\n- {tp.sink.label()}",
            ]
            if tp.steps:
                out.append("")
                out.append("Taint path:")
                for i, s in enumerate(tp.steps, 1):
                    out.append(f"{i}. {s.label()}")
            san = tp.sanitizers_encountered
            out.append("")
            out.append("Sanitizers:")
            out += ([f"- {s.label()}" for s in san] if san else ["- None observed"])
        else:
            out += ["", "Taint path: none analyzed"]
        if self.evidence:
            out.append("")
            out.append("Evidence:")
            for e in self.evidence:
                reason = f" — {e.reason}" if e.reason else ""
                out.append(f"- {e.location()}{reason}")
        if self.description:
            out += ["", self.description]
        if self.impact:
            out += ["", f"**Impact:** {self.impact}"]
        if self.recommendation:
            out += ["", f"**Recommendation:** {self.recommendation}"]
        if self.disproof:
            out += ["", f"**Would disprove:** {self.disproof}"]
        return "\n".join(out)


def _taint_from_dict(raw: dict) -> TaintPathReference:
    raw = dict(raw or {})
    src = TaintNode(**(raw.pop("source", {}) or {}))
    sink = TaintNode(**(raw.pop("sink", {}) or {}))
    steps = [TaintStep(**s) for s in raw.pop("steps", []) or []]
    enc = [TaintNode(**n) for n in raw.pop("sanitizers_encountered", []) or []]
    byp = [TaintNode(**n) for n in raw.pop("sanitizers_bypassed", []) or []]
    allowed = {f.name for f in TaintPathReference.__dataclass_fields__.values()}
    raw = {k: v for k, v in raw.items() if k in allowed}
    return TaintPathReference(
        source=src, sink=sink, steps=steps,
        sanitizers_encountered=enc, sanitizers_bypassed=byp, **raw,
    )


# --------------------------------------------------------------- validation
def validate_finding(f: SecurityFinding) -> list[str]:
    """Structural validation. Returns a list of human-readable errors (empty=ok)."""
    errs: list[str] = []
    if not f.title:
        errs.append("title is required")
    if f.severity not in SEVERITIES:
        errs.append(f"invalid severity {f.severity!r} (allowed: {SEVERITIES})")
    if f.status not in STATUSES:
        errs.append(f"invalid status {f.status!r} (allowed: {STATUSES})")
    if not (0.0 <= f.confidence <= 1.0):
        errs.append(f"confidence {f.confidence} out of range [0.0, 1.0]")
    if not f.evidence and not f.taint_paths:
        errs.append("finding has no evidence and no taint path")
    for i, tp in enumerate(f.taint_paths):
        if tp.completeness not in COMPLETENESS:
            errs.append(f"taint_paths[{i}].completeness invalid: {tp.completeness!r}")
        if tp.analysis_mode not in ANALYSIS_MODES:
            errs.append(f"taint_paths[{i}].analysis_mode invalid: {tp.analysis_mode!r}")
        if not (0.0 <= tp.confidence <= 1.0):
            errs.append(f"taint_paths[{i}].confidence out of range")
    for i, ev in enumerate(f.evidence):
        if ev.evidence_type not in EVIDENCE_TYPES:
            errs.append(f"evidence[{i}].evidence_type invalid: {ev.evidence_type!r}")
    # A data-flow finding must not be 'confirmed' on LLM say-so alone.
    if (f.status == "confirmed" and f.is_dataflow_category()
            and not f.has_supporting_taint_path()):
        errs.append(
            "data-flow finding marked 'confirmed' without a complete or "
            "runtime-confirmed taint path"
        )
    return errs


def validate_against_workspace(f: SecurityFinding, root) -> list[str]:
    """Ground evidence in the actual repo: paths inside workspace, valid lines,
    snippets approximately matching source. Returns errors (empty = ok)."""
    from pathlib import Path

    root = Path(root).resolve()
    errs: list[str] = []

    def _check(path: str, start: int | None, end: int | None, snippet: str | None,
               where: str) -> None:
        if not path:
            errs.append(f"{where}: empty path")
            return
        p = (root / path).resolve() if not Path(path).is_absolute() else Path(path)
        if root != p and root not in p.parents:
            errs.append(f"{where}: path escapes workspace: {path}")
            return
        if not p.is_file():
            errs.append(f"{where}: file not found in workspace: {path}")
            return
        try:
            lines = p.read_text(errors="replace").splitlines()
        except OSError:
            errs.append(f"{where}: cannot read {path}")
            return
        n = len(lines)
        for lbl, ln in (("start_line", start), ("end_line", end)):
            if ln is not None and not (1 <= ln <= n):
                errs.append(f"{where}: {lbl} {ln} out of range 1..{n} in {path}")
        if snippet and start and 1 <= start <= n:
            window = "\n".join(lines[max(0, start - 2): min(n, (end or start) + 1)])
            if _norm(snippet)[:40] and _norm(snippet)[:40] not in _norm(window):
                errs.append(f"{where}: snippet does not match source at {path}:{start}")

    for i, ev in enumerate(f.evidence):
        _check(ev.path, ev.start_line, ev.end_line, ev.snippet, f"evidence[{i}]")
    for i, tp in enumerate(f.taint_paths):
        if tp.source.path:
            _check(tp.source.path, tp.source.line, tp.source.line, None,
                   f"taint_paths[{i}].source")
        if tp.sink.path:
            _check(tp.sink.path, tp.sink.line, tp.sink.line, None,
                   f"taint_paths[{i}].sink")
    return errs


# --------------------------------------------------------------- deduplication
def dedupe_findings(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    """Collapse findings sharing a fingerprint, keeping the highest-confidence one
    and unioning their evidence, taint paths, tools, CWEs, and OWASP tags."""
    by_fp: dict[str, SecurityFinding] = {}
    for f in findings:
        f.ensure_identity()
        keep = by_fp.get(f.fingerprint)
        if keep is None:
            by_fp[f.fingerprint] = f
            continue
        winner = keep if keep.confidence >= f.confidence else f
        other = f if winner is keep else keep
        winner.evidence = _union(winner.evidence, other.evidence, key=lambda e: e.location())
        winner.taint_paths = _union(
            winner.taint_paths, other.taint_paths, key=lambda t: t.ensure_id()
        )
        winner.cwe_ids = sorted(set(winner.cwe_ids) | set(other.cwe_ids))
        winner.owasp_categories = sorted(
            set(winner.owasp_categories) | set(other.owasp_categories)
        )
        winner.source_tools = sorted(set(winner.source_tools) | set(other.source_tools))
        by_fp[f.fingerprint] = winner
    return list(by_fp.values())


def _union(a: list, b: list, key) -> list:
    seen = {key(x) for x in a}
    return a + [x for x in b if key(x) not in seen]
