"""
Description: Opengrep adapter — normalizes Opengrep JSON leads into SecurityFindings.
Author: Aleksa Zatezalo
Date Created: 07-31-2026

Taint-mode results (rules with ``mode: taint``) carry a ``dataflow_trace``
section with the full source → intermediate-vars → sink chain. When present,
the adapter lifts that chain into a supporting :class:`TaintPathReference`
attached to the finding, promotes confidence, and marks status ``confirmed``
(the finding is grounded in an actual dataflow chain, not just a pattern hit).
"""

from __future__ import annotations

import shutil
from pathlib import Path

from ..models.findings import (
    FindingEvidence,
    SecurityFinding,
    TaintNode,
    TaintPathReference,
    TaintStep,
)
from ..tools.common import workspace
from ..tools.opengrep_tools import (
    DEFAULT_CONFIG,
    DEFAULT_TAINT_CONFIG,
    _format,
    _opengrep_bin,
    _run,
)
from .base import ANALYZER_LEAD_MAX_CONFIDENCE, AnalyzerResult, clamp, extract_cwe

# OpenGrep severities → PHRAK severities.
_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
# Opengrep metadata confidence → a numeric lead confidence (always a lead, so low).
_CONFIDENCE = {"HIGH": 0.6, "MEDIUM": 0.5, "LOW": 0.4}
# When a taint-mode dataflow_trace is present, we have real source→sink
# evidence — clamp confidence higher than a bare pattern lead.
_TAINT_CONFIDENCE = {"HIGH": 0.9, "MEDIUM": 0.8, "LOW": 0.7}


def _relpath(p: str, root: Path) -> str:
    try:
        return str(Path(p).resolve().relative_to(root))
    except ValueError:
        return p


def _owasp(meta: dict) -> list[str]:
    raw = meta.get("owasp")
    if not raw:
        return []
    if isinstance(raw, str):
        raw = [raw]
    return [" ".join(str(x).split()) for x in raw if str(x).strip()]


def _cliloc_location(entry) -> tuple[str, int | None, str | None]:
    """Extract (path, line, content) from a Opengrep ``CliLoc`` tuple.

    Shape: ``["CliLoc", [{"path":..., "start":{"line":N,...}, ...}, "content"]]``.
    Returns ('', None, None) if the structure isn't what we expect (defensive —
    Opengrep's JSON format has shifted before).
    """
    if not isinstance(entry, list) or len(entry) < 2:
        return "", None, None
    inner = entry[1]
    if not isinstance(inner, list) or not inner:
        return "", None, None
    loc = inner[0] if isinstance(inner[0], dict) else {}
    content = inner[1] if len(inner) > 1 and isinstance(inner[1], str) else None
    line = None
    start = loc.get("start")
    if isinstance(start, dict):
        ln = start.get("line")
        if isinstance(ln, int):
            line = ln
    return loc.get("path", "") or "", line, content


def _dataflow_to_taint(
    trace: dict, root: Path, confidence: float
) -> TaintPathReference | None:
    """Lift Opengrep's ``dataflow_trace`` into a TaintPathReference.

    Opengrep OSS gives us the source, sink, and the intermediate variables it
    tracked between them. We record this as ``analysis_mode: intra_procedural``
    (Opengrep OSS is single-file dataflow; the paid ``interfile_languages_used``
    key would tell us otherwise), ``completeness: complete`` because we have
    both endpoints, and preserve intermediate hops as :class:`TaintStep`\\s.
    """
    if not isinstance(trace, dict):
        return None
    src_path, src_line, src_expr = _cliloc_location(trace.get("taint_source"))
    sink_path, sink_line, sink_expr = _cliloc_location(trace.get("taint_sink"))
    if not src_path or not sink_path:
        return None

    src_rel = _relpath(src_path, root)
    sink_rel = _relpath(sink_path, root)

    steps: list[TaintStep] = []
    for iv in trace.get("intermediate_vars") or []:
        if not isinstance(iv, dict):
            continue
        loc = iv.get("location") or {}
        p = loc.get("path", "")
        ln_dict = loc.get("start") or {}
        ln = ln_dict.get("line") if isinstance(ln_dict, dict) else None
        symbol = iv.get("content") if isinstance(iv.get("content"), str) else None
        steps.append(
            TaintStep(
                path=_relpath(p, root) if p else src_rel,
                line=ln if isinstance(ln, int) else None,
                symbol=symbol,
                operation="propagation",
            )
        )

    tp = TaintPathReference(
        source=TaintNode(
            path=src_rel, line=src_line, expression=src_expr, kind="source"
        ),
        sink=TaintNode(
            path=sink_rel, line=sink_line, expression=sink_expr, kind="sink"
        ),
        steps=steps,
        confidence=confidence,
        completeness="complete",
        analysis_mode="intra_procedural",
    )
    tp.ensure_id()
    return tp


def normalize(
    data: dict, root: Path, config: str = DEFAULT_CONFIG
) -> list[SecurityFinding]:
    """Turn Opengrep ``--json`` output into SecurityFindings.

    Pattern hits become ``unconfirmed`` leads (max confidence capped). Taint
    hits (``mode: taint`` rules, which carry a ``dataflow_trace``) become
    ``confirmed`` findings with a supporting :class:`TaintPathReference`.
    """
    findings: list[SecurityFinding] = []
    for r in data.get("results", []):
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        trace = extra.get("dataflow_trace")
        path = _relpath(r.get("path", ""), root)
        start = r.get("start", {}).get("line")
        end = r.get("end", {}).get("line") or start
        check = (r.get("check_id", "") or "").split(".")[-1]
        message = " ".join((extra.get("message", "") or "").split())
        severity = _SEVERITY.get(extra.get("severity", ""), "medium")
        # Category from rule metadata beats the check-id when present — lets
        # SecurityFinding.is_dataflow_category() key off a normalized label.
        category = str(meta.get("category") or check or "static-analysis")

        raw_conf = str(meta.get("confidence", "")).upper()
        if trace:
            confidence = _TAINT_CONFIDENCE.get(raw_conf, 0.8)
            status = "confirmed"
        else:
            confidence = clamp(
                _CONFIDENCE.get(raw_conf, 0.5),
                ANALYZER_LEAD_MAX_CONFIDENCE,
            )
            status = "unconfirmed"

        taint_path = _dataflow_to_taint(trace, root, confidence) if trace else None
        taint_paths = [taint_path] if taint_path is not None else []

        # If we built a taint path, prefer the source as the finding location
        # (the untrusted input) — matches PHRAK's report_finding convention.
        loc_path = path
        loc_start = start if isinstance(start, int) else None
        loc_end = end if isinstance(end, int) else None
        if taint_path is not None:
            loc_path = taint_path.source.path or path
            loc_start = taint_path.source.line or loc_start
            loc_end = taint_path.source.line or loc_end

        title = message[:120] or check or "opengrep finding"
        finding = SecurityFinding(
            title=title,
            description=message,
            category=category,
            severity=severity,
            confidence=confidence,
            status=status,
            cwe_ids=extract_cwe(meta.get("cwe"), check, message),
            owasp_categories=_owasp(meta),
            affected_files=[path] if path else [],
            evidence=[
                FindingEvidence(
                    path=loc_path,
                    start_line=loc_start,
                    end_line=loc_end,
                    reason=message[:200],
                    evidence_type=(
                        "taint_step" if taint_path is not None else "analyzer_hit"
                    ),
                )
            ],
            taint_paths=taint_paths,
            source_tools=["opengrep"],
            source_agent="opengrep",
        ).ensure_identity()
        findings.append(finding)
    return findings


class OpengrepAdapter:
    """Opengrep as an AnalyzerAdapter (pattern-based SAST leads)."""

    name = "opengrep"

    def is_available(self) -> bool:
        return shutil.which(_opengrep_bin()) is not None

    def supports(self, path: str) -> bool:  # noqa: ARG002 - language-agnostic
        return True

    def run(self, path: str = ".", config: str = DEFAULT_CONFIG) -> AnalyzerResult:
        data, err = _run(path, config)
        if err:
            return AnalyzerResult(
                tool=self.name, error=err, available=self.is_available()
            )
        root = workspace()
        return AnalyzerResult(
            tool=self.name,
            findings=normalize(data, root, config),
            summary=_format(data, config),
        )

    def run_taint(self, path: str = ".") -> AnalyzerResult:
        """Convenience: run PHRAK's bundled taint ruleset."""
        return self.run(path=path, config=DEFAULT_TAINT_CONFIG)
