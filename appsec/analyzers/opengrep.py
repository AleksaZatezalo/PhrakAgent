"""
Description: Opengrep adapter — normalizes Opengrep JSON leads into SecurityFindings.
Author: Aleksa Zatezalo
Date Created: 07-31-2026
"""

from __future__ import annotations

import shutil
from pathlib import Path

from ..models.findings import FindingEvidence, SecurityFinding
from ..tools.common import workspace
from ..tools.opengrep_tools import (
    DEFAULT_CONFIG,
    _format,
    _opengrep_bin,
    _run,
)
from .base import ANALYZER_LEAD_MAX_CONFIDENCE, AnalyzerResult, clamp, extract_cwe

# Opengrep/Semgrep severities → PHRAK severities.
_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
# Opengrep metadata confidence → a numeric lead confidence (always a lead, so low).
_CONFIDENCE = {"HIGH": 0.6, "MEDIUM": 0.5, "LOW": 0.4}


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


def normalize(
    data: dict, root: Path, config: str = DEFAULT_CONFIG
) -> list[SecurityFinding]:
    """Turn Opengrep ``--json`` output into unconfirmed SecurityFinding leads."""
    findings: list[SecurityFinding] = []
    for r in data.get("results", []):
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        path = _relpath(r.get("path", ""), root)
        start = r.get("start", {}).get("line")
        end = r.get("end", {}).get("line") or start
        check = (r.get("check_id", "") or "").split(".")[-1]
        message = " ".join((extra.get("message", "") or "").split())
        severity = _SEVERITY.get(extra.get("severity", ""), "medium")
        confidence = clamp(
            _CONFIDENCE.get(str(meta.get("confidence", "")).upper(), 0.5),
            ANALYZER_LEAD_MAX_CONFIDENCE,
        )
        title = message[:120] or check or "opengrep finding"
        finding = SecurityFinding(
            title=title,
            description=message,
            # the rule short-name carries the vuln class (e.g. "sql-injection"),
            # which SecurityFinding.is_dataflow_category() keys off of.
            category=check or "static-analysis",
            severity=severity,
            confidence=confidence,
            status="unconfirmed",  # a pattern hit is a lead, never confirmed
            cwe_ids=extract_cwe(meta.get("cwe"), check, message),
            owasp_categories=_owasp(meta),
            affected_files=[path] if path else [],
            evidence=[
                FindingEvidence(
                    path=path,
                    start_line=start if isinstance(start, int) else None,
                    end_line=end if isinstance(end, int) else None,
                    reason=message[:200],
                    evidence_type="analyzer_hit",
                )
            ],
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
