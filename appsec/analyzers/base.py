"""
Description: AnalyzerAdapter protocol + shared normalization plumbing.
Author: Aleksa Zatezalo
Date Created: 07-30-2026
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ..models.findings import (
    SecurityFinding,
    dedupe_findings,
    validate_against_workspace,
    validate_finding,
)

# Analyzer leads are unverified by construction: cap their confidence so a raw
# pattern hit never outranks a human/agent-confirmed finding during dedup.
ANALYZER_LEAD_MAX_CONFIDENCE = 0.6
UNGROUNDED_MAX_CONFIDENCE = 0.4

_CWE_RE = re.compile(r"CWE[-\s]?(\d+)", re.IGNORECASE)


@dataclass
class AnalyzerResult:
    """Outcome of running one analyzer over a path."""

    tool: str
    findings: list[SecurityFinding] = field(default_factory=list)
    summary: str = ""
    error: str | None = None
    available: bool = True


@runtime_checkable
class AnalyzerAdapter(Protocol):
    """A deterministic analyzer normalized into the finding pipeline."""

    name: str

    def is_available(self) -> bool:
        """True when the underlying binary is installed / on PATH."""
        ...

    def supports(self, path: str) -> bool:
        """True when this analyzer has something to analyze under ``path``."""
        ...

    def run(self, path: str) -> AnalyzerResult:
        """Scan ``path`` and return normalized findings (never raises)."""
        ...


# --------------------------------------------------------------- helpers
def extract_cwe(*texts: object) -> list[str]:
    """Pull ``CWE-<n>`` ids out of arbitrary metadata (strings / lists / dicts)."""
    found: list[str] = []
    for t in texts:
        for s in _flatten_strings(t):
            for m in _CWE_RE.finditer(s):
                cwe = f"CWE-{m.group(1)}"
                if cwe not in found:
                    found.append(cwe)
    return found


def _flatten_strings(obj: object) -> list[str]:
    if obj is None:
        return []
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        out: list[str] = []
        for v in obj.values():
            out += _flatten_strings(v)
        return out
    if isinstance(obj, (list, tuple, set)):
        out = []
        for v in obj:
            out += _flatten_strings(v)
        return out
    return [str(obj)]


def clamp(value: float, hi: float) -> float:
    return max(0.0, min(value, hi))


def finalize_findings(findings: list[SecurityFinding], root) -> list[SecurityFinding]:
    """Validate → ground (downgrade) → dedupe. Structurally-invalid ones are
    dropped (an analyzer we can't trust to be well-formed shouldn't inject noise).
    """
    out: list[SecurityFinding] = []
    for f in findings:
        f.ensure_identity()
        if validate_finding(f):
            continue  # malformed normalization — skip rather than record garbage
        if validate_against_workspace(f, root):
            f.status = "unconfirmed"
            f.confidence = clamp(f.confidence, UNGROUNDED_MAX_CONFIDENCE)
            f.ensure_identity()
        out.append(f)
    return dedupe_findings(out)
