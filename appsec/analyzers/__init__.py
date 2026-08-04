"""Deterministic analyzer adapters.

Each adapter implements the :class:`AnalyzerAdapter` protocol
(``is_available`` / ``supports`` / ``run``) and **normalizes** its native output
into :class:`~appsec.models.findings.SecurityFinding` objects, so analyzer results
flow through the exact same validate → ground → dedup → record path as findings an
agent reports by hand (instead of being opaque text leads).

Adapters:
* :class:`~appsec.analyzers.opengrep.OpengrepAdapter` — pattern-based SAST leads.
* :class:`~appsec.analyzers.dependencies.DependencyAuditAdapter` — known-vulnerable
  dependency versions (pip-audit / npm audit / govulncheck / cargo audit).

The sanitizer-effectiveness table (:mod:`appsec.analyzers.sanitizers`) is a
companion used to avoid *false-sanitizer* assumptions when reasoning about a lead.
"""

from __future__ import annotations

from .base import AnalyzerAdapter, AnalyzerResult, finalize_findings
from .dependencies import DependencyAuditAdapter
from .opengrep import OpengrepAdapter

__all__ = [
    "AnalyzerAdapter",
    "AnalyzerResult",
    "finalize_findings",
    "OpengrepAdapter",
    "DependencyAuditAdapter",
]
