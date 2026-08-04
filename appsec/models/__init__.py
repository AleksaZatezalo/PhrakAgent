"""Structured data models shared across PHRAK (findings, taint paths)."""

from __future__ import annotations

from .findings import (
    ANALYSIS_MODES,
    COMPLETENESS,
    EVIDENCE_TYPES,
    SEVERITIES,
    STATUSES,
    TAINT_NODE_KINDS,
    FindingEvidence,
    SecurityFinding,
    TaintNode,
    TaintPathReference,
    TaintStep,
    dedupe_findings,
    status_transition_allowed,
    validate_against_workspace,
    validate_finding,
)

__all__ = [
    "SecurityFinding",
    "FindingEvidence",
    "TaintPathReference",
    "TaintNode",
    "TaintStep",
    "validate_finding",
    "validate_against_workspace",
    "dedupe_findings",
    "status_transition_allowed",
    "SEVERITIES",
    "STATUSES",
    "COMPLETENESS",
    "ANALYSIS_MODES",
    "TAINT_NODE_KINDS",
    "EVIDENCE_TYPES",
]
