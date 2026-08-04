"""
Description: Deterministic analyzer adapters.
Author: Aleksa Zatezalo
Date Created: 07-30-2026
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
