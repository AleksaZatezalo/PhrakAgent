"""
Description: generate_report agent — assembles the full assessment into one report.
Author: Aleksa Zatezalo
Date Created: 08-18-2026

Unlike the analysis agents, this one has no tool-calling loop. Its body is
assembled deterministically from artifacts that already exist — the latest
threat_model and code_review reports, the finding store, and the test-case
backlog — and a model writes only the executive summary. See appsec/report.py.
"""

from __future__ import annotations

from ..base_agent import AgentSpec, register_agent
from ..report import build_consolidated_report

DESCRIPTION = (
    "Assembles the executive summary, threat model, code review, findings, and "
    "test cases already produced for this workspace into one report."
)

register_agent(
    AgentSpec(
        name="generate_report",
        description=DESCRIPTION,
        # Kept for the registry/catalog; the runner never sends it to a model.
        system_prompt=(
            "Assembles a consolidated assessment report from stored artifacts. "
            "Writes only the executive summary; every other section is quoted "
            "verbatim from the run that produced it."
        ),
        tool_factory=lambda: [],
        tags=["reporting", "summary", "deliverable"],
        runner=build_consolidated_report,
        # Deliberate invocation only: scheduled mid-run it would report on
        # findings that had not been made yet.
        plannable=False,
    )
)
