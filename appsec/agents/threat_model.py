"""
Description: Threat Modeling agent — STRIDE / DFD-based threat analysis.
Author: Aleksa Zatezalo
Date Created: 07-31-2026
"""

from __future__ import annotations

from ..base_agent import AgentSpec, register_agent
from ..tools.analysis import analysis_tools
from ..tools.analyzer_tools import dependency_audit
from ..tools.filesystem import read_only_tools


def _tools() -> list:
    return read_only_tools() + analysis_tools() + [dependency_audit]


SYSTEM_PROMPT = """You are a threat-modeling expert. Produce a rigorous,
risk-centric (PASTA) and STRIDE-driven threat model for the target system.

You have one curated skill per section, listed under "Your skills" below. Before
you write a section, call load_skill("<name>") to pull its full procedure, then
follow it. Base everything on code you actually read (fingerprint_stack,
analyze_dependencies, read_file, search_code) — never on assumptions.

Work through the sections in the order below and produce the COMPLETE report in a
single pass. Never stop to ask the user to run a tool, load a skill, or paste
code — do it yourself and keep going until every section is written:
1. system-architecture — components, stack, entry points, data stores, and
   numbered trust boundaries.
2. data-flow — a text DFD (entities / processes / stores / flows) overlaying the
   trust boundaries.
3. pasta-threat-analysis — work the 7 PASTA stages to derive threats and the top
   attack paths.
4. threat-details — every threat in a consistent, evidenced table.
5. executive-summary — the leadership summary (write it last, present it first).

Output sections, in this order:
- **Executive Summary**
- **System Architecture** (components / stack / trust boundaries)
- **Data Flow** (DFD)
- **PASTA Threat Analysis** (incl. top 3-5 attack paths)
- **Threat Details** (the per-threat table)
- **Prioritized Recommendations**

Be concrete and tie every threat to a real component. Assume a security-engineer
audience; don't explain what STRIDE/PASTA are.

NEVER ask the user to paste, provide, or upload file contents: you have a
read_file tool, so read the files yourself. If a file is missing, call list_dir
to find the real filenames and read those."""


register_agent(
    AgentSpec(
        name="threat_model",
        description="Builds a STRIDE/DFD threat model: trust boundaries, per-element threats, and prioritized attack paths.",
        system_prompt=SYSTEM_PROMPT,
        tool_factory=_tools,
        tags=["design", "stride", "architecture"],
        # Skill-heavy: front-loading all five procedures + a long report + 7
        # required sections overflows num_ctx and forces re-drive rounds. Inject
        # a one-line skill index and let it load each procedure on demand.
        inline_skills=False,
        report_sections=[
            "executive summary",
            "system architecture|architecture",
            "data flow|dfd",
            "pasta|threat analysis",
            "threat details|threat detail",
            "attack path",
            "recommend",
        ],
    )
)
