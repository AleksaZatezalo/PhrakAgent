"""The ``report_finding`` tool — structured, evidence-grounded findings.

Lets an agent (currently ``code_review``) record a vulnerability as a validated
:class:`~appsec.models.findings.SecurityFinding` instead of only prose. Every
finding is:

* structurally validated (severity/status/confidence/enum checks) — a
  structurally-invalid finding is REJECTED so the model corrects and resubmits;
* grounded in the workspace (evidence path inside the workspace, valid line
  numbers) — a finding whose evidence can't be grounded is still recorded but
  DOWNGRADED to ``unconfirmed`` (we never silently upgrade model claims);
* recorded to the run-scoped collector (:mod:`appsec.runtime`) so the agent loop
  can render/persist/verify them after the run.

The agent still writes its Markdown report; this captures the machine-readable
version alongside it.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..models.findings import (
    FindingEvidence,
    SecurityFinding,
    TaintNode,
    TaintPathReference,
    validate_against_workspace,
    validate_finding,
)
from ..runtime import active_agent, record_finding, require_config
from .common import workspace


def _split(csv: str) -> list[str]:
    return [x.strip() for x in (csv or "").split(",") if x.strip()]


@tool
def report_finding(
    title: str,
    category: str,
    severity: str,
    description: str,
    file: str,
    line: int,
    recommendation: str = "",
    disproof: str = "",
    end_line: int = 0,
    cwe: str = "",
    owasp: str = "",
    confidence: float = 0.5,
    sink_file: str = "",
    sink_line: int = 0,
) -> str:
    """Record ONE confirmed vulnerability as a structured finding (call once per
    distinct issue, after you have READ the code that proves it).

    Required evidence: ``file`` and ``line`` must point at the real vulnerable
    location in the workspace (relative path). Set ``disproof`` to the concrete
    evidence that would make this a false positive. For data-flow bugs (injection,
    traversal, SSRF, deserialization, ...) also give the SINK via ``sink_file`` /
    ``sink_line`` (``file``/``line`` are then treated as the source).

    ``severity`` is one of critical/high/medium/low/info. ``confidence`` is 0.0-1.0.
    ``cwe`` / ``owasp`` are comma-separated (e.g. "CWE-89", "A03:2021-Injection").

    Findings whose evidence can't be located in the workspace are recorded as
    UNCONFIRMED. Returns the finding id + status, or a REJECTED message to fix."""
    ev_end = end_line or line
    evidence = [FindingEvidence(
        path=file, start_line=line, end_line=ev_end,
        reason=(description or "")[:200], evidence_type="source_reference",
    )]

    taint_paths = []
    if sink_file and sink_line:
        taint_paths.append(TaintPathReference(
            source=TaintNode(path=file, line=line, kind="source"),
            sink=TaintNode(path=sink_file, line=sink_line, kind="sink"),
            completeness="partial",          # asserted by the model, not the engine
            analysis_mode="syntactic",
            confidence=min(max(confidence, 0.0), 1.0),
        ))

    finding = SecurityFinding(
        title=title,
        category=category,
        severity=(severity or "").strip().lower(),
        description=description,
        recommendation=recommendation,
        disproof=disproof,
        confidence=min(max(confidence, 0.0), 1.0),
        status="new",
        cwe_ids=_split(cwe),
        owasp_categories=_split(owasp),
        affected_files=[file],
        evidence=evidence,
        taint_paths=taint_paths,
        source_agent=active_agent(),
        source_tools=["report_finding"],
    ).ensure_identity()

    # 1) structural validation — reject so the model can correct and resubmit.
    errs = validate_finding(finding)
    if errs:
        return "REJECTED (not recorded): " + "; ".join(errs) + \
               ". Fix these and call report_finding again."

    # 2) workspace grounding — downgrade (don't reject) if evidence isn't real.
    ground_errs = validate_against_workspace(finding, workspace())
    if ground_errs:
        finding.status = "unconfirmed"
        finding.confidence = min(finding.confidence, 0.4)
        finding.ensure_identity()
        record_finding(finding)
        return (
            f"RECORDED as UNCONFIRMED ({finding.id}) — evidence not grounded: "
            + "; ".join(ground_errs)
            + ". Re-check the exact file path and line, then report again if wrong."
        )

    record_finding(finding)
    return (
        f"RECORDED ({finding.id}, status={finding.status}, "
        f"severity={finding.severity}, confidence={finding.confidence:.2f}). "
        "Continue with the next finding or finish your report."
    )


def finding_tools() -> list:
    return [report_finding]
