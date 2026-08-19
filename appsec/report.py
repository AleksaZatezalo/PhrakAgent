"""
Description: Deterministic consolidated-report assembly for the generate_report agent.
Author: Aleksa Zatezalo
Date Created: 08-18-2026

The body of a consolidated report is *assembled*, not authored: the threat model
and code review are quoted verbatim from the reports those agents already saved,
and the finding and test-case sections are rendered straight from their stores.
Only the executive summary is written by a model, from a compact digest of that
same material. Anything else would let a paraphrase drift away from the evidence
the report claims to rest on.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import Config
from .llm import message_text

# Agents whose latest saved report becomes a section of the consolidated one.
SECTION_AGENTS = [
    ("threat_model", "Threat Model"),
    ("code_review", "Code Review"),
]

_EXEC_SUMMARY_PROMPT = """You are writing the EXECUTIVE SUMMARY of a whitebox
application-security assessment report. Everything below was produced by earlier
analysis of the target's source code.

Write 3-6 short paragraphs for a technical decision-maker:
- The overall security posture of the target, in plain language.
- The most serious issues and what an attacker could actually achieve.
- Themes and root causes across findings, not a restatement of the list.
- What state the verification work is in (how much has been tested by hand).
- What should be done first.

Rules:
- Ground every claim in the material below. Do NOT invent findings, file paths,
  CVEs, or severities that do not appear here.
- Do not repeat the finding list verbatim — the report already contains it.
- No preamble, no heading, no sign-off. Start with the substance.
- If the material is thin, say so plainly rather than padding.

## Target
{workspace}

## Findings recorded
{findings}

## Test-case progress
{test_cases}

## Threat model (excerpt)
{threat_model}

## Code review (excerpt)
{code_review}
"""


def _latest_report(config: Config, agent: str) -> Optional[Path]:
    """The newest single-agent report saved for ``agent``, if any.

    Single-agent runs are saved as ``report-<ts>-<agent>.md`` (see
    ``Orchestrator.save_agent_report``); the timestamp leads the name, so a
    lexical sort is chronological.
    """
    reports = config.reports_dir()
    if not reports.is_dir():
        return None
    matches = sorted(reports.glob(f"report-*-{agent}.md"))
    return matches[-1] if matches else None


def _section_body(path: Path) -> str:
    """The agent's own output from a saved report, minus the wrapper header."""
    text = path.read_text(errors="replace")
    # save_agent_report writes "# <name> Report — <ts>" then metadata then
    # "## Output". Keep what follows; fall back to the whole file.
    marker = re.search(r"^##\s+Output\s*$", text, re.MULTILINE)
    body = text[marker.end() :] if marker else text
    return body.strip()


def _demote_headings(markdown: str, by: int = 1) -> str:
    """Push every ATX heading down ``by`` levels so quoted sections nest cleanly.

    Without this a quoted report's own ``## Summary`` would sit at the same level
    as the consolidated report's sections and break the document outline.
    Fenced code blocks are skipped so a shell comment isn't mangled.
    """
    out, in_fence = [], False
    for line in markdown.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
        elif not in_fence:
            m = re.match(r"^(#{1,5})(\s+)", line)
            if m:
                line = "#" * min(len(m.group(1)) + by, 6) + m.group(2) + line[m.end() :]
        out.append(line)
    return "\n".join(out)


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n… [truncated at {limit} chars for the summary prompt]"


def _findings_section(config: Config) -> tuple[str, str]:
    """(rendered section, compact digest for the summary prompt)."""
    from .store import FindingStore, render_finding_list

    records = FindingStore(config).list()
    if not records:
        return (
            "_No findings recorded. Run `code_review`, or add one by hand with "
            "`/finding-add`._",
            "(none recorded)",
        )
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    records = sorted(
        records,
        key=lambda r: (
            order.get(r.as_finding().severity, 5),
            -r.as_finding().confidence,
        ),
    )
    parts = ["```", render_finding_list(records), "```", ""]
    digest_rows = []
    for rec in records:
        f = rec.as_finding()
        # to_markdown already starts at h3, which is the right depth under an
        # h2 section — no demotion needed.
        parts.append(f.to_markdown())
        parts.append("")
        loc = f.evidence[0].location() if f.evidence else "?"
        digest_rows.append(
            f"- [{f.severity}] {f.title} @ {loc} "
            f"(status {f.effective_status()}, confidence {f.confidence:.2f})"
        )
    return "\n".join(parts), "\n".join(digest_rows)


def _test_cases_section(config: Config) -> tuple[str, str]:
    """(rendered section, compact digest for the summary prompt)."""
    from .store import TestCaseStore, render_test_case_list

    cases = TestCaseStore(config).list()
    if not cases:
        return (
            "_No test cases recorded. Run `test_case`, or add one by hand with "
            "`/testcase-add`._",
            "(none recorded)",
        )
    parts = ["```", render_test_case_list(cases), "```", ""]
    for tc in cases:
        parts.append(tc.to_markdown())  # already h3, the right depth here
        parts.append("")
    done = sum(1 for t in cases if t.status == "complete")
    doing = sum(1 for t in cases if t.status == "in_progress")
    failed = sum(1 for t in cases if t.result == "fail")
    digest = (
        f"{len(cases)} test case(s): {done} complete, {doing} in progress, "
        f"{len(cases) - done - doing} not started; {failed} recorded a failing "
        "(vulnerable) result."
    )
    return "\n".join(parts), digest


def build_consolidated_report(
    task: str = "", *, config: Config, llm=None, context: str = ""
) -> str:
    """Assemble the full assessment report. ``llm`` writes the summary only."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    workspace = str(Path(config.paths.workspace).expanduser().resolve())

    # 1. quoted agent sections (verbatim, from what those agents already saved)
    sections: dict[str, str] = {}
    excerpts: dict[str, str] = {}
    missing: list[str] = []
    for agent, _title in SECTION_AGENTS:
        path = _latest_report(config, agent)
        if path is None:
            missing.append(agent)
            sections[agent] = (
                f"_No `{agent}` report found in `{config.reports_dir()}`. "
                f"Run `/{agent} <target>` (or `phrak agent {agent} …`) and "
                "generate this report again._"
            )
            excerpts[agent] = "(not available — this agent has not been run)"
            continue
        body = _section_body(path)
        sections[agent] = f"_Source: `{path.name}`_\n\n{_demote_headings(body, by=1)}"
        excerpts[agent] = _clip(body, 6000)

    # 2. deterministic sections straight from the stores
    findings_md, findings_digest = _findings_section(config)
    tests_md, tests_digest = _test_cases_section(config)

    # 3. the one model-written part
    summary = _executive_summary(
        llm,
        workspace=workspace,
        findings=findings_digest,
        test_cases=tests_digest,
        threat_model=excerpts["threat_model"],
        code_review=excerpts["code_review"],
    )

    out = [
        f"# Security Assessment Report — {ts}",
        "",
        f"**Target:** `{workspace}`",
    ]
    if task.strip():
        out.append(f"**Scope note:** {task.strip()}")
    if missing:
        out.append(
            f"\n> ⚠ Incomplete: no report available for {', '.join(missing)}. "
            "Those sections are placeholders."
        )
    out += [
        "",
        "## 1. Executive Summary",
        "",
        summary,
        "",
        "## 2. Threat Model",
        "",
        sections["threat_model"],
        "",
        "## 3. Code Review",
        "",
        sections["code_review"],
        "",
        "## 4. Findings",
        "",
        findings_md,
        "",
        "## 5. Test Cases",
        "",
        tests_md,
        "",
        "---",
        "",
        "_Assembled by PHRAK `generate_report`. The threat model and code review "
        "are quoted verbatim from their own runs; findings and test cases are "
        "rendered from the workspace stores. PHRAK performs static, whitebox "
        "analysis only — it never interacts with a running application, so every "
        "test case is a hypothesis until a human executes it._",
    ]
    return "\n".join(out)


def _executive_summary(llm, **fields) -> str:
    """The only model-written section. Degrades to a factual stub on failure."""
    if llm is None:
        return _summary_stub(fields)
    prompt = _EXEC_SUMMARY_PROMPT.format(**fields)
    try:
        text = message_text(llm.invoke(prompt)).strip()
    except Exception as e:
        return _summary_stub(fields, error=str(e))
    from .ui import strip_thoughts

    text = strip_thoughts(text)
    return text or _summary_stub(fields)


def _summary_stub(fields: dict, error: str = "") -> str:
    """A truthful placeholder when no summary could be generated."""
    why = f" ({error})" if error else ""
    return (
        f"_The executive summary could not be generated{why}. The assembled "
        "sections below are unaffected._\n\n"
        f"Findings recorded:\n{fields.get('findings', '(none)')}\n\n"
        f"Test cases: {fields.get('test_cases', '(none)')}"
    )
