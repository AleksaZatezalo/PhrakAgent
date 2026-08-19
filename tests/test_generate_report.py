"""
Description: generate_report — deterministic assembly of the consolidated report.
Author: Aleksa Zatezalo
Date Created: 08-18-2026
"""

from __future__ import annotations

import re

import pytest

from appsec.models.findings import FindingEvidence, SecurityFinding
from appsec.models.testcases import SecurityTestCase
from appsec.report import _demote_headings, build_consolidated_report
from appsec.store import FindingStore
from appsec.store import TestCaseStore as Store  # aliased: not a test class


class _LLM:
    """Records the prompt and returns a canned summary."""

    def __init__(self, reply="Overall the target is in poor shape.", raises=False):
        self.reply = reply
        self.raises = raises
        self.prompts: list[str] = []

    def invoke(self, prompt):
        self.prompts.append(prompt)
        if self.raises:
            raise RuntimeError("model unreachable")

        class _R:
            content = self.reply

        return _R()


def _save_agent_report(config, agent: str, ts: str, body: str) -> None:
    """Write a report in the shape Orchestrator.save_agent_report produces."""
    d = config.reports_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / f"report-{ts}-{agent}.md").write_text(
        f"# {agent} Report — {ts}\n\n**Agent:** {agent}\n\n"
        f"**Task:** something\n\n## Output\n\n{body}\n"
    )


@pytest.fixture
def populated(config):
    _save_agent_report(
        config, "threat_model", "20260818-100000", "## Summary\nOne trust boundary."
    )
    _save_agent_report(
        config, "code_review", "20260818-110000", "## Findings\nSQL built by concat."
    )
    FindingStore(config).upsert(
        [
            SecurityFinding(
                title="SQL injection in /user",
                category="SQL injection",
                severity="critical",
                confidence=0.9,
                affected_files=["vuln_app.py"],
                evidence=[
                    FindingEvidence(path="vuln_app.py", start_line=11, reason="concat")
                ],
                source_agent="code_review",
            ).ensure_identity()
        ],
        run_id="r1",
    )
    Store(config).upsert(
        [
            SecurityTestCase(
                title="SQLi via id",
                target="GET /user?id",
                steps=["send a quote"],
                expected_result="error proves injection",
                severity="critical",
                source_agent="test_case",
            ).ensure_identity()
        ]
    )
    return config


# ------------------------------------------------------------------ structure
def test_report_has_all_five_sections(populated):
    out = build_consolidated_report(config=populated, llm=_LLM())
    assert re.findall(r"^## .*", out, re.M) == [
        "## 1. Executive Summary",
        "## 2. Threat Model",
        "## 3. Code Review",
        "## 4. Findings",
        "## 5. Test Cases",
    ]


def test_agent_sections_are_quoted_verbatim(populated):
    out = build_consolidated_report(config=populated, llm=_LLM())
    assert "One trust boundary." in out
    assert "SQL built by concat." in out
    assert "report-20260818-100000-threat_model.md" in out  # provenance shown


def test_findings_and_test_cases_come_from_the_stores(populated):
    out = build_consolidated_report(config=populated, llm=_LLM())
    assert "SQL injection in /user" in out
    assert "SQLi via id" in out
    assert "error proves injection" in out


def test_only_the_summary_is_model_written(populated):
    """The LLM is called exactly once, and its text lands only in section 1."""
    llm = _LLM(reply="MODEL_SUMMARY_MARKER")
    out = build_consolidated_report(config=populated, llm=llm)
    assert len(llm.prompts) == 1
    assert out.count("MODEL_SUMMARY_MARKER") == 1
    summary, rest = out.split("## 2. Threat Model", 1)
    assert "MODEL_SUMMARY_MARKER" in summary
    assert "MODEL_SUMMARY_MARKER" not in rest


def test_summary_prompt_is_grounded_in_the_real_material(populated):
    llm = _LLM()
    build_consolidated_report(config=populated, llm=llm)
    prompt = llm.prompts[0]
    assert "SQL injection in /user" in prompt  # findings digest
    assert "One trust boundary" in prompt  # threat model excerpt
    assert "SQL built by concat" in prompt  # code review excerpt
    assert "1 test case(s)" in prompt or "test case" in prompt


def test_uses_the_newest_report_per_agent(populated):
    _save_agent_report(
        populated, "code_review", "20260818-990000", "## Findings\nNEWER REVIEW."
    )
    out = build_consolidated_report(config=populated, llm=_LLM())
    assert "NEWER REVIEW." in out
    assert "SQL built by concat." not in out


def test_scope_note_is_included_when_given(populated):
    out = build_consolidated_report("pre-release audit", config=populated, llm=_LLM())
    assert "pre-release audit" in out


def test_footer_states_the_static_only_boundary(populated):
    out = build_consolidated_report(config=populated, llm=_LLM())
    assert "never interacts with a running application" in out


# --------------------------------------------------------------- degradation
def test_missing_agent_reports_are_flagged_not_faked(config):
    out = build_consolidated_report(config=config, llm=_LLM())
    assert "⚠ Incomplete" in out
    assert "threat_model" in out and "code_review" in out
    assert "## 2. Threat Model" in out  # section still present
    assert "No `threat_model` report found" in out


def test_empty_stores_say_how_to_populate_them(config):
    out = build_consolidated_report(config=config, llm=_LLM())
    assert "No findings recorded" in out and "/finding-add" in out
    assert "No test cases recorded" in out and "/testcase-add" in out


def test_a_failing_model_does_not_lose_the_assembled_sections(populated):
    out = build_consolidated_report(config=populated, llm=_LLM(raises=True))
    assert "could not be generated" in out
    assert "model unreachable" in out
    assert "One trust boundary." in out  # everything else survives
    assert "SQL injection in /user" in out


def test_no_llm_at_all_still_produces_a_report(populated):
    out = build_consolidated_report(config=populated, llm=None)
    assert "could not be generated" in out
    assert "One trust boundary." in out


# ------------------------------------------------------------ heading nesting
def test_quoted_headings_are_demoted_so_the_outline_holds(populated):
    out = build_consolidated_report(config=populated, llm=_LLM())
    # the quoted report's own "## Summary" must not sit beside our "## 2. ..."
    assert "### Summary" in out
    assert re.search(r"^## Summary$", out, re.M) is None


def test_demote_headings_skips_fenced_code():
    text = "# Title\n\n```\n# not a heading\n```\n\n## Real\n"
    out = _demote_headings(text, by=1)
    assert "## Title" in out
    assert "# not a heading" in out  # untouched inside the fence
    assert "### Real" in out


def test_demote_headings_clamps_at_h6():
    assert _demote_headings("###### deep\n", by=2).startswith("###### deep")


# ------------------------------------------------------------- agent wiring
def test_registered_as_a_non_plannable_agent_with_a_runner():
    from appsec import agents  # noqa: F401  (registration side-effect)
    from appsec.base_agent import REGISTRY

    spec = REGISTRY.get("generate_report")
    assert spec.runner is build_consolidated_report
    assert spec.plannable is False
    assert "generate_report" not in REGISTRY.plannable_names()
    assert "generate_report" in REGISTRY.names()  # still directly invocable


def test_planner_catalog_excludes_non_plannable_agents():
    from appsec import agents  # noqa: F401
    from appsec.base_agent import REGISTRY

    assert "generate_report" not in REGISTRY.catalog(only_plannable=True)
    assert "generate_report" in REGISTRY.catalog()
