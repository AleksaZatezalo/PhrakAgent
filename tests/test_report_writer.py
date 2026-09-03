"""
Description: ReportWriter — per-agent, consolidated, section reports + pruning.
Author: Aleksa Zatezalo
Date Created: 09-03-2026
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from appsec.report_writer import ReportWriter


def _step(agent, task):
    return SimpleNamespace(agent=agent, task=task)


def _task(agent, status, artifact, task="do it"):
    return SimpleNamespace(agent=agent, status=status, artifact=artifact, task=task)


# ------------------------------------------------------------- per-agent
def test_save_agent_report_shape_and_path(config):
    rw = ReportWriter(config)
    path = rw.save_agent_report("code_review", "review ./target", "SQLi at x.py:1")
    p = Path(path)
    assert p.parent == config.reports_dir()
    assert p.name.startswith("report-") and p.name.endswith("-code_review.md")
    body = p.read_text()
    assert "# code_review Report" in body
    assert "review ./target" in body and "SQLi at x.py:1" in body


# ---------------------------------------------------------- consolidated
def test_save_consolidated_includes_plan_body_and_raw_outputs(config):
    rw = ReportWriter(config)
    plan = [_step("code_review", "review"), _step("threat_model", "model")]
    outputs = [
        {"agent": "code_review", "output": "FINDING BODY"},
        {"agent": "threat_model", "output": "THREAT BODY"},
    ]
    path = rw.save_consolidated("assess app", plan, outputs, "CONSOLIDATED")
    body = Path(path).read_text()
    assert "**Request:** assess app" in body
    assert "1. **code_review** — review" in body
    assert "2. **threat_model** — model" in body
    assert "## Consolidated Report" in body and "CONSOLIDATED" in body
    assert "### code_review" in body and "FINDING BODY" in body
    assert "### threat_model" in body and "THREAT BODY" in body


# ------------------------------------------------------------- sections
def test_save_section_reports_only_writes_usable_done_section_agents(config):
    rw = ReportWriter(config)
    tasks = [
        _task("code_review", "done", "real review body"),  # written
        _task("threat_model", "failed", "[task failed: boom]"),  # skipped (status)
        _task("code_review", "done", "[task skipped: dep failed]"),  # skipped (body)
        _task("test_case", "done", "not a section agent"),  # skipped (agent)
    ]
    rw.save_section_reports(tasks)
    written = sorted(p.name for p in config.reports_dir().glob("report-*.md"))
    assert len(written) == 1
    assert written[0].endswith("-code_review.md")


# ---------------------------------------------------------------- prune
def test_prune_keeps_only_the_newest(config):
    config.keep_reports = 2
    rw = ReportWriter(config)
    for i in range(4):
        # distinct names within the same second so pruning is deterministic
        (config.reports_dir() / f"report-2026073{i}-000000-code_review.md").write_text(
            "x"
        )
    rw.save_agent_report("threat_model", "model it", "out")
    assert len(list(config.reports_dir().glob("report-*.md"))) == 2


def test_prune_disabled_when_keep_is_zero(config):
    config.keep_reports = 0
    rw = ReportWriter(config)
    for i in range(3):
        (config.reports_dir() / f"report-2026073{i}-000000-x.md").write_text("x")
    rw.save_agent_report("code_review", "t", "o")
    assert len(list(config.reports_dir().glob("report-*.md"))) == 4  # nothing pruned
