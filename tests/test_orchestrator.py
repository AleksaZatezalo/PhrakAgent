"""
Description: Orchestrator planning and routing (no real LLM / agents needed).
Author: Aleksa Zatezalo
Date Created: 07-31-2026
"""

from __future__ import annotations

from appsec.base_agent import AgentRegistry, AgentSpec
from appsec.orchestrator import Orchestrator, Step, _extract_json
from tests.conftest import FakeLLM


def _registry():
    reg = AgentRegistry()
    reg.register(AgentSpec("code_review", "reviews source code for vulnerabilities",
                           "p", tags=["sast", "code"]))
    reg.register(AgentSpec("threat_model", "builds a STRIDE threat model",
                           "p", tags=["stride", "design"]))
    return reg


def _orch(llm, config):
    return Orchestrator(llm, skills=None, config=config, registry=_registry())


def test_plan_parses_llm_json(config):
    llm = FakeLLM(reply='{"plan": [{"agent": "code_review", "task": "review app"}]}')
    plan = _orch(llm, config).plan("assess the app")
    assert plan == [Step(agent="code_review", task="review app")]


def test_plan_falls_back_to_all_agents_on_llm_error(config):
    plan = _orch(FakeLLM(raises=True), config).plan("assess the app")
    assert {s.agent for s in plan} == {"code_review", "threat_model"}


def test_plan_ignores_unknown_agents(config):
    llm = FakeLLM(reply='{"plan": [{"agent": "nope", "task": "x"}]}')
    # no valid steps -> fallback to all agents
    plan = _orch(llm, config).plan("x")
    assert {s.agent for s in plan} == {"code_review", "threat_model"}


def test_route_exact_name(config):
    assert _orch(FakeLLM(reply="threat_model"), config).route("x") == "threat_model"


def test_route_falls_back_to_heuristic(config):
    # empty LLM reply -> keyword heuristic; "threat model" should win.
    routed = _orch(FakeLLM(reply=""), config).route("build a threat model please")
    assert routed == "threat_model"


# ------------------------------------------------- single-agent report saving
def test_save_agent_report_writes_output_and_task(config):
    orch = _orch(FakeLLM(reply=""), config)
    path = orch.save_agent_report(
        "code_review", "review ./target", "SQL injection at vuln_app.py:11"
    )
    from pathlib import Path

    p = Path(path)
    assert p.parent == config.reports_dir()
    assert p.name.startswith("report-") and p.name.endswith("-code_review.md")
    body = p.read_text()
    assert "review ./target" in body                       # the task is recorded
    assert "SQL injection at vuln_app.py:11" in body       # ...and the output


def test_save_agent_report_is_pruned_by_keep_reports(config):
    """Per-agent reports share the ``report-*.md`` namespace, so keep_reports
    must prune them alongside the pipeline's consolidated reports."""
    config.keep_reports = 2
    orch = _orch(FakeLLM(reply=""), config)
    for i in range(4):
        # distinct names within the same second -> exercise pruning deterministically
        (config.reports_dir() / f"report-2026073{i}-000000-code_review.md").write_text("x")
    orch.save_agent_report("threat_model", "model it", "out")
    assert len(list(config.reports_dir().glob("report-*.md"))) == 2


def test_extract_json_variants():
    assert _extract_json('{"a": 1}') == {"a": 1}
    assert _extract_json('```json\n{"a": 2}\n```') == {"a": 2}
    assert _extract_json('noise {"a": 3} tail') == {"a": 3}
    assert _extract_json("no json here") is None
