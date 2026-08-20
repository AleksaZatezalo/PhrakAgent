"""
Description: Structured capture survives a spent step budget; process-wide token usage.
Author: Aleksa Zatezalo
Date Created: 08-19-2026
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from appsec.base_agent import Agent, AgentSpec


class _Msg:
    """Stands in for an AIMessage carrying provider usage metadata."""

    def __init__(self, inp=0, out=0, meta=None):
        self.usage_metadata = {"input_tokens": inp, "output_tokens": out}
        self.response_metadata = meta or {}
        self.content = ""


@pytest.fixture(autouse=True)
def _reset_usage():
    from appsec import runtime

    with runtime._USAGE_LOCK:
        runtime._USAGE.update({"input": 0, "output": 0, "calls": 0})
    yield


def _agent(config, tool_names, monkeypatch):
    """An Agent whose tools are name-only stubs and whose LLM is never used."""
    spec = AgentSpec(
        name="code_review",
        description="d",
        system_prompt="p",
        tool_factory=lambda: [],
    )
    agent = Agent.__new__(Agent)  # skip __init__: it builds skills/LLM plumbing
    agent.spec = spec
    agent.config = config
    agent.quiet = True
    agent.tools = [SimpleNamespace(name=n) for n in tool_names]
    agent._budget_exhausted = True
    return agent


# ------------------------------------------------- recording before write-up
def test_recording_round_runs_before_the_tool_free_writeup(config, monkeypatch):
    """The regression: the write-up prompt says 'STOP using tools', which
    silently included report_finding — so a budget-exhausted run described
    vulnerabilities in prose while the findings store stayed empty."""
    agent = _agent(config, ["read_file", "report_finding"], monkeypatch)
    prompts = []

    def _drive(graph, message, cfg):
        prompts.append((message, cfg.get("recursion_limit")))
        return "REPORT BODY"

    agent._drive = _drive
    agent._note = lambda msg: None
    agent._best = lambda cand, cur: cand or cur

    agent._wrap_up_if_exhausted(object(), {"configurable": {}}, "")

    assert len(prompts) == 2, "expected a record round then a write-up round"
    record, writeup = prompts
    assert "report_finding" in record[0]
    assert "RECORD" in record[0]
    assert record[1] == Agent._RECORD_STEPS  # its own, larger budget
    assert "STOP using tools" in writeup[0]
    assert writeup[1] == Agent._FINALIZE_STEPS


def test_recording_round_names_only_the_tools_the_agent_has(config, monkeypatch):
    agent = _agent(config, ["read_file", "report_test_case"], monkeypatch)
    prompts = []
    agent._drive = lambda g, m, c: prompts.append(m) or ""
    agent._note = lambda msg: None
    agent._best = lambda cand, cur: cand or cur

    agent._wrap_up_if_exhausted(object(), {"configurable": {}}, "")
    assert "report_test_case" in prompts[0]
    assert "report_finding" not in prompts[0]


def test_no_recording_round_for_agents_that_record_nothing(config, monkeypatch):
    """threat_model has no capture tool — it should go straight to the write-up."""
    agent = _agent(config, ["read_file", "search_code"], monkeypatch)
    prompts = []
    agent._drive = lambda g, m, c: prompts.append(m) or "BODY"
    agent._note = lambda msg: None
    agent._best = lambda cand, cur: cand or cur

    agent._wrap_up_if_exhausted(object(), {"configurable": {}}, "")
    assert len(prompts) == 1
    assert "STOP using tools" in prompts[0]


def test_recording_round_text_never_becomes_the_report(config, monkeypatch):
    """The record turn replies 'DONE'; that must not displace the real answer."""
    agent = _agent(config, ["report_finding"], monkeypatch)
    replies = iter(["DONE", "THE REAL REPORT"])
    agent._drive = lambda g, m, c: next(replies)
    agent._note = lambda msg: None
    agent._best = lambda cand, cur: cand if len(cand) > len(cur) else cur

    out = agent._wrap_up_if_exhausted(object(), {"configurable": {}}, "")
    assert out == "THE REAL REPORT"
    assert "DONE" not in out


def test_wrap_up_is_skipped_when_the_budget_was_not_spent(config, monkeypatch):
    agent = _agent(config, ["report_finding"], monkeypatch)
    agent._budget_exhausted = False
    agent._drive = lambda g, m, c: pytest.fail("should not drive the model")
    assert agent._wrap_up_if_exhausted(object(), {}, "EXISTING") == "EXISTING"


def test_recording_tools_detection(config, monkeypatch):
    agent = _agent(config, ["read_file", "report_finding", "report_test_case"], None)
    assert agent._recording_tools() == ["report_finding", "report_test_case"]
    bare = _agent(config, ["read_file"], None)
    assert bare._recording_tools() == []


# ------------------------------------------------------- empty-store warning
def test_warns_when_a_capable_agent_records_no_findings(config, monkeypatch):
    from appsec.runtime import begin_findings

    agent = _agent(config, ["report_finding"], None)
    notes = []
    agent._note = notes.append
    begin_findings()
    agent._append_structured_findings("body")
    assert any("no structured findings recorded" in n for n in notes)


def test_no_warning_for_an_agent_that_cannot_record(config, monkeypatch):
    from appsec.runtime import begin_findings

    agent = _agent(config, ["read_file"], None)
    notes = []
    agent._note = notes.append
    begin_findings()
    agent._append_structured_findings("body")
    assert notes == []


def test_warns_when_no_test_cases_recorded(config, monkeypatch):
    from appsec.runtime import begin_test_cases

    agent = _agent(config, ["report_test_case"], None)
    notes = []
    agent._note = notes.append
    begin_test_cases()
    agent._append_structured_test_cases("body")
    assert any("no test cases recorded" in n for n in notes)


# ------------------------------------------------- record-as-you-go prompting
def test_code_review_prompt_demands_immediate_recording():
    """Batching findings to the end loses them when the step budget runs out,
    which is exactly what happened on a large repo."""
    from appsec.agents.code_review import SYSTEM_PROMPT as p

    assert "DO NOT BATCH" in p
    assert "THE MOMENT" in p
    assert "report_finding" in p
    # the rationale must be present — the model needs to know *why*
    assert "step budget" in p and "LOST" in p
    # and the report must be framed as coming after recording, not instead of it
    assert "written report comes LAST" in p


def test_test_case_prompt_demands_immediate_recording():
    from appsec.agents.test_case import SYSTEM_PROMPT as p

    assert "DO NOT BATCH" in p
    assert "report_test_case the moment" in p
    assert "step budget" in p


def test_code_review_prompt_no_longer_defers_the_report():
    """The old wording ('write your final findings report after you have read
    the code' + a trailing RECORD paragraph) read as explore-then-record."""
    from appsec.agents.code_review import SYSTEM_PROMPT as p

    assert "Only write your final findings report after you have read the code" not in p


def test_continuation_prompt_reminds_capable_agents_to_record(config):
    agent = _agent(config, ["read_file", "report_finding"], None)
    reminder = agent._record_reminder()
    assert "report_finding" in reminder
    assert "not" in reminder and "recorded" in reminder


def test_continuation_reminder_is_empty_for_agents_without_capture(config):
    agent = _agent(config, ["read_file", "search_code"], None)
    assert agent._record_reminder() == ""


def test_continuation_reminder_lists_every_capture_tool(config):
    agent = _agent(config, ["report_finding", "report_test_case"], None)
    reminder = agent._record_reminder()
    assert "report_finding" in reminder and "report_test_case" in reminder


# --------------------------------------------------------------- token usage
def test_usage_accumulates_across_calls():
    from appsec.runtime import record_usage, usage_totals

    record_usage(_Msg(100, 20))
    record_usage(_Msg(50, 10))
    assert usage_totals() == {"input": 150, "output": 30, "calls": 2}


def test_usage_reads_ollama_metadata_names():
    from appsec.runtime import record_usage, usage_totals

    msg = _Msg(0, 0, meta={"prompt_eval_count": 7, "eval_count": 3})
    msg.usage_metadata = {}
    record_usage(msg)
    assert usage_totals()["input"] == 7 and usage_totals()["output"] == 3


def test_usage_ignores_replies_without_metadata():
    from appsec.runtime import record_usage, usage_totals

    empty = _Msg(0, 0)
    empty.usage_metadata = {}
    record_usage(empty)
    assert usage_totals()["calls"] == 0


def test_usage_is_thread_safe():
    import threading

    from appsec.runtime import record_usage, usage_totals

    def worker():
        for _ in range(200):
            record_usage(_Msg(1, 1))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert usage_totals() == {"input": 800, "output": 800, "calls": 800}


def test_cost_summary_reports_the_process_total(config):
    from appsec.chat import ChatSession
    from appsec.runtime import record_usage

    session = ChatSession.__new__(ChatSession)  # skip the graph build
    session.tokens = {"input": 5, "output": 5, "turns": 1}
    session.app = SimpleNamespace(config=config)

    record_usage(_Msg(9000, 400))  # as an agent run would
    out = session.cost_summary()
    assert "9000" in out and "400" in out
    assert "includes /run" in out
