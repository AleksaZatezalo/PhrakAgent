"""
Description: A turn that dies must not take the whole task with it.
Author: Aleksa Zatezalo
Date Created: 08-01-2026
"""

from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage
from langgraph.errors import GraphRecursionError

from appsec.base_agent import Agent, AgentSpec
from appsec.orchestrator import Orchestrator, Task
from appsec.skill_store import SkillStore
from appsec.ui import strip_thoughts
from tests.conftest import FakeLLM

SECTIONS = ["summary", "severity"]


class FakeGraph:
    """Stands in for the compiled tool-calling graph.

    Each queued turn is either ``("text", <assistant text>)`` or
    ``("raise", <exception>)``; turns are consumed in order and the prompt of
    each one is recorded so tests can assert what the agent asked for.
    """

    def __init__(self, turns):
        self.turns = list(turns)
        self.prompts: list[str] = []

    def stream(self, payload, cfg, stream_mode=None):
        self.prompts.append(payload["messages"][0].content)
        kind, value = self.turns.pop(0) if self.turns else ("text", "")
        if kind == "raise":
            raise value
        yield {"agent": {"messages": [AIMessage(content=value)]}}


@pytest.fixture
def agent(config, monkeypatch):
    """An Agent wired to a FakeGraph the test fills in via ``agent.graph``."""
    import langchain.agents

    spec = AgentSpec(
        "tester", "test agent", "be a test agent", report_sections=SECTIONS
    )
    a = Agent(spec, FakeLLM(reply="unused"), SkillStore(config), config, quiet=True)
    monkeypatch.setattr(
        langchain.agents, "create_agent", lambda *args, **kwargs: a.graph
    )
    return a


def _report(extra: str = "") -> str:
    return f"## Summary\nfindings here\n\n## Severity\nhigh\n{extra}"


# ------------------------------------------------------------- output hygiene
def test_strip_thoughts_drops_leaked_tool_protocol():
    # qwen2.5-coder emits exactly this as its whole "report"
    assert strip_thoughts("<tool_response>\n\n</tool_response>") == ""
    assert strip_thoughts("<|im_start|>real answer<tool_call>") == "real answer"
    assert strip_thoughts("keep <think>drop me</think>this") == "keep this"


# --------------------------------------------------------- exhausted budget
def test_exhausted_budget_gets_a_wrap_up_turn(agent):
    """Out of steps mid-turn -> one tool-free turn to write up what it has."""
    agent.graph = FakeGraph(
        [
            ("raise", GraphRecursionError("Recursion limit of 40 reached")),
            ("text", _report()),
        ]
    )
    out = agent.run("review the app")

    assert "findings here" in out
    assert "STOP using tools" in agent.graph.prompts[1]


def test_wrap_up_turn_cannot_itself_loop(agent, config):
    """Every turn exhausting its budget ends the run, it doesn't recurse."""
    config.max_rounds = 3
    agent.graph = FakeGraph([("raise", GraphRecursionError("boom"))] * 20)
    out = agent.run("review the app")

    assert "incomplete run" in out
    # 3 completion rounds, each with a wrap-up attempt: bounded, not runaway
    assert len(agent.graph.prompts) == 6


def test_no_usable_output_falls_back_to_a_report(agent):
    """Protocol noise is not an answer, but the run still reports what happened."""
    agent.graph = FakeGraph([("text", "<tool_response></tool_response>")] * 10)
    out = agent.run("review the app")

    assert "incomplete run" in out
    assert "max_steps" in out  # tells the user which knob to turn
    assert "tool_response" not in out


# ------------------------------------------------------------ provider errors
def test_provider_error_with_no_output_is_raised(agent):
    """A dead provider must surface, not masquerade as an empty report."""
    agent.graph = FakeGraph([("raise", RuntimeError("401 invalid x-api-key"))] * 10)

    with pytest.raises(RuntimeError, match="invalid x-api-key"):
        agent.run("review the app")


def test_provider_error_after_a_good_report_keeps_the_report(agent):
    """A late failure can't discard work that's already written."""
    agent.graph = FakeGraph(
        [
            ("text", _report()),
            ("raise", RuntimeError("429 rate limited")),
        ]
    )
    # incomplete on purpose so a second round runs and fails
    agent.spec.report_sections = SECTIONS + ["remediation"]
    out = agent.run("review the app")

    assert "findings here" in out


# --------------------------------------------------------- best-answer choice
def test_a_later_junk_turn_does_not_replace_a_good_draft(agent):
    agent.spec.report_sections = SECTIONS + ["remediation"]  # never satisfied
    agent.graph = FakeGraph(
        [
            ("text", _report()),
            ("text", "<tool_response></tool_response>"),
            ("text", "ok"),
        ]
    )
    out = agent.run("review the app")

    assert "findings here" in out


def test_a_more_complete_turn_wins(agent):
    agent.graph = FakeGraph(
        [
            ("text", "## Summary\npartial only"),
            ("text", _report("\n\n## Remediation\nfix it")),
        ]
    )
    out = agent.run("review the app")

    assert "fix it" in out


# ------------------------------------------------------- orchestrator report
def test_all_failed_synthesis_names_the_errors(config):
    """The terminal message is where the user looks; it must carry the reason."""
    orch = Orchestrator(FakeLLM(reply="unused"), skills=None, config=config)
    tasks = [
        Task(
            id="t1",
            agent="code_review",
            task="review",
            status="failed",
            error="Recursion limit of 40 reached",
        ),
        Task(
            id="t2",
            agent="test_case",
            task="tests",
            depends_on=["t1"],
            status="skipped",
        ),
    ]
    out = orch._synthesize_dag("assess", tasks)

    assert "Recursion limit of 40 reached" in out
    assert "t2" in out and "skipped" in out


# ------------------------------------------------ context / synthesis budgets
def test_merge_outputs_never_starves_a_later_agent():
    """A long first report must not consume the whole budget.

    Regression: the old code sliced the *concatenation*, so a 23k-char first
    report ate a 16k cap and the second agent's 35k-char report reached the
    synthesizer as zero characters — which it then reported as "output not
    received" even though the agent had delivered.
    """
    from appsec.orchestrator import _merge_outputs

    merged = _merge_outputs(
        [("code_review", "A" * 23_114), ("threat_model", "B" * 34_898)], budget=16_000
    )

    assert "code_review" in merged and "threat_model" in merged
    assert "A" in merged and "B" in merged  # both are represented
    assert "truncated" in merged  # and it says it clipped


def test_merge_outputs_hands_unused_share_to_longer_sections():
    from appsec.orchestrator import _merge_outputs

    merged = _merge_outputs([("short", "s" * 10), ("long", "L" * 5_000)], budget=2_000)

    assert "s" * 10 in merged  # short section kept whole
    assert merged.count("L") > 1_000  # long one got the remainder


def test_merge_outputs_leaves_small_inputs_untouched():
    from appsec.orchestrator import _merge_outputs

    merged = _merge_outputs([("a", "one"), ("b", "two")], budget=100_000)
    assert "truncated" not in merged
    assert "one" in merged and "two" in merged


def test_prompt_budget_scales_with_the_provider():
    """One fixed cap can't serve a 16k local window and a 1M Claude window."""
    from appsec.config import LLMConfig
    from appsec.llm import prompt_char_budget

    local = prompt_char_budget(LLMConfig(provider="ollama", num_ctx=16384))
    claude = prompt_char_budget(LLMConfig(provider="anthropic", model="claude-opus-5"))

    assert 16_000 < local < 40_000  # ~half a 16k-token window, in chars
    assert claude > 200_000  # a full multi-agent run fits
