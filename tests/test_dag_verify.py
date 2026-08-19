"""
Description: DAG planner + verify agent integration.

The verify agent is opt-in. When enable_verify is True and the agent is
registered, the DAG planner prompt should mention it as an option, and a
default "assess this app" plan should schedule a verify task that depends on
code_review. When enable_verify is False, verify must not appear.
"""

from __future__ import annotations

import json

from appsec.base_agent import AgentRegistry, AgentSpec
from appsec.orchestrator import Orchestrator, Task
from tests.conftest import FakeLLM


def _registry(include_verify: bool = False) -> AgentRegistry:
    reg = AgentRegistry()
    specs = [
        ("code_review", "reviews code"),
        ("threat_model", "threat model"),
        ("test_case", "builds test cases"),
    ]
    if include_verify:
        specs.append(("verify", "sandboxed PoC runner"))
    for n, d in specs:
        reg.register(AgentSpec(n, d, "p"))
    return reg


def _orch(llm, config, include_verify: bool = False) -> Orchestrator:
    return Orchestrator(
        llm, skills=None, config=config, registry=_registry(include_verify)
    )


# ------------------------------- prompt content


def test_dag_planner_mentions_verify_only_when_registered(config):
    """The catalog line the planner receives contains 'verify' iff registered."""
    llm = FakeLLM(reply='{"tasks":[]}')
    orch_off = _orch(llm, config, include_verify=False)
    orch_on = _orch(llm, config, include_verify=True)

    assert "verify" not in orch_off.registry.catalog()
    assert "verify" in orch_on.registry.catalog()


def test_verify_agent_scheduled_after_code_review_when_present(config):
    """LLM plan naming verify is honoured; verify.depends_on includes code_review."""
    reply = json.dumps(
        {
            "tasks": [
                {
                    "id": "t1",
                    "agent": "code_review",
                    "task": "review",
                    "depends_on": [],
                    "parallel_group": "static",
                },
                {
                    "id": "t2",
                    "agent": "threat_model",
                    "task": "model",
                    "depends_on": [],
                    "parallel_group": "static",
                },
                {
                    "id": "t3",
                    "agent": "verify",
                    "task": "confirm findings",
                    "depends_on": ["t1"],
                    "parallel_group": "",
                },
                {
                    "id": "t4",
                    "agent": "test_case",
                    "task": "tests",
                    "depends_on": ["t1", "t2"],
                    "parallel_group": "",
                },
            ]
        }
    )
    orch = _orch(FakeLLM(reply=reply), config, include_verify=True)
    tasks = orch.plan_dag("assess this app for security issues")
    by_agent = {t.agent: t for t in tasks}
    assert "verify" in by_agent, "verify should be scheduled when registered"
    verify_task = by_agent["verify"]
    assert "t1" in verify_task.depends_on
    # code_review must not depend on verify (no cycles).
    assert "t3" not in by_agent["code_review"].depends_on


def test_verify_agent_dropped_when_not_registered(config):
    """If the LLM hallucinated a 'verify' task but the agent isn't registered,
    plan_dag silently drops it — the whole run doesn't fail."""
    reply = json.dumps(
        {
            "tasks": [
                {"id": "t1", "agent": "code_review", "task": "review"},
                {"id": "t2", "agent": "verify", "task": "poc", "depends_on": ["t1"]},
            ]
        }
    )
    orch = _orch(FakeLLM(reply=reply), config, include_verify=False)
    tasks = orch.plan_dag("assess")
    agents = {t.agent for t in tasks}
    assert "verify" not in agents
    # code_review still made it through
    assert "code_review" in agents


def test_planner_prompt_includes_verify_guidance_when_available(config):
    """The DAG planner prompt sent to the LLM should tell it to schedule verify
    after code_review — otherwise a weak model won't wire it in.

    We look for the explicit assessment-flow instruction, not just any
    occurrence of the word (the agent catalog line contains it trivially).
    """
    captured = {"prompts": []}

    class CapturingLLM(FakeLLM):
        def invoke(self, prompt, **k):
            captured["prompts"].append(
                prompt if isinstance(prompt, str) else str(prompt)
            )
            return super().invoke(prompt, **k)

    # Return one valid task so plan_dag doesn't fall back to the linear planner
    # (which would then also invoke the LLM with the OTHER prompt and confuse us).
    reply = json.dumps(
        {"tasks": [{"id": "t1", "agent": "code_review", "task": "review"}]}
    )
    orch = _orch(CapturingLLM(reply=reply), config, include_verify=True)
    orch.plan_dag("assess this app")
    # The first invocation is the DAG planner prompt.
    prompt = (captured["prompts"][0] or "").lower()
    # The rule text should tell the planner to include a verify task that
    # depends on code_review — not merely list verify in the catalog.
    assert (
        "verify task" in prompt
        or "verify agent" in prompt
        or ("verify" in prompt and "depends on code_review" in prompt)
    ), f"planner prompt missing verify scheduling guidance:\n{prompt}"


def test_planner_prompt_omits_verify_when_unavailable(config):
    """When verify isn't registered, the planner prompt shouldn't mention it —
    otherwise the LLM will schedule a task the runner can't execute."""
    captured = {"prompts": []}

    class CapturingLLM(FakeLLM):
        def invoke(self, prompt, **k):
            captured["prompts"].append(
                prompt if isinstance(prompt, str) else str(prompt)
            )
            return super().invoke(prompt, **k)

    reply = json.dumps(
        {"tasks": [{"id": "t1", "agent": "code_review", "task": "review"}]}
    )
    orch = _orch(CapturingLLM(reply=reply), config, include_verify=False)
    orch.plan_dag("assess this app")
    prompt = (captured["prompts"][0] or "").lower()
    # 'verify' as a token might appear in generic prose; the concrete agent
    # guidance line ("verify agent"/"verify task") should be absent.
    assert "verify agent" not in prompt
    assert "verify task" not in prompt


# ------------------------------- execution


def test_run_dag_actually_runs_verify_after_code_review(config):
    """End-to-end: a plan with verify runs verify, and code_review's artifact
    reaches it as context (that's how the sandbox PoC agent knows what to
    verify)."""
    import threading

    from appsec.orchestrator import Orchestrator, Task

    class Recording(Orchestrator):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.calls: list[tuple[str, str]] = []
            self._lock = threading.Lock()

        def run_agent(self, name, task, context="", quiet=False):
            with self._lock:
                self.calls.append((name, context))
            return f"OUTPUT[{name}]"

    orch = Recording(
        FakeLLM(reply="synth report"),
        skills=None,
        config=config,
        registry=_registry(include_verify=True),
    )
    plan = [
        Task(id="t1", agent="code_review", task="review"),
        Task(id="t2", agent="verify", task="poc", depends_on=["t1"]),
    ]
    result = orch.run_dag("assess", plan=plan)
    agents_run = [c[0] for c in orch.calls]
    assert agents_run == ["code_review", "verify"]
    # verify received code_review's artifact as context.
    verify_context = dict(orch.calls)["verify"]
    assert "OUTPUT[code_review]" in verify_context
    # The consolidated report was produced.
    assert result["report"]
