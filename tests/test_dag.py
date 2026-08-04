"""
Description: DAG orchestration: planning, parallel fan-out, partial-failure (Phase 8).
Author: Aleksa Zatezalo
Date Created: 07-31-2026
"""

from __future__ import annotations

import threading
import time

from appsec.base_agent import AgentRegistry, AgentSpec
from appsec.orchestrator import Orchestrator, Task
from tests.conftest import FakeLLM


def _registry():
    reg = AgentRegistry()
    for n, d in (
        ("code_review", "reviews code"),
        ("threat_model", "threat model"),
        ("test_case", "builds test cases"),
    ):
        reg.register(AgentSpec(n, d, "p"))
    return reg


class RecordingOrch(Orchestrator):
    """Orchestrator whose run_agent is stubbed to avoid real LLM/agents."""

    def __init__(self, *a, fail: set | None = None, **k):
        super().__init__(*a, **k)
        self.calls: list[tuple[str, str]] = []  # (agent, context)
        self.active = 0
        self.max_active = 0
        self._lock = threading.Lock()
        self._fail = fail or set()

    def run_agent(self, name, task, context="", quiet=False):
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.calls.append((name, context))
        try:
            time.sleep(0.02)
            if name in self._fail:
                raise RuntimeError(f"{name} boom")
            return f"OUTPUT[{name}]"
        finally:
            with self._lock:
                self.active -= 1


def _orch(llm, config, **k):
    return RecordingOrch(llm, skills=None, config=config, registry=_registry(), **k)


# --------------------------------------------------------------- planning
def test_plan_dag_parses_dependencies(config):
    llm = FakeLLM(
        reply='{"tasks": ['
        '{"id": "t1", "agent": "code_review", "task": "review",'
        ' "depends_on": [], "parallel_group": "a"},'
        '{"id": "t2", "agent": "test_case", "task": "tests",'
        ' "depends_on": ["t1"], "parallel_group": ""}]}'
    )
    tasks = _orch(llm, config).plan_dag("assess")
    assert [t.id for t in tasks] == ["t1", "t2"]
    assert tasks[1].depends_on == ["t1"]


def test_plan_dag_drops_dangling_deps_and_unknown_agents(config):
    llm = FakeLLM(
        reply='{"tasks": ['
        '{"id": "t1", "agent": "nope", "task": "x"},'
        '{"id": "t2", "agent": "code_review", "task": "y",'
        ' "depends_on": ["ghost", "t2"]}]}'
    )
    tasks = _orch(llm, config).plan_dag("x")
    assert [t.id for t in tasks] == ["t2"]
    assert tasks[0].depends_on == []  # ghost + self-dep dropped


def test_plan_dag_falls_back_to_linear(config):
    tasks = _orch(FakeLLM(raises=True), config).plan_dag("assess the app")
    # linear fallback: each task depends on the previous
    assert len(tasks) >= 1
    assert tasks[0].depends_on == []
    for prev, t in zip(tasks, tasks[1:]):
        assert t.depends_on == [prev.id]


# --------------------------------------------------------------- execution
def test_run_dag_respects_dependencies(config):
    orch = _orch(FakeLLM(reply="synth report"), config)
    plan = [
        Task(id="t1", agent="code_review", task="review"),
        Task(id="t2", agent="test_case", task="tests", depends_on=["t1"]),
    ]
    result = orch.run_dag("assess", plan=plan)
    # the dependent task ran with the reviewer's output as context
    dependent_ctx = next(c for n, c in orch.calls if n == "test_case")
    assert "OUTPUT[code_review]" in dependent_ctx
    assert all(t.status == "done" for t in result["dag"])


def test_run_dag_runs_independent_tasks_in_parallel(config):
    config.orchestrator.max_concurrency = 3
    orch = _orch(FakeLLM(reply="synth"), config)
    plan = [
        Task(id="t1", agent="code_review", task="a", parallel_group="g"),
        Task(id="t2", agent="threat_model", task="b", parallel_group="g"),
        Task(id="t3", agent="test_case", task="c", parallel_group="g"),
    ]
    orch.run_dag("assess", plan=plan)
    assert orch.max_active >= 2  # genuinely concurrent


def test_run_dag_isolates_partial_failure(config):
    orch = _orch(FakeLLM(reply="synth"), config, fail={"code_review"})
    plan = [
        Task(id="t1", agent="code_review", task="review"),
        Task(id="t2", agent="test_case", task="tests", depends_on=["t1"]),
        Task(id="t3", agent="threat_model", task="model"),  # independent -> survives
    ]
    result = orch.run_dag("assess", plan=plan)
    st = {t.id: t.status for t in result["dag"]}
    assert st["t1"] == "failed"
    assert st["t2"] == "skipped"  # dependent on the failed task
    assert st["t3"] == "done"  # independent task still ran


def test_run_dag_synthesis_notes_coverage(config):
    orch = _orch(FakeLLM(reply="SYNTH"), config, fail={"threat_model"})
    plan = [
        Task(id="t1", agent="code_review", task="review"),
        Task(id="t2", agent="threat_model", task="model"),
    ]
    result = orch.run_dag("assess", plan=plan)
    # synthesis prompt received a coverage block including the failed task
    synth_prompt = orch.llm.calls[-1]
    assert "t2" in synth_prompt and "failed" in synth_prompt


def test_run_dag_breaks_dependency_cycle(config):
    orch = _orch(FakeLLM(reply="synth"), config)
    plan = [
        Task(id="t1", agent="code_review", task="a", depends_on=["t2"]),
        Task(id="t2", agent="threat_model", task="b", depends_on=["t1"]),
    ]
    result = orch.run_dag("assess", plan=plan)  # must not hang
    assert all(t.status == "skipped" for t in result["dag"])
