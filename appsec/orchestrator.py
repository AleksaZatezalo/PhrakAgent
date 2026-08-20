"""
Description: Orchestrator — plans and coordinates the specialist agents.
Author: Aleksa Zatezalo
Date Created: 08-01-2026
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from langchain_core.language_models.chat_models import BaseChatModel

from .base_agent import REGISTRY, Agent, AgentRegistry
from .config import Config
from .llm import ModelRegistry, message_text, prompt_char_budget
from .skill_store import SkillStore


def _extract_json(text: str) -> Optional[dict]:
    """Best-effort JSON object extraction from a possibly-chatty LLM response."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.MULTILINE).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


@dataclass
class Step:
    agent: str
    task: str


@dataclass
class Task:
    """One node in an execution DAG (Phase 8).

    ``depends_on`` names the task ids whose artifacts must exist first;
    ``parallel_group`` is a hint that same-group tasks are independent and may run
    concurrently. ``status`` / ``artifact`` / ``error`` are filled in as the DAG
    executes. It quacks like :class:`Step` (``.agent`` / ``.task``) so the same
    progress callbacks and report writer work unchanged.
    """

    id: str
    agent: str
    task: str
    depends_on: list[str] = field(default_factory=list)
    parallel_group: str = ""
    status: str = "pending"  # pending | running | done | failed | skipped
    artifact: str = ""
    error: str = ""


_PLANNER_PROMPT = """You are the orchestrator for a team of application-security
agents. Decompose the user's request into an ordered plan, assigning each step
to exactly one available agent.

Available agents:
{catalog}

Rules:
- Order steps sensibly (understand the code before threat-modeling it; derive
  test cases only AFTER a code review and threat model have produced findings).
- For a general "assess / review / secure this app" request, produce a FULL
  assessment: a code_review step, a threat_model step, and a final test_case step
  that turns their findings into a security test plan.
- Only use agents from the list above; use each at most twice.
- Keep the plan to 1-4 steps. Each step's "task" is a concrete instruction.

Return ONLY JSON:
{{"plan": [{{"agent": "<name>", "task": "<what this agent should do>"}}]}}

USER REQUEST: {request}
"""

_DAG_PLANNER_PROMPT = """You are the orchestrator for a team of application-security
agents. Decompose the user's request into a DEPENDENCY GRAPH of tasks, assigning
each to exactly one available agent.

Available agents:
{catalog}

Rules:
- Give each task a short unique id (t1, t2, ...).
- "depends_on" lists the ids whose output this task needs first (understand the
  code before threat-modeling it; derive test cases only AFTER the code review
  and threat model that produce the findings they verify). Independent tasks
  should have NO dependency so they can run in parallel.
- For a general "assess / review / secure this app" request, produce a FULL
  assessment: a code_review task and a threat_model task (independent — same
  parallel_group), then a test_case task that depends on BOTH and turns their
  findings into a prioritized security test plan.{verify_rule}
- Put independent tasks that can run at the same time in the same
  "parallel_group" (a short label); leave it empty for strictly-ordered tasks.
- Only use agents from the list above; 2-6 tasks total. Each "task" is a concrete
  instruction.

Return ONLY JSON:
{{"tasks": [{{"id": "t1", "agent": "<name>", "task": "<instruction>",
  "depends_on": [], "parallel_group": ""}}]}}

USER REQUEST: {request}
"""

# Inserted into _DAG_PLANNER_PROMPT when the opt-in verify agent is registered.
# Kept as a separate string so unavailable-agent runs never leak guidance
# telling the LLM to schedule a task the runner can't execute.
_VERIFY_RULE = """
- When a `verify` agent is available AND the request is a full assessment,
  ALSO add a verify task that depends on code_review — its job is to take
  each confirmed data-flow finding and attempt a sandboxed PoC to promote it
  from static-only to runtime-confirmed. Place verify AFTER code_review and
  BEFORE (or parallel to) test_case; verify's outputs are context for
  test_case, not the other way round."""

_ROUTER_PROMPT = """Choose the SINGLE best agent to handle the user's request.

Available agents:
{catalog}

Reply with ONLY the agent name (one word from the list). No explanation.

REQUEST: {request}
"""


def _clip(text: str, limit: int) -> str:
    """Trim to ``limit`` chars and say so — silent truncation reads as absence."""
    text = text or ""
    if len(text) <= limit:
        return text
    return (
        text[:limit].rstrip()
        + f"\n\n[... truncated: {len(text) - limit} more characters]"
    )


def _merge_outputs(sections: list[tuple[str, str]], budget: int) -> str:
    """Join ``(header, body)`` outputs into one blob, fairly sharing ``budget``.

    Slicing the *concatenation* lets the first long report eat the whole budget,
    so later agents' work never reaches the reader at all — which a synthesizing
    model then honestly describes as "output not received", even though the agent
    delivered. Each section gets its own share instead; shortest first, so
    whatever a small section doesn't use is handed to the longer ones and clipping
    only happens when the budget is genuinely tight.
    """
    if not sections:
        return ""
    order = range(len(sections))
    left, clipped = budget, {}
    for n, i in enumerate(sorted(order, key=lambda i: len(sections[i][1]))):
        share = max(1, left // (len(sections) - n))
        clipped[i] = _clip(sections[i][1], share)
        left -= len(clipped[i])
    return "\n\n".join(f"### {sections[i][0]}\n{clipped[i]}" for i in order)


_SYNTHESIS_PROMPT = """You are the lead application-security engineer. Merge
the specialist agents' outputs below into ONE report. This came from a task graph
in which some tasks may have failed or been skipped — be honest about coverage.

Requirements:
- Deduplicate overlapping findings and correlate related ones (e.g. a review
  finding that a later task corroborated or contradicted — say which won and why).
- PRESERVE DISAGREEMENT: when two agents conflict, surface both positions rather
  than silently picking one.
- Separate CONFIRMED findings (verified / live-reproduced) from HYPOTHESES
  (static-only, unconfirmed) into distinct sections. Never present a hypothesis
  as confirmed.
- Prioritize by risk.

Structure the report as:
1. Executive summary
2. Confirmed findings (by severity) — from the code review
3. Hypotheses / needs verification (by severity)
4. Attack surface / threats — from the threat model
5. Security test cases to investigate — if a test_case agent produced a list of
   test cases, reproduce that full, prioritized list here (keep the IDs, steps,
   expected results, and traceability); do NOT collapse it into a sentence.
6. Prioritized remediation roadmap
7. Coverage & limitations — what was and was NOT examined, and any task that
   failed or was skipped (listed below), so the reader knows the gaps.

USER REQUEST: {request}

EXECUTION COVERAGE:
{coverage}

SPECIALIST OUTPUTS:
{outputs}
"""


class Orchestrator:
    def __init__(
        self,
        llm: BaseChatModel,
        skills: SkillStore,
        config: Config,
        registry: AgentRegistry = REGISTRY,
        models: ModelRegistry | None = None,
    ) -> None:
        self.llm = llm
        self.skills = skills
        self.config = config
        self.registry = registry
        self.models = models

    def _model_for(self, agent_name: str) -> BaseChatModel:
        """The (possibly per-agent overridden) model for an agent."""
        if self.models is not None:
            return self.models.for_agent(agent_name)
        return self.llm

    # ------------------------------------------------------------- planning
    def plan(self, request: str) -> list[Step]:
        # Only plannable agents are offered: an assembly agent like
        # generate_report has to be invoked deliberately, never scheduled into
        # the middle of a run where it would report on findings not yet made.
        plannable = self.registry.plannable_names()
        prompt = _PLANNER_PROMPT.format(
            catalog=self.registry.catalog(only_plannable=True), request=request
        )
        try:
            data = _extract_json(message_text(self.llm.invoke(prompt)))
        except Exception:
            data = None

        steps: list[Step] = []
        if data and isinstance(data.get("plan"), list):
            for item in data["plan"]:
                name = item.get("agent")
                if name in plannable:
                    steps.append(Step(agent=name, task=item.get("task", request)))
        if not steps:  # fallback: run every agent on the raw request
            steps = [Step(agent=n, task=request) for n in plannable]
        return steps

    # -------------------------------------------------------------- routing
    def route(self, request: str) -> str:
        """Pick the single most appropriate agent for a request."""
        names = self.registry.plannable_names()
        prompt = _ROUTER_PROMPT.format(
            catalog=self.registry.catalog(only_plannable=True), request=request
        )
        try:
            text = message_text(self.llm.invoke(prompt)).strip()
        except Exception:
            text = ""
        # exact / substring match against known agent names
        low = text.lower()
        for n in names:
            if n == low or n in low.split():
                return n
        for n in names:
            if n in low:
                return n
        return self._heuristic_route(request)

    def _heuristic_route(self, request: str) -> str:
        """Keyword fallback when the LLM router is unhelpful."""
        words = set(re.findall(r"[a-z0-9]+", request.lower()))
        best, best_score = self.registry.plannable_names()[0], -1
        for spec in self.registry.specs():
            if not spec.plannable:
                continue
            hay = f"{spec.name} {spec.description} {' '.join(spec.tags)}".lower()
            score = sum(1 for w in words if w in hay)
            if score > best_score:
                best, best_score = spec.name, score
        return best

    # -------------------------------------------------------------- running
    def run_agent(
        self, name: str, task: str, context: str = "", quiet: bool = False
    ) -> str:
        spec = self.registry.get(name)
        if spec.runner is not None:
            # An assembly agent: its output is built from stored artifacts, not
            # written by a tool-calling loop. See AgentSpec.runner.
            return spec.runner(
                task, config=self.config, llm=self._model_for(name), context=context
            )
        agent = Agent(
            spec, self._model_for(name), self.skills, self.config, quiet=quiet
        )
        return agent.run(task, extra_context=context)

    def save_agent_report(self, name: str, task: str, output: str) -> str:
        """Persist ONE agent's final output under ``reports_dir``; returns the path.

        A direct single-agent run (``phrak agent <name> ...``, ``/<name>`` in
        chat) skips the pipeline's consolidated report, so its output — including
        the structured findings the agent appends — would otherwise be lost once
        the terminal scrolls. The timestamp leads the filename so the shared
        ``report-*.md`` glob still sorts and prunes chronologically.
        """
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        path = self.config.reports_dir() / f"report-{ts}-{name}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "\n".join(
                [
                    f"# {name} Report — {ts}",
                    f"\n**Agent:** {name}",
                    f"\n**Task:** {task}\n",
                    "## Output\n",
                    output,
                    "",
                ]
            )
        )
        self._prune_reports()
        return str(path)

    # --------------------------------------------------------- DAG planning
    def plan_dag(self, request: str) -> list[Task]:
        """Plan a dependency graph of tasks. Falls back to a linear DAG."""
        # Only inject the verify-agent scheduling rule when it's actually
        # available — otherwise the planner would confidently emit a task
        # that plan_dag would then drop and the run would proceed without
        # the verification step the user thought they configured.
        verify_rule = _VERIFY_RULE if "verify" in self.registry.names() else ""
        prompt = _DAG_PLANNER_PROMPT.format(
            catalog=self.registry.catalog(only_plannable=True),
            request=request,
            verify_rule=verify_rule,
        )
        data = None
        try:
            data = _extract_json(message_text(self.llm.invoke(prompt)))
        except Exception:
            data = None

        tasks: list[Task] = []
        names = set(self.registry.plannable_names())
        if data and isinstance(data.get("tasks"), list):
            seen_ids: set[str] = set()
            for item in data["tasks"]:
                agent = item.get("agent")
                tid = str(item.get("id") or f"t{len(tasks) + 1}")
                if agent not in names or tid in seen_ids:
                    continue
                seen_ids.add(tid)
                deps = [str(d) for d in (item.get("depends_on") or [])]
                tasks.append(
                    Task(
                        id=tid,
                        agent=agent,
                        task=item.get("task", request),
                        depends_on=deps,
                        parallel_group=str(item.get("parallel_group") or ""),
                    )
                )
            # drop dangling dependencies the model may have invented
            valid = {t.id for t in tasks}
            for t in tasks:
                t.depends_on = [d for d in t.depends_on if d in valid and d != t.id]
        if not tasks:  # fall back to a linear DAG from the flat planner
            prev = ""
            for i, step in enumerate(self.plan(request), 1):
                tid = f"t{i}"
                tasks.append(
                    Task(
                        id=tid,
                        agent=step.agent,
                        task=step.task,
                        depends_on=[prev] if prev else [],
                    )
                )
                prev = tid
        return tasks

    def run(
        self,
        request: str,
        plan: Optional[list[Step]] = None,
        on_step=None,
    ) -> dict:
        """Execute the full pipeline. ``on_step(i, step)`` is an optional progress
        callback. Returns {"plan", "steps": [...], "dag", "report", "report_path"}.

        There is one execution engine — the task DAG (:meth:`_execute`). A DAG
        plan (``config.orchestrator.mode == 'dag'``, the default) can express real
        independence and fan out in parallel; a linear plan is just the degenerate
        case — a strictly-sequential chain where each step depends on every earlier
        one, so it runs in order and sees all prior outputs as context. An explicit
        ``plan`` (list of :class:`Step`) is always run as that sequential chain.
        """
        if plan is not None:
            tasks = self._sequential_tasks(plan)
        else:
            mode = getattr(
                getattr(self.config, "orchestrator", None), "mode", "linear"
            )
            tasks = (
                self.plan_dag(request)
                if mode == "dag"
                else self._sequential_tasks(self.plan(request))
            )
        return self._execute(request, tasks, on_step=on_step)

    @staticmethod
    def _sequential_tasks(steps: list[Step]) -> list[Task]:
        """A linear plan as a fully-sequential DAG chain.

        Each task depends on EVERY earlier one, which pins strict ordering (no
        step is ready until all before it are done) and, through the executor's
        dependency-scoped context, feeds each step every prior step's output —
        the "sees all earlier findings" behaviour the linear pipeline relied on.
        """
        tasks: list[Task] = []
        for i, step in enumerate(steps, 1):
            tasks.append(
                Task(
                    id=f"t{i}",
                    agent=step.agent,
                    task=step.task,
                    depends_on=[t.id for t in tasks],
                )
            )
        return tasks

    def run_single(self, request: str, on_step=None) -> dict:
        """Fast path: route to one best-fit agent and run only it (no synthesis)."""
        name = self.route(request)
        step = Step(agent=name, task=request)
        if on_step:
            on_step(1, step)
        output = self.run_agent(name, request)
        outputs = [{"agent": name, "task": request, "output": output}]
        report_path = self._save_report(request, [step], outputs, output)
        return {
            "plan": [step],
            "steps": outputs,
            "report": output,
            "report_path": report_path,
            "routed_to": name,
        }

    # ----------------------------------------------------------- DAG running
    def run_dag(
        self,
        request: str,
        plan: Optional[list[Task]] = None,
        on_step=None,
    ) -> dict:
        """Plan (if needed) and execute a task DAG. Thin wrapper over the shared
        :meth:`_execute` engine, kept as a named entry point for callers that
        already hold a :class:`Task` plan."""
        return self._execute(request, plan or self.plan_dag(request), on_step=on_step)

    def _execute(
        self,
        request: str,
        tasks: list[Task],
        on_step=None,
    ) -> dict:
        """The single execution engine: run a task DAG with bounded parallel
        fan-out and partial-failure isolation, then synthesize. Returns
        {"plan", "steps", "dag", "report", "report_path"}."""
        import concurrent.futures as cf
        import threading

        from .store import FindingStore, TestCaseStore

        # Snapshot the durable stores so we can tell whether the agents recorded
        # anything THIS run. If they did, we trust their precise items; if they
        # didn't (a weak model that only wrote prose), we salvage the findings
        # and test cases out of the synthesized report below.
        n_find_before = len(FindingStore(self.config).list())
        n_tc_before = len(TestCaseStore(self.config).list())

        by_id = {t.id: t for t in tasks}
        max_workers = max(
            1, getattr(getattr(self.config, "orchestrator", None), "max_concurrency", 3)
        )
        continue_on_failure = getattr(
            getattr(self.config, "orchestrator", None), "continue_on_failure", True
        )

        lock = threading.Lock()
        step_counter = {"n": 0}

        def deps_done(t: Task) -> bool:
            return all(by_id[d].status == "done" for d in t.depends_on if d in by_id)

        def deps_failed(t: Task) -> bool:
            return any(
                by_id[d].status in ("failed", "skipped")
                for d in t.depends_on
                if d in by_id
            )

        def context_for(t: Task) -> str:
            deps = [by_id[d] for d in t.depends_on if d in by_id and by_id[d].artifact]
            if not deps:
                return ""
            # Budgeted against the *consumer's* model: a task told to trace its
            # work back to a dependency's findings needs to actually be shown
            # them, and how much fits depends on which model is reading.
            budget = prompt_char_budget(self.config.llm_for(t.agent))
            return _merge_outputs([(d.agent, d.artifact) for d in deps], budget)

        def execute(t: Task) -> None:
            t.status = "running"
            if on_step:
                with lock:
                    step_counter["n"] += 1
                    n = step_counter["n"]
                on_step(n, t)
            try:
                # quiet=True unless we're strictly serial (single worker), so
                # concurrent agents don't fight over the terminal spinner.
                t.artifact = self.run_agent(
                    t.agent, t.task, context=context_for(t), quiet=max_workers > 1
                )
                t.status = "done"
            except Exception as e:  # partial-failure isolation
                t.status = "failed"
                t.error = str(e)
                t.artifact = f"[task failed: {e}]"

        # Wave-by-wave scheduling: run all currently-ready tasks concurrently
        # (bounded by max_workers), then re-evaluate as results land.
        with cf.ThreadPoolExecutor(max_workers=max_workers) as pool:
            pending = {t.id for t in tasks}
            while pending:
                ready = [
                    by_id[i]
                    for i in list(pending)
                    if by_id[i].status == "pending" and deps_done(by_id[i])
                ]
                # tasks whose deps failed can never run — skip them (isolation)
                for i in list(pending):
                    t = by_id[i]
                    if t.status == "pending" and deps_failed(t):
                        t.status = "skipped"
                        t.artifact = "[skipped: a prerequisite task failed]"
                        pending.discard(i)
                        if not continue_on_failure:
                            for j in list(pending):
                                by_id[j].status = "skipped"
                                by_id[j].artifact = "[skipped: run aborted]"
                                pending.discard(j)
                if not ready:
                    if not pending:
                        break
                    # nothing ready but tasks remain and none can run -> break the
                    # deadlock (e.g. a dependency cycle) by skipping the rest.
                    if all(by_id[i].status == "pending" for i in pending) and not any(
                        deps_done(by_id[i]) for i in pending
                    ):
                        for i in list(pending):
                            by_id[i].status = "skipped"
                            by_id[i].artifact = "[skipped: unsatisfiable dependency]"
                            pending.discard(i)
                        break
                    continue
                futures = {pool.submit(execute, t): t for t in ready}
                for i in [t.id for t in ready]:
                    pending.discard(i)
                for fut in cf.as_completed(futures):
                    fut.result()  # execute() never raises; this just joins

        outputs = [
            {
                "agent": t.agent,
                "task": t.task,
                "output": t.artifact,
                "status": t.status,
                "id": t.id,
            }
            for t in tasks
        ]
        # Persist each specialist's own report so generate_report can quote it.
        # A pipeline run otherwise only saves the consolidated report, leaving
        # generate_report with no threat_model / code_review section to include.
        self._save_section_reports(tasks)

        report = self._synthesize(request, tasks)
        self._salvage_from_report(
            report,
            recover_findings=len(FindingStore(self.config).list()) == n_find_before,
            recover_test_cases=len(TestCaseStore(self.config).list()) == n_tc_before,
        )
        # Now that findings exist (recorded by the agents or salvaged above), make
        # sure every one — including unconfirmed findings — has a test case.
        self._ensure_coverage()
        report_path = self._save_report(request, tasks, outputs, report)
        return {
            "plan": tasks,
            "steps": outputs,
            "dag": tasks,
            "report": report,
            "report_path": report_path,
        }

    # ---------------------------------------------------------- synthesize
    def _synthesize(self, request: str, tasks: list[Task]) -> str:
        done = [t for t in tasks if t.status == "done"]
        if not done:
            # Include each task's error: this is the one branch the user reads
            # when nothing worked, so leaving the reason out (it was only in the
            # saved report's raw-output section) hides exactly what they need.
            return "\n".join(
                ["No task completed successfully."]
                + [
                    f"- {t.id} [{t.agent}] {t.status}"
                    + (f": {t.error}" if t.error else "")
                    for t in tasks
                ]
            )
        if len(done) == 1 and len(tasks) == 1:
            return done[0].artifact
        coverage_lines = []
        for t in tasks:
            note = f" — {t.error}" if t.error else ""
            coverage_lines.append(f"- {t.id} [{t.agent}] {t.status}: {t.task}{note}")
        joined = _merge_outputs(
            [(f"{t.agent} (task {t.id}: {t.task})", t.artifact) for t in done],
            prompt_char_budget(self.config.llm),
        )
        prompt = _SYNTHESIS_PROMPT.format(
            request=request, coverage="\n".join(coverage_lines), outputs=joined
        )
        try:
            return message_text(self.llm.invoke(prompt))
        except Exception as e:
            return joined + f"\n\n[synthesis failed: {e}]"

    def _salvage_from_report(
        self,
        report: str,
        recover_findings: bool,
        recover_test_cases: bool,
    ) -> None:
        """Populate the stores from the consolidated report when the agents didn't.

        On a weak local model an agent can produce only a prose report and record
        nothing structured — yet the synthesized report is full of concrete
        findings and test cases. Rather than leave /findings and /testcases empty,
        parse them deterministically out of the report text. Only runs for a track
        the agents left empty this run, so precise agent-recorded items are never
        shadowed by vaguer salvaged ones.
        """
        if not report or not (recover_findings or recover_test_cases):
            return
        from . import extract
        from .banner import GREY, RESET
        from .store import FindingStore, TaintStore, TestCaseStore
        from .tools.common import workspace

        try:
            ws = workspace()
        except Exception:
            ws = None
        n_f = n_t = 0
        try:
            if recover_findings:
                findings = extract.findings_from_report(
                    report, source_agent="synthesis", workspace=ws
                )
                if findings:
                    FindingStore(self.config).upsert(findings, run_id="synthesis")
                    TaintStore(self.config).upsert(findings, run_id="synthesis")
                    n_f = len(findings)
            if recover_test_cases:
                cases = extract.test_cases_from_report(report, source_agent="synthesis")
                if cases:
                    TestCaseStore(self.config).upsert(cases)
                    n_t = len(cases)
        except Exception as e:  # salvage is best-effort, never fails the run
            print(f"  {GREY}(could not salvage items from report: {e}){RESET}")
            return
        if n_f or n_t:
            got = ", ".join(
                p
                for p in (
                    f"{n_f} finding(s)" if n_f else "",
                    f"{n_t} test case(s)" if n_t else "",
                )
                if p
            )
            print(
                f"  {GREY}salvaged {got} from the consolidated report "
                f"(agents recorded none){RESET}"
            )

    def _save_section_reports(self, tasks: list[Task]) -> None:
        """Save each completed threat_model / code_review task as its own report.

        generate_report quotes the latest ``report-<ts>-<agent>.md`` for those
        agents; a pipeline run only writes the consolidated report, so without
        this those sections show as 'no report found' placeholders even though
        the agents ran. Best-effort — a save failure never fails the run.
        """
        from .report import SECTION_AGENTS

        wanted = {a for a, _ in SECTION_AGENTS}
        for t in tasks:
            if t.agent not in wanted or t.status != "done":
                continue
            body = (t.artifact or "").strip()
            if not body or body.startswith("[task "):
                continue  # nothing usable (failed/skipped placeholder)
            try:
                self.save_agent_report(t.agent, t.task, t.artifact)
            except Exception as e:  # pragma: no cover - defensive
                from .banner import GREY, RESET

                print(f"  {GREY}(could not save {t.agent} report: {e}){RESET}")

    def _ensure_coverage(self) -> None:
        """Link/backfill test cases so every finding has one. Best-effort."""
        from .banner import GREY, RESET
        from .coverage import ensure_test_case_coverage

        try:
            r = ensure_test_case_coverage(self.config)
        except Exception as e:  # pragma: no cover - defensive
            print(f"  {GREY}(could not reconcile test-case coverage: {e}){RESET}")
            return
        bits = []
        if r.get("linked"):
            bits.append(f"linked {r['linked']} test case(s) to findings")
        if r.get("generated"):
            bits.append(f"added {r['generated']} verification test case(s)")
        if bits:
            print(f"  {GREY}coverage: {', '.join(bits)}{RESET}")

    def _save_report(
        self, request: str, plan: list[Step], outputs: list[dict], report: str
    ) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        path = self.config.reports_dir() / f"report-{ts}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        body = [
            f"# AppSec Report — {ts}",
            f"\n**Request:** {request}\n",
            "## Plan",
            "\n".join(f"{i}. **{s.agent}** — {s.task}" for i, s in enumerate(plan, 1)),
            "\n## Consolidated Report\n",
            report,
            "\n---\n## Raw agent outputs\n",
        ]
        for o in outputs:
            body.append(f"### {o['agent']}\n\n{o['output']}\n")
        path.write_text("\n".join(body))
        self._prune_reports()
        return str(path)

    def _prune_reports(self) -> None:
        keep = self.config.keep_reports
        if not keep or keep <= 0:
            return
        d = self.config.reports_dir()
        files = sorted(d.glob("report-*.md"))
        for f in files[:-keep]:
            try:
                f.unlink()
            except OSError:
                pass
