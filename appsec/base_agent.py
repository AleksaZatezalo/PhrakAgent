"""
Description: Base agent + registry.
Author: Aleksa Zatezalo
Date Created: 08-01-2026
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import BaseTool

from . import file_assist
from .config import Config
from .llm import message_text
from .skill_store import SkillStore

# A tool factory returns the tools for an agent. It's a callable (not a static
# list) so tools that need config/runtime are built lazily at agent creation.
ToolFactory = Callable[[], list]


@dataclass
class AgentSpec:
    name: str
    description: str  # one line — shown to the orchestrator for routing
    system_prompt: str
    tool_factory: ToolFactory = field(default=lambda: [])
    tags: list[str] = field(default_factory=list)
    # Sections the final report MUST contain for the run to be considered
    # complete. Each entry may list alternatives with "|". The agent is nudged
    # to keep working until all are present (run-to-completion).
    report_sections: list[str] = field(default_factory=list)
    # When True, every curated skill's full body is front-loaded into the system
    # prompt (skill_library.playbook). When False, only a one-line index is
    # injected and the agent pulls a procedure on demand via load_skill — much
    # smaller prompt, fewer completion rounds. Turn off for skill-heavy agents
    # whose prompt would otherwise blow past the model's context window.
    inline_skills: bool = True


class AgentRegistry:
    """Central registry of available agents. Built-ins register here."""

    def __init__(self) -> None:
        self._specs: dict[str, AgentSpec] = {}

    def register(self, spec: AgentSpec, *, override: bool = False) -> AgentSpec:
        if spec.name in self._specs and not override:
            raise ValueError(f"Agent '{spec.name}' already registered")
        self._specs[spec.name] = spec
        return spec

    def get(self, name: str) -> AgentSpec:
        if name not in self._specs:
            raise KeyError(
                f"Unknown agent '{name}'. Available: {', '.join(self.names())}"
            )
        return self._specs[name]

    def names(self) -> list[str]:
        return sorted(self._specs)

    def specs(self) -> list[AgentSpec]:
        return [self._specs[n] for n in self.names()]

    def catalog(self) -> str:
        """Human/LLM readable list of agents for routing prompts."""
        return "\n".join(f"- {s.name}: {s.description}" for s in self.specs())


# The single global registry used across the process.
REGISTRY = AgentRegistry()


def register_agent(spec: AgentSpec, *, override: bool = False) -> AgentSpec:
    return REGISTRY.register(spec, override=override)


class Agent:
    """Runs an :class:`AgentSpec` as a tool-calling loop, grounded in skills."""

    def __init__(
        self,
        spec: AgentSpec,
        llm: BaseChatModel,
        skills: SkillStore,
        config: Config,
        quiet: bool = False,
    ) -> None:
        self.spec = spec
        self.llm = llm
        self.skills = skills
        self.config = config
        # quiet=True suppresses the live spinner and prefixes tool lines with the
        # agent name — used when several agents run concurrently (parallel fan-out)
        # so their output doesn't clobber a shared terminal with competing spinners.
        self.quiet = quiet
        # why the most recent turn stopped — see _drive / _wrap_up_if_exhausted
        self._budget_exhausted = False
        self._error = ""
        # every agent can pause to ask questions, request permission, and load
        # its curated skills on demand
        from .tools.interaction import interaction_tools
        from .tools.skills_tool import skill_tools

        self.tools: list[BaseTool] = (
            list(spec.tool_factory()) + interaction_tools() + skill_tools()
        )

    def _note(self, msg: str) -> None:
        """Emit a grey progress line on the same stdout channel as the tool-call
        lines, so a long run visibly shows activity between tool calls. In quiet
        (parallel) mode the line carries the agent-name tag like tool lines do."""
        from .banner import GREY, RESET

        tag = f"[{self.spec.name}] " if getattr(self, "quiet", False) else ""
        print(f"  {GREY}{tag}… {msg}{RESET}")

    def _system_prompt(self, task: str) -> str:
        from . import skill_library

        learned = self.skills.skills_block(f"{self.spec.name}: {task}")
        base = self.spec.system_prompt
        parts = [base]
        # Front-load ALL of this agent's curated skills so it runs every one,
        # rather than optionally pulling them via load_skill. Skill-heavy agents
        # (inline_skills=False) instead get a one-line index and load procedures
        # on demand, keeping the prompt small enough to fit the context window.
        if self.spec.inline_skills:
            skills = skill_library.playbook(self.spec.name)
        else:
            skills = skill_library.index(self.spec.name)
        if skills:
            parts.append(skills)
        if self.spec.report_sections:
            required = ", ".join(s.split("|")[0] for s in self.spec.report_sections)
            parts.append(
                "Do NOT stop until you have produced a COMPLETE report containing "
                f"every required section: {required}. Keep using your tools until "
                "the report is thorough. If you are genuinely blocked, call "
                "ask_user; for sensitive actions call request_permission — but "
                "otherwise keep working to completion."
            )
        if learned:
            parts.append(learned)
        return "\n\n".join(parts)

    def run(self, task: str, extra_context: str = "") -> str:
        import uuid

        from langchain.agents import create_agent

        from .middleware import VerbalizedToolCallMiddleware
        from .runtime import (
            begin_findings,
            begin_tool_ledger,
            set_active_agent,
        )

        self._run_id = uuid.uuid4().hex[:12]
        self._error = ""
        set_active_agent(self.spec.name)
        begin_findings()  # capture structured findings emitted via report_finding
        begin_tool_ledger()  # track which tools actually executed (live-test gate)
        graph = create_agent(
            self.llm,
            self.tools,
            system_prompt=self._system_prompt(task),
            middleware=[
                VerbalizedToolCallMiddleware(
                    enabled=self.config.llm.provider.lower() != "anthropic"
                )
            ],
            checkpointer=_make_saver(),  # keep context across completion rounds
        )
        cfg = {
            "configurable": {"thread_id": uuid.uuid4().hex},
            "recursion_limit": self.config.max_steps,
        }

        user = task if not extra_context else f"{task}\n\nContext:\n{extra_context}"
        # Front-load the real workspace file tree so the model reads actual
        # files instead of hallucinating names (e.g. asking for "app.py").
        overview = file_assist.workspace_overview(self.tools)
        if overview:
            user = f"{user}\n\n{overview}"
        self._note(f"{self.spec.name}: analyzing the workspace and drafting the report")
        answer = self._best(self._drive(graph, user, cfg), "")
        answer = self._wrap_up_if_exhausted(graph, cfg, answer)

        # run-to-completion: nudge until every required report section is present.
        rounds = 1
        while rounds < max(1, self.config.max_rounds):
            missing = self._incomplete_sections(answer)
            if not missing:
                break
            self._note(
                f"{self.spec.name}: completion round {rounds + 1}/"
                f"{max(1, self.config.max_rounds)} — still working"
            )
            from .banner import GREY, RESET

            # If the model stalled by asking the user to hand it code, read the
            # files itself and feed them back instead of a generic nudge.
            injected = file_assist.maybe_satisfy_file_request(self.tools, answer)
            if injected:
                print(
                    f"  {GREY}… reading files it asked for instead of "
                    f"waiting on you{RESET}"
                )
                answer = self._best(self._drive(graph, injected, cfg), answer)
            else:
                print(
                    f"  {GREY}… report incomplete (missing: "
                    f"{', '.join(missing)}); continuing{RESET}"
                )
                cont = (
                    "Your report is INCOMPLETE — it is missing these required "
                    f"sections: {', '.join(missing)}. Continue using your tools "
                    "as needed, then output the COMPLETE final report containing "
                    "ALL required sections. Do not stop until every section is "
                    "present. NEVER ask the user to paste code — read it "
                    "yourself with read_file."
                )
                answer = self._best(self._drive(graph, cont, cfg), answer)
            answer = self._wrap_up_if_exhausted(graph, cfg, answer)
            rounds += 1

        self._note(f"{self.spec.name}: compiling the final report")
        if not answer:
            # Nothing usable at all. A provider-level failure (bad key, rate
            # limit, context overflow) is the caller's problem to see, so it is
            # re-raised; a model that merely burned its budget still leaves tool
            # results and findings worth reporting.
            if self._error:
                raise RuntimeError(f"{self.spec.name}: {self._error}")
            answer = self._fallback_report(task)
        answer = self._append_structured_findings(answer)
        return answer

    # -------------------------------------------------- turn-outcome handling
    # Wrapping up costs a model turn plus the odd stray tool call; more than that
    # means the model is still looping and the fallback report takes over.
    _FINALIZE_STEPS = 6

    _FINALIZE_PROMPT = (
        "STOP using tools — this round's tool budget is spent and no further "
        "tool call will run. Using ONLY what you have already gathered, write "
        "the COMPLETE final report now, including every required section. If a "
        "section is unsupported by what you found, say so explicitly instead of "
        "leaving it out."
    )

    def _wrap_up_if_exhausted(self, graph, cfg: dict, answer: str) -> str:
        """Ask for a write-up when a turn died on the step budget.

        Hitting ``max_steps`` used to raise straight out of the agent and fail
        the whole task, discarding every tool result the model had gathered. A
        model deep in a tool loop has usually seen enough to write *something*,
        so it gets one short, tool-free turn to do that.
        """
        if not self._budget_exhausted:
            return answer
        self._note(f"{self.spec.name}: step budget spent — writing up what it has")
        wrap_cfg = {**cfg, "recursion_limit": self._FINALIZE_STEPS}
        answer = self._best(self._drive(graph, self._FINALIZE_PROMPT, wrap_cfg), answer)
        self._budget_exhausted = False  # the wrap-up turn may exhaust its own
        return answer

    def _best(self, candidate: str, current: str) -> str:
        """Keep whichever of two answers is the more complete report.

        Turns can end on junk — a nudge that only produced protocol noise, a
        wrap-up cut short — and blindly taking the newest text would throw away a
        good earlier draft. Fewer missing required sections wins; length breaks
        the tie; a tie goes to the newer text.
        """
        from .ui import strip_thoughts

        cand, cur = strip_thoughts(candidate), strip_thoughts(current)
        if not cand or not cur:
            return cand or cur

        def rank(text: str) -> tuple[int, int]:
            return (-len(self._incomplete_sections(text)), len(text))

        return cand if rank(cand) >= rank(cur) else cur

    def _fallback_report(self, task: str) -> str:
        """Stand-in report for a run that produced no prose at all.

        The tools still ran and their findings are still recorded, so an honest
        note about what happened beats handing the orchestrator an empty string
        (which reads downstream as "this agent had nothing to say").
        """
        from .runtime import ran_tools

        used = sorted({name for name, _ in ran_tools()})
        return "\n".join(
            [
                f"## {self.spec.name}: incomplete run",
                "",
                f"**Task:** {task}",
                "",
                f"The model exhausted its step budget (`max_steps: {self.config.max_steps}`) "
                "without producing a report.",
                f"Tools that did run: {', '.join(used) if used else 'none'}.",
                "",
                "Any validated findings from this run are listed below. For a full "
                "report, narrow the task, raise `max_steps`, or use a stronger model.",
            ]
        )

    # -------------------------------------------------- structured findings
    def _append_structured_findings(self, answer: str) -> str:
        """Render any validated findings captured during the run into the report."""
        from .runtime import take_findings

        findings = take_findings()
        if not findings:
            return answer
        from .models.findings import dedupe_findings

        findings = dedupe_findings(findings)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: (order.get(f.severity, 5), -f.confidence))
        self._note(f"{self.spec.name}: recorded {len(findings)} structured finding(s)")
        self._persist_findings(findings)
        n_unconf = sum(1 for f in findings if f.status == "unconfirmed")
        n_grounded = len(findings) - n_unconf
        parts = [
            "",
            "---",
            "## Structured Findings (validated)",
            f"_{len(findings)} finding(s): {n_grounded} grounded, {n_unconf} "
            "unconfirmed. Evidence checked against the workspace._",
            "",
        ]
        for f in findings:
            parts.append(f.to_markdown())
            parts.append("")
        return answer + "\n".join(parts)

    def _persist_findings(self, findings: list) -> None:
        """Record this run's findings into the durable cross-run history store.

        Best-effort: history is a convenience layer, never allowed to fail a run.
        """
        try:
            from .store import FindingStore, TaintStore

            run_id = getattr(self, "_run_id", "")
            FindingStore(self.config).upsert(findings, run_id=run_id)
            TaintStore(self.config).upsert(findings, run_id=run_id)
        except Exception:
            pass

    def _incomplete_sections(self, text: str) -> list[str]:
        low = (text or "").lower()
        missing = []
        for section in self.spec.report_sections:
            alts = [a.strip() for a in section.split("|") if a.strip()]
            if alts and not any(a in low for a in alts):
                missing.append(alts[0])
        return missing

    def _drive(self, graph, message: str, cfg: dict) -> str:
        """Stream one turn, showing a spinner + live tool activity.

        Never raises: a turn that dies on the step budget or on a provider error
        still returns whatever text streamed before it stopped, and records why
        it stopped in ``_budget_exhausted`` / ``_error`` for :meth:`run`.
        """
        from langgraph.errors import GraphRecursionError

        from .banner import DIM, GREEN, GREY, RESET
        from .ui import Spinner

        # In quiet (parallel) mode the spinner is a no-op and tool lines carry an
        # agent-name prefix so interleaved output stays attributable.
        spinner = None if self.quiet else Spinner(f"{self.spec.name} working")
        tag = f"[{self.spec.name}] " if self.quiet else ""
        answer = ""
        self._budget_exhausted = False
        if spinner:
            spinner.start()
        try:
            for chunk in graph.stream(
                {"messages": [HumanMessage(content=message)]},
                cfg,
                stream_mode="updates",
            ):
                if spinner:
                    spinner.stop()
                interactive = False
                for _node, update in chunk.items():
                    for m in (update or {}).get("messages", []):
                        if isinstance(m, AIMessage):
                            for call in getattr(m, "tool_calls", None) or []:
                                name = call.get("name")
                                args = call.get("args", {})
                                preview = ", ".join(
                                    f"{k}={str(v)[:40]}" for k, v in args.items()
                                )
                                print(f"  {GREY}{tag}⚙ {name}({preview}){RESET}")
                                if name in ("ask_user", "request_permission"):
                                    interactive = True
                            if m.content:
                                answer = message_text(m)
                                # Echo a short preview of the model's narration so
                                # long generation turns visibly show progress (the
                                # full text is still stripped/kept for the report).
                                from .ui import strip_thoughts

                                shown = strip_thoughts(answer).strip()
                                first = shown.splitlines()[0] if shown else ""
                                if first:
                                    print(f"  {DIM}{GREY}{tag}✎ {first[:80]}{RESET}")
                        elif isinstance(m, ToolMessage):
                            c = message_text(m)
                            first = c.strip().splitlines()[0] if c.strip() else ""
                            print(f"  {DIM}{GREEN}{tag}↳ {m.name}: {first[:80]}{RESET}")
                # leave spinner off while an interactive tool reads stdin
                if spinner and not interactive:
                    spinner.start()
        except KeyboardInterrupt:
            answer = answer or "[interrupted]"
        except GraphRecursionError:
            # Out of graph steps mid-turn. Common with smaller local models,
            # which loop on tool calls; the partial text is kept and run() asks
            # for a wrap-up rather than failing the task.
            self._budget_exhausted = True
            if spinner:
                spinner.stop()
            print(
                f"  {GREY}{tag}… step budget "
                f"({cfg.get('recursion_limit')}) spent{RESET}"
            )
        except Exception as e:
            # Provider-side failure (auth, rate limit, context overflow). Held,
            # not raised: run() re-raises it only if the run produced nothing,
            # so a late failure can't discard a report that's already written.
            self._error = str(e)
            if spinner:
                spinner.stop()
            print(f"  {GREY}{tag}… turn failed: {e}{RESET}")
        finally:
            if spinner:
                spinner.stop()
        return answer


def _make_saver():
    try:
        from langgraph.checkpoint.memory import InMemorySaver

        return InMemorySaver()
    except Exception:
        from langgraph.checkpoint.memory import MemorySaver

        return MemorySaver()
