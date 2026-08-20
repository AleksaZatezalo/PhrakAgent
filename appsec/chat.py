"""
Description: Conversational chat session — talk to PHRAK like you talk to Claude Code.
Author: Aleksa Zatezalo
Date Created: 08-01-2026
"""

from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from .banner import BGREEN, CYAN, DIM, GREEN, GREY, RESET, phrak_print
from .llm import message_text

THREAD_ID = "phrak-chat"

SYSTEM_PROMPT = """You are PHRAK, an expert application-security assistant that
works conversationally, like a pair-hacking partner. You focus on two things for
the codebase in the current workspace: security CODE REVIEW and THREAT MODELING.

You have tools — USE THEM, don't guess:
- Explore code: list_dir, read_file, search_code (paths are RELATIVE to the
  workspace root; always list_dir(".") first to orient yourself).
- Static analysis: opengrep_scan (Opengrep) for vulnerabilities and scan_secrets
  for hardcoded credentials/keys. Verify hits by reading the code.
- Architecture: fingerprint_stack, analyze_dependencies — to understand
  frameworks, libraries, and entry points for threat modeling.

What you do:
- Code review: find vulnerabilities (OWASP/CWE) and report them with file:line,
  severity, why they're exploitable, and a concrete fix.
- Threat modeling: identify trust boundaries, data flows, and STRIDE threats,
  then prioritize the most serious attack paths.

Rules:
- Actually call tools; do NOT print tool-call JSON as your answer.
- Ground every claim in code you have read; cite file:line.
- Be concise and direct. Ask a clarifying question only when genuinely blocked.
- You review and model threats only — you do not modify files or run scans.
"""


def _build_tools() -> list:
    from .tools.analysis import analysis_tools
    from .tools.filesystem import read_only_tools
    from .tools.opengrep_tools import opengrep_tools

    seen: dict[str, object] = {}
    for t in [
        *read_only_tools(),
        *analysis_tools(),
        *opengrep_tools(),
    ]:
        seen[t.name] = t  # dedupe by tool name
    return list(seen.values())


def _make_saver():
    try:
        from langgraph.checkpoint.memory import InMemorySaver

        return InMemorySaver()
    except Exception:  # older langgraph
        from langgraph.checkpoint.memory import MemorySaver

        return MemorySaver()


class ChatSession:
    """One multi-turn conversation with tool use and persistent thread memory."""

    def __init__(self, app) -> None:
        self.app = app
        self.last_answer = ""
        self.verbose = False
        self.tokens = {"input": 0, "output": 0, "turns": 0}
        self._model_name = None  # set to override the base model
        self._thread_seq = 0
        self._build()

    def _build(self) -> None:
        """(Re)build the underlying agent graph, e.g. after /clear or /model."""
        from langchain.agents import create_agent

        from .middleware import VerbalizedToolCallMiddleware

        llm = self._resolve_llm()
        self.model_desc = self._describe_llm()
        self.graph = create_agent(
            llm,
            _build_tools(),
            system_prompt=SYSTEM_PROMPT,
            middleware=[
                VerbalizedToolCallMiddleware(
                    enabled=self.app.config.llm.provider.lower() != "anthropic"
                )
            ],
            checkpointer=_make_saver(),
        )
        self._cfg = {
            "configurable": {"thread_id": f"{THREAD_ID}-{self._thread_seq}"},
            "recursion_limit": self.app.config.max_steps,
        }

    def _resolve_llm(self):
        if self._model_name:
            from dataclasses import replace

            cfg = replace(self.app.config.llm_for("chat"), model=self._model_name)
            return self.app.models.get(cfg)
        return self.app.models.for_agent("chat")  # allows agent_models: {chat: ...}

    def _describe_llm(self) -> str:
        if self._model_name:
            c = self.app.config.llm_for("chat")
            return f"{c.provider}:{self._model_name}"
        return self.app.models.describe("chat")

    # --------------------------------------------------------- session control
    def clear(self) -> None:
        """Forget the conversation so far (fresh thread + counters)."""
        self._thread_seq += 1
        self.last_answer = ""
        self._build()

    def switch_model(self, name: str) -> str:
        self._model_name = name.strip() or None
        self._build()
        return self.model_desc

    def cost_summary(self) -> str:
        """Chat's own usage plus everything else this process has spent.

        The process total matters more than the chat total: one ``/run`` costs
        far more than a conversation, and reporting only chat turns made ``/cost``
        read as 0 straight after a full multi-agent assessment.
        """
        from .runtime import usage_totals

        t = self.tokens
        total = usage_totals()
        provider = self.app.config.llm.provider
        charge = (
            "$0.00 (local Ollama — no API charge)"
            if provider == "ollama"
            else "provider-dependent"
        )
        return (
            f"chat turns  — input: {t['input']}, output: {t['output']}, "
            f"turns: {t['turns']}\n"
            f"this session — input: {total['input']}, output: {total['output']}, "
            f"model calls: {total['calls']}  "
            f"(includes /run, agents and reports)\n"
            f"estimated spend: {charge}"
        )

    def _account(self, msg) -> None:
        """Best-effort token accounting from provider metadata."""
        from .runtime import record_usage

        um = getattr(msg, "usage_metadata", None) or {}
        meta = getattr(msg, "response_metadata", None) or {}
        inp = um.get("input_tokens") or meta.get("prompt_eval_count") or 0
        out = um.get("output_tokens") or meta.get("eval_count") or 0
        self.tokens["input"] += int(inp)
        self.tokens["output"] += int(out)
        record_usage(msg)  # feed the process-wide total too

    def send(self, text: str) -> str:
        """Send one user turn, streaming tool activity, return the final reply."""
        from .runtime import set_active_agent
        from .ui import Spinner

        set_active_agent("phrak")
        self.tokens["turns"] += 1
        answer = ""
        spinner = Spinner("phrak thinking")
        spinner.start()
        try:
            for chunk in self.graph.stream(
                {"messages": [HumanMessage(content=text)]},
                self._cfg,
                stream_mode="updates",
            ):
                spinner.stop()
                for _node, update in chunk.items():
                    for msg in update.get("messages", []) if update else []:
                        answer = self._observe(msg) or answer
                spinner.start()
        except KeyboardInterrupt:
            return "\n[interrupted]"
        except Exception as e:
            return f"[error: {e}]"
        finally:
            spinner.stop()

        from .ui import strip_thoughts

        answer = strip_thoughts(answer)
        self.last_answer = answer
        return answer

    def _observe(self, msg) -> str:
        """Print live tool activity; return final answer text when present."""
        if isinstance(msg, AIMessage):
            self._account(msg)
            for call in getattr(msg, "tool_calls", None) or []:
                args = call.get("args", {})
                preview = ", ".join(f"{k}={str(v)[:40]}" for k, v in args.items())
                print(f"  {GREY}⚙ {call.get('name')}({preview}){RESET}")
            if msg.content:
                return message_text(msg)
        elif isinstance(msg, ToolMessage):
            content = message_text(msg)
            if self.verbose:
                print(f"  {DIM}{GREEN}↳ {msg.name}:{RESET}")
                for line in content.strip().splitlines()[:40]:
                    print(f"    {DIM}{line[:200]}{RESET}")
            else:
                first = content.strip().splitlines()[0] if content.strip() else ""
                print(f"  {DIM}{GREEN}↳ {msg.name}: {first[:80]}{RESET}")
        return ""
