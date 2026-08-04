"""Terminal UI: animated spinners and styled sub-agent prompts.

Spinners run on a background thread while an agent thinks. Sub-agent questions
and permission requests get a distinct colored box (magenta = question, yellow =
permission) so it's obvious a *specialist agent* is asking — not the main prompt.
All of this degrades to no-ops / plain text when output isn't a TTY.
"""

from __future__ import annotations

import re
import sys
import textwrap
import threading

from .banner import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    GREY,
    MAGENTA,
    RED,
    RESET,
    YELLOW,
)

_IS_TTY = sys.stdout.isatty()

# The currently running spinner, so interactive prompts can pause it.
_active_spinner: "Spinner | None" = None


class Spinner:
    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, label: str, color: str = GREEN) -> None:
        self.label = label
        self.color = color
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        global _active_spinner
        if not _IS_TTY or self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        _active_spinner = self
        self._thread.start()

    def _spin(self) -> None:
        i = 0
        while not self._stop.is_set():
            frame = self.FRAMES[i % len(self.FRAMES)]
            sys.stdout.write(
                f"\r{self.color}{frame}{RESET} {DIM}{self.label}…{RESET}   "
            )
            sys.stdout.flush()
            i += 1
            self._stop.wait(0.09)
        self._clear()

    def _clear(self) -> None:
        sys.stdout.write("\r" + " " * (len(self.label) + 14) + "\r")
        sys.stdout.flush()

    def set_label(self, label: str) -> None:
        self.label = label

    def stop(self) -> None:
        global _active_spinner
        if self._thread is None:
            return
        self._stop.set()
        self._thread.join(timeout=1)
        self._thread = None
        if _active_spinner is self:
            _active_spinner = None
        if _IS_TTY:
            self._clear()


def pause_active_spinner() -> None:
    if _active_spinner is not None:
        _active_spinner.stop()


# --------------------------------------------------------------- activity log
def report_activity(message: str, color: str = CYAN) -> None:
    """Print one live activity line to stdout, tagged with the running agent.

    Used to surface the external actions a tool takes mid-run — spawning a
    subprocess or making a network request — so you can see *if and when* they
    happen (and whether they finished). Pauses any active spinner first so the
    line isn't garbled by the animation, and always prints (TTY or not) so the
    trail survives in piped/redirected output too.
    """
    from .runtime import active_agent

    pause_active_spinner()
    print(f"  {color}{message}{RESET} {GREY}[{active_agent()}]{RESET}")


def log_syscall(cmd: str) -> None:
    """Announce an external command / network call a tool is about to make."""
    if len(cmd) > 120:
        cmd = cmd[:117] + "…"
    report_activity(f"⟫ exec: {cmd}", CYAN)


def log_syscall_result(summary: str, ok: bool = True) -> None:
    """Announce that the external call finished (exit code / status / error)."""
    report_activity(f"  {'✓' if ok else '✗'} {summary}", GREEN if ok else RED)


def log_syscall_note(summary: str) -> None:
    """A dim, non-alarming activity note — for *expected* conditions such as an
    optional binary being absent when the tool has a fallback (rg -> grep). Uses
    a grey '…' so it doesn't read as a failure the way a red '✗' would."""
    report_activity(f"  … {summary}", GREY)


# reasoning models (e.g. deepseek-r1) wrap chain-of-thought in these tags;
# strip them so only the finished answer reaches the user.
_THINK = re.compile(r"<(think|thought|reasoning|scratchpad)>.*?</\1>", re.DOTALL | re.IGNORECASE)

# Smaller local tool-callers (qwen2.5-coder, llama3.x, …) sometimes write the
# harness's own tool protocol into their *prose* instead of emitting a structured
# tool call — a report whose whole body is "<tool_response></tool_response>" is a
# real failure mode, not a hypothetical. Claude doesn't do this, but the markup is
# worthless in a report either way, so it is stripped for every provider.
_PROTOCOL_TAGS = (
    "tool_response", "tool_call", "tool_result", "tool_use", "tool_outputs",
    "function_call", "function_results",
)
_PROTOCOL_BLOCK = re.compile(
    r"<(" + "|".join(_PROTOCOL_TAGS) + r")>.*?</\1>", re.DOTALL | re.IGNORECASE
)
# leftovers: an unclosed tag, or a chat-template control token (<|im_start|>)
_PROTOCOL_STRAY = re.compile(
    r"</?(" + "|".join(_PROTOCOL_TAGS) + r")>|<\|[^|>]{0,64}\|>", re.IGNORECASE
)


def strip_thoughts(text) -> str:
    """Reduce a raw model turn to the prose worth showing.

    Drops chain-of-thought and any tool-protocol markup the model leaked into its
    answer. Returns "" when nothing but that markup was there — callers treat an
    empty result as "this turn produced no answer".
    """
    if not text:
        return ""
    if not isinstance(text, str):
        # a raw provider response / content-block list slipped through
        from .llm import message_text

        text = message_text(text)
    text = _THINK.sub("", text)
    text = _PROTOCOL_BLOCK.sub("", text)
    return _PROTOCOL_STRAY.sub("", text).strip()


def render_markdown(text: str) -> None:
    """Pretty-print an LLM answer as markdown (headings, tables, code). Strips
    any chain-of-thought first. Falls back to plain text when not a TTY."""
    text = strip_thoughts(text)
    if not text:
        return
    if not _IS_TTY:
        print(text)
        return
    try:
        from rich.console import Console
        from rich.markdown import Markdown

        Console().print(Markdown(text))
    except Exception:
        print(text)


def _wrap(text: str, width: int = 58) -> list[str]:
    lines: list[str] = []
    for para in str(text).splitlines() or [""]:
        lines.extend(textwrap.wrap(para, width) or [""])
    return lines


def styled_question(agent: str, question: str) -> str:
    """Ask the user a question on behalf of a sub-agent; return their answer."""
    pause_active_spinner()
    print()
    print(f"  {MAGENTA}╭─ ◆ {BOLD}{agent}{RESET}{MAGENTA} needs your input {'─' * 20}╮{RESET}")
    for line in _wrap(question):
        print(f"  {MAGENTA}│{RESET} {line}")
    print(f"  {MAGENTA}╰{'─' * 56}╯{RESET}")
    try:
        ans = input(f"  {MAGENTA}↳ you:{RESET} ").strip()
    except (EOFError, KeyboardInterrupt):
        ans = ""
    return ans or "(no answer provided; use your best judgment and continue)"


def styled_permission(agent: str, action: str, detail: str = "") -> str:
    """Request permission on behalf of a sub-agent; return GRANTED/DENIED."""
    pause_active_spinner()
    print()
    print(f"  {YELLOW}╭─ ⚠ {BOLD}{agent}{RESET}{YELLOW} requests permission {'─' * 17}╮{RESET}")
    print(f"  {YELLOW}│{RESET} action: {action}")
    for line in _wrap(detail):
        if line:
            print(f"  {YELLOW}│{RESET} {line}")
    print(f"  {YELLOW}╰{'─' * 56}╯{RESET}")
    try:
        ans = input(f"  {YELLOW}↳ allow? [y/N]:{RESET} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = ""
    return "GRANTED" if ans in ("y", "yes") else "DENIED: user declined"
