"""
Description: Process-wide runtime context.
Author: Aleksa Zatezalo
Date Created: 07-31-2026
"""

from __future__ import annotations

import contextvars
import threading
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # avoid import cycles at runtime
    from .config import Config
    from .models.findings import SecurityFinding
    from .models.testcases import SecurityTestCase


class _Runtime:
    config: Optional["Config"] = None


RUNTIME = _Runtime()

# Which agent is currently executing — used to label interactive prompts.
_ACTIVE_AGENT: contextvars.ContextVar[str] = contextvars.ContextVar(
    "active_agent", default="agent"
)

# Run-scoped collectors are context-vars, NOT process globals, so several agents
# can run concurrently (Phase 8 parallel fan-out) without clobbering each other's
# findings / tool ledger. Each worker thread gets a fresh context where these
# default to None; the agent sets them at the start of its own run.
_FINDINGS: contextvars.ContextVar[Optional[list]] = contextvars.ContextVar(
    "findings", default=None
)
_TOOL_RUNS: contextvars.ContextVar[Optional[list]] = contextvars.ContextVar(
    "tool_runs", default=None
)
_TEST_CASES: contextvars.ContextVar[Optional[list]] = contextvars.ContextVar(
    "test_cases", default=None
)


def set_active_agent(name: str) -> None:
    _ACTIVE_AGENT.set(name)


def active_agent() -> str:
    return _ACTIVE_AGENT.get()


def init_runtime(config: "Config") -> None:
    RUNTIME.config = config
    # Late-register opt-in agents whose availability depends on config.
    try:
        from .agents import register_verify_if_enabled

        register_verify_if_enabled(config)
    except Exception:
        pass


def require_config() -> "Config":
    if RUNTIME.config is None:
        raise RuntimeError("Runtime not initialised. Call init_runtime() first.")
    return RUNTIME.config


# ------------------------------------------------------ structured findings
def begin_findings() -> list:
    """Start capturing structured findings for a run; returns the fresh list."""
    fresh: list = []
    _FINDINGS.set(fresh)
    return fresh


def record_finding(finding: "SecurityFinding") -> bool:
    """Append a finding to the active run's collector. False if not capturing."""
    coll = _FINDINGS.get()
    if coll is None:
        return False
    coll.append(finding)
    return True


def peek_findings() -> list:
    """The findings captured so far WITHOUT clearing the collector.

    Lets an agent check whether anything has been recorded yet (e.g. to decide
    if a dedicated recording pass is needed) before the final ``take_findings``.
    """
    return list(_FINDINGS.get() or [])


def take_findings() -> list:
    """Return and clear the captured findings (empty list if none/not capturing)."""
    out = _FINDINGS.get() or []
    _FINDINGS.set(None)
    return out


# ------------------------------------------------------------- token usage
# Process-wide (not a context-var) and lock-guarded: the point is the TOTAL
# across everything a session spends — chat turns, every agent in a DAG's
# parallel fan-out, and the report generator — because that total is what a
# paid provider bills for.
_USAGE_LOCK = threading.Lock()
_USAGE: dict[str, int] = {"input": 0, "output": 0, "calls": 0}


def record_usage(msg) -> None:
    """Best-effort token accounting from one model reply's provider metadata."""
    um = getattr(msg, "usage_metadata", None) or {}
    meta = getattr(msg, "response_metadata", None) or {}
    inp = um.get("input_tokens") or meta.get("prompt_eval_count") or 0
    out = um.get("output_tokens") or meta.get("eval_count") or 0
    if not inp and not out:
        return
    with _USAGE_LOCK:
        _USAGE["input"] += int(inp)
        _USAGE["output"] += int(out)
        _USAGE["calls"] += 1


def usage_totals() -> dict:
    with _USAGE_LOCK:
        return dict(_USAGE)


# ------------------------------------------------------------- test cases
def begin_test_cases() -> list:
    """Start capturing authored test cases for a run; returns the fresh list."""
    fresh: list = []
    _TEST_CASES.set(fresh)
    return fresh


def record_test_case(case: "SecurityTestCase") -> bool:
    """Append a test case to the active run's collector. False if not capturing."""
    coll = _TEST_CASES.get()
    if coll is None:
        return False
    coll.append(case)
    return True


def peek_test_cases() -> list:
    """The test cases captured so far WITHOUT clearing the collector."""
    return list(_TEST_CASES.get() or [])


def take_test_cases() -> list:
    """Return and clear the captured test cases (empty list if none)."""
    out = _TEST_CASES.get() or []
    _TEST_CASES.set(None)
    return out


# ------------------------------------------------------ tool-execution ledger
def begin_tool_ledger() -> list:
    """Start recording which tools actually execute during a run."""
    fresh: list = []
    _TOOL_RUNS.set(fresh)
    return fresh


def record_tool_run(name: str, detail: str = "") -> None:
    """Note that a tool actually executed (no-op outside a run)."""
    coll = _TOOL_RUNS.get()
    if coll is not None:
        coll.append((name, detail))


def ran_tools() -> list:
    """The (name, detail) pairs recorded this run (empty if none/not capturing)."""
    return list(_TOOL_RUNS.get() or [])
