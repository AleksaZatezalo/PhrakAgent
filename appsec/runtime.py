"""Process-wide runtime context.

Tools are plain functions (LangChain ``@tool``) and can't easily receive the
config through the agent loop, so we stash the live objects here at startup and
let tools read them. Set once via :func:`init_runtime`.
"""

from __future__ import annotations

import contextvars
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # avoid import cycles at runtime
    from .config import Config
    from .models.findings import SecurityFinding


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


def set_active_agent(name: str) -> None:
    _ACTIVE_AGENT.set(name)


def active_agent() -> str:
    return _ACTIVE_AGENT.get()


def init_runtime(config: "Config") -> None:
    RUNTIME.config = config


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


def take_findings() -> list:
    """Return and clear the captured findings (empty list if none/not capturing)."""
    out = _FINDINGS.get() or []
    _FINDINGS.set(None)
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
