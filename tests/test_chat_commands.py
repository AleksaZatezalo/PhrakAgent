"""
Description: Chat slash-command registry: dispatch, aliases, fallbacks, listing.
Author: Aleksa Zatezalo
Date Created: 09-03-2026
"""

from __future__ import annotations

import contextlib
import io
from types import SimpleNamespace

from appsec import chat_commands as cc


# --------------------------------------------------------------------- fakes
class _Registry:
    """Mirror the shape repl/chat_commands read: names() + get().{runner,description}."""

    def __init__(self, names=("code_review", "threat_model", "generate_report")):
        self._names = list(names)

    def names(self):
        return list(self._names)

    def get(self, name):
        # generate_report is an assembly agent: it carries a runner and takes no
        # task argument.
        return SimpleNamespace(
            description=f"{name} description",
            runner=(lambda *a, **k: "") if name == "generate_report" else None,
        )

    def catalog(self):
        return "AGENT CATALOG"


def _session():
    return SimpleNamespace(
        model_desc="ollama:qwen",
        verbose=False,
        cleared=False,
        clear=lambda: None,
        switch_model=lambda name: name or "ollama:qwen",
        cost_summary=lambda: "COST SUMMARY",
    )


def _app(registry=None):
    cfg = SimpleNamespace(paths=SimpleNamespace(workspace="."))
    return SimpleNamespace(registry=registry or _Registry(), config=cfg)


def _ctx(rest="", app=None, session=None):
    return cc.ChatContext(
        app=app or _app(), session=session or _session(), args=None, rest=rest
    )


def _capture(fn, *args, **kwargs):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = fn(*args, **kwargs)
    return result, buf.getvalue()


# ------------------------------------------------------------- registry shape
def test_every_command_name_is_dispatchable_and_unique():
    seen = set()
    for c in cc.COMMANDS:
        for alias in c.names:
            assert alias not in seen, f"duplicate command alias: {alias!r}"
            seen.add(alias)
            assert cc._BY_NAME[alias] is c


def test_aliases_resolve_to_their_primary_command():
    assert cc._BY_NAME[""].name == "help"
    assert cc._BY_NAME["?"].name == "help"
    assert cc._BY_NAME["h"].name == "help"
    assert cc._BY_NAME["exit"].name == "quit"
    assert cc._BY_NAME["q"].name == "quit"
    assert cc._BY_NAME["see-threatmodel"].name == "see_threatmodel"
    assert cc._BY_NAME["see-codereview"].name == "see_codereview"


def test_every_command_group_is_in_group_order():
    for c in cc.COMMANDS:
        assert c.group in cc.GROUP_ORDER


# ------------------------------------------------------------------- dispatch
def test_quit_signals_exit():
    result, out = _capture(cc.dispatch, _ctx(), "quit", [])
    assert result is True
    assert "disconnecting" in out


def test_quit_aliases_signal_exit():
    for alias in ("exit", "q"):
        result, _ = _capture(cc.dispatch, _ctx(), alias, [])
        assert result is True, alias


def test_non_quit_command_keeps_repl_running():
    # /agents (non-verbose) just prints the catalog and returns False.
    result, out = _capture(cc.dispatch, _ctx(), "agents", [])
    assert result is False
    assert "AGENT CATALOG" in out


def test_bare_slash_maps_to_help():
    # A lone "/" becomes an empty command word; it must render help, not error.
    result, out = _capture(cc.dispatch, _ctx(), "", [])
    assert result is False
    # chat_help prints the section headers built from the registry.
    assert "/help" in out and "analyze" in out


def test_unknown_command_suggests_a_near_match():
    names = cc.command_names(_app())
    result, out = _capture(cc.dispatch, _ctx(), "reveiw", names)
    assert result is False
    assert "unknown command '/reveiw'" in out
    # a typo close to a known command surfaces a suggestion
    assert "did you mean" in out


def test_unknown_command_without_near_match_still_explains():
    result, out = _capture(cc.dispatch, _ctx(), "zzzzzzz", ["run", "ask"])
    assert result is False
    assert "unknown command '/zzzzzzz'" in out
    assert "/help" in out


# --------------------------------------------------------- dynamic agent path
def test_agent_command_without_task_prints_usage():
    # A normal agent needs a task; dispatch should show usage, not run anything.
    result, out = _capture(cc.dispatch, _ctx(rest=""), "code_review", [])
    assert result is False
    assert "usage: /code_review <task>" in out


def test_assembly_agent_runs_without_a_task():
    calls = {}

    def run_agent(name, task):
        calls["run"] = (name, task)
        return "REPORT BODY"

    app = _app()
    app.orchestrator = SimpleNamespace(
        run_agent=run_agent,
        save_agent_report=lambda name, task, out: "/tmp/report.md",
    )
    app.rag = SimpleNamespace(index_file=lambda path: 0)  # _land_report hook

    result, out = _capture(cc.dispatch, _ctx(rest="", app=app), "generate_report", [])
    assert result is False
    assert calls["run"] == ("generate_report", "")
    assert "REPORT BODY" in out


# ------------------------------------------------------ session-only handlers
def test_clear_resets_the_session():
    session = _session()
    flag = {"cleared": False}
    session.clear = lambda: flag.__setitem__("cleared", True)
    _capture(cc.dispatch, _ctx(session=session), "clear", [])
    assert flag["cleared"] is True


def test_verbose_toggles():
    session = _session()
    assert session.verbose is False
    _capture(cc.dispatch, _ctx(session=session), "verbose", [])
    assert session.verbose is True
    _capture(cc.dispatch, _ctx(session=session), "verbose", [])
    assert session.verbose is False


def test_model_reports_current_when_bare():
    _, out = _capture(cc.dispatch, _ctx(rest=""), "model", [])
    assert "ollama:qwen" in out


def test_model_switch_uses_default_alias():
    session = _session()
    seen = {}
    session.switch_model = lambda name: seen.setdefault("name", name) or "reset-model"
    _capture(cc.dispatch, _ctx(rest="default", session=session), "model", [])
    assert seen["name"] == ""  # "default"/"reset" clear the override


def test_cost_prints_summary():
    _, out = _capture(cc.dispatch, _ctx(), "cost", [])
    assert "COST SUMMARY" in out


# -------------------------------------------------------------- listing views
def test_command_names_includes_builtins_and_agents_deduped():
    names = cc.command_names(_app())
    assert "help" in names and "run" in names and "config" in names
    assert "code_review" in names and "threat_model" in names
    # aliases and the bare-"/" entry are not listed as separate names
    assert "exit" not in names and "?" not in names and "" not in names
    assert len(names) == len(set(names))


def test_help_groups_cover_every_command():
    groups = dict(cc.help_groups(_app()))
    usages = {u for _, rows in groups.items() for u, _ in rows}
    for c in cc.COMMANDS:
        assert c.usage in usages, f"{c.name} missing from /help"


def test_help_groups_expand_agents_and_system_extras():
    groups = dict(cc.help_groups(_app()))
    agent_usages = [u for u, _ in groups["agents"]]
    # a normal agent shows a task arg; the assembly agent does not
    assert "/code_review <text>" in agent_usages
    assert "/generate_report" in agent_usages
    assert "/generate_report <text>" not in agent_usages
    assert "/agents [--verbose]" in agent_usages  # the static command still listed
    system_usages = [u for u, _ in groups["system"]]
    assert "@path/to/file" in system_usages
    assert "<text>" in system_usages
