"""
Description: Chat slash-command registry — the single source of truth for what
    ``/commands`` exist, how they dispatch, and how /help + Tab-complete list them.
Author: Aleksa Zatezalo
Date Created: 09-03-2026
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from .banner import BGREEN, CYAN, GREEN, GREY, RESET, WHITE, phrak_print
from .ui import render_markdown

# ---------------------------------------------------------------- dispatch types


@dataclass
class ChatContext:
    """Everything a slash-command handler needs for one invocation.

    ``rest`` is the argument string after the command word; ``args`` is the
    argparse namespace the chat session was launched with (only ``/config`` needs
    it, to re-derive the config path for the setup wizard).
    """

    app: Any
    session: Any
    args: Any
    rest: str = ""


# A handler runs one command. Returning True asks the REPL loop to exit (``/quit``);
# any other value (usually None) keeps it running.
Handler = Callable[[ChatContext], Optional[bool]]


@dataclass(frozen=True)
class Command:
    """One chat slash-command: how to dispatch it and how /help lists it.

    ``names`` is the primary name followed by any aliases (the empty string is a
    valid alias — a bare ``/`` maps to it). ``usage`` / ``summary`` are the two
    columns /help renders; ``group`` sorts it into a /help section.
    """

    names: tuple[str, ...]
    group: str
    usage: str
    summary: str
    handler: Handler

    @property
    def name(self) -> str:
        return self.names[0]


# The order /help renders its sections in.
GROUP_ORDER = ("analyze", "agents", "findings", "test cases", "session", "system")


# ------------------------------------------------------------------- handlers
# Each handler mirrors exactly one branch of the old cmd_chat if/elif chain.
# Imports stay function-local so importing this module (which repl does, just for
# the command metadata) doesn't drag in the orchestrator, stores, or clone code.


def _h_help(ctx: ChatContext) -> None:
    from . import repl

    repl.chat_help(ctx.app)


def _h_quit(ctx: ChatContext) -> bool:
    phrak_print("disconnecting...")
    return True


def _h_agents(ctx: ChatContext) -> None:
    app, rest = ctx.app, ctx.rest
    if "--verbose" in rest.split() or "-v" in rest.split():
        from .session_cmds import list_tools_grouped

        print(app.registry.catalog())
        print("\n" + list_tools_grouped(app))
    else:
        print(app.registry.catalog())


def _h_config(ctx: ChatContext) -> None:
    if ctx.rest.strip() == "--show":
        print(ctx.app.config.show())
        return
    from .cli import _config_path
    from .config import run_setup

    run_setup(_config_path(ctx.args))
    phrak_print("config saved — restart PHRAK to apply the new settings.")


def _h_clone(ctx: ChatContext) -> None:
    from .clone import clone_repo

    app = ctx.app
    toks = ctx.rest.split()
    if not toks:
        print("usage: /clone <git-url> [dest] [--index]")
        return
    do_index = "--index" in toks
    toks = [t for t in toks if t != "--index"]
    res = clone_repo(app.config, toks[0], toks[1] if len(toks) > 1 else "")
    phrak_print(res.message)
    if res.ok and do_index:
        app.config.paths.workspace = res.dest
        stats = app.rag.reindex()
        phrak_print(f"workspace -> {res.dest}; indexed {stats['chunks']} chunks")


def _h_ask(ctx: ChatContext) -> None:
    from .cli import _do_ask

    rest = ctx.rest
    if not rest:
        print(
            "usage: /ask <question>   (add --reindex to refresh the index first)"
        )
        return
    tokens = rest.split()
    reindex = "--reindex" in tokens
    question = " ".join(t for t in tokens if t != "--reindex")
    print()
    _do_ask(ctx.app, question, reindex=reindex)
    print()


def _fmt_duration(seconds: float) -> str:
    """A compact ``mm:ss`` / ``s`` label for a run's wall-clock time."""
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(round(seconds)), 60)
    return f"{m}m{s:02d}s"


def render_run_summary(result: dict) -> None:
    """Print a one-glance recap of a finished run: step outcomes, how many
    findings / test cases it recorded, and how long it took. Reads only the
    ``run``/``run_single`` result dict, so it is safe for both plan and route."""
    tasks = result.get("dag") or result.get("plan") or []
    done = sum(1 for t in tasks if getattr(t, "status", "done") == "done")
    failed = sum(1 for t in tasks if getattr(t, "status", "") == "failed")
    skipped = sum(1 for t in tasks if getattr(t, "status", "") == "skipped")

    mark = {"done": f"{GREEN}✓{RESET}", "failed": f"{RESET}✗{RESET}",
            "skipped": f"{GREY}–{RESET}"}
    steps = "  ".join(
        f"{mark.get(getattr(t, 'status', 'done'), '·')} {t.agent}" for t in tasks
    )

    print(f"\n{BGREEN}run complete{RESET} {GREY}· {_fmt_duration(result.get('elapsed', 0))}{RESET}")
    tally = [f"{done} done"]
    if failed:
        tally.append(f"{failed} failed")
    if skipped:
        tally.append(f"{skipped} skipped")
    print(f"  steps    :: {', '.join(tally)}")
    if steps:
        print(f"             {steps}")
    nf, nt = result.get("n_findings"), result.get("n_test_cases")
    if nf is not None or nt is not None:
        print(f"  recorded :: {nf or 0} finding(s), {nt or 0} test case(s)")
    if result.get("routed_to"):
        print(f"  routed   :: {result['routed_to']}")
    print(f"  report   :: {CYAN}{result.get('report_path', '?')}{RESET}")


def _h_run(ctx: ChatContext) -> None:
    from .cli import _land_report

    app, rest = ctx.app, ctx.rest
    if not rest:
        print("usage: /run <request>")
        return
    result = app.orchestrator.run(
        rest,
        on_step=lambda i, s: phrak_print(f"{BGREEN}{s.agent}{RESET} → {s.task}"),
    )
    print()
    render_markdown(result["report"])
    _land_report(app, result["report_path"])
    render_run_summary(result)
    print()


def _h_route(ctx: ChatContext) -> None:
    from .cli import _land_report

    app, rest = ctx.app, ctx.rest
    if not rest:
        print("usage: /route <request>")
        return
    result = app.orchestrator.run_single(
        rest,
        on_step=lambda i, s: phrak_print(f"routed → {BGREEN}{s.agent}{RESET}"),
    )
    print()
    render_markdown(result["report"])
    _land_report(app, result["report_path"])
    print()


def _h_findings(ctx: ChatContext) -> None:
    from .session_cmds import findings_list, parse_findings_flags

    kwargs, err = parse_findings_flags(ctx.rest)
    print(err or findings_list(ctx.app, **kwargs))


def _h_finding(ctx: ChatContext) -> None:
    from .session_cmds import finding_detail

    print()
    render_markdown(finding_detail(ctx.app, ctx.rest))
    print()


def _h_see_threatmodel(ctx: ChatContext) -> None:
    from .session_cmds import show_agent_report

    print()
    render_markdown(show_agent_report(ctx.app, "threat_model"))
    print()


def _h_see_codereview(ctx: ChatContext) -> None:
    from .session_cmds import show_agent_report

    print()
    render_markdown(show_agent_report(ctx.app, "code_review"))
    print()


def _h_triage(ctx: ChatContext) -> None:
    from .session_cmds import triage_finding

    phrak_print(triage_finding(ctx.app, ctx.rest))


def _h_note(ctx: ChatContext) -> None:
    from .session_cmds import note_finding

    phrak_print(note_finding(ctx.app, ctx.rest))


def _h_finding_add(ctx: ChatContext) -> None:
    from .session_cmds import add_manual_finding, prompt_for_finding

    print(
        f"\n  {GREEN}new verified finding{RESET} "
        f"{GREY}(Ctrl-C to cancel; the id is generated){RESET}"
    )
    fields = prompt_for_finding()
    print()
    if fields is None:
        phrak_print("cancelled — nothing recorded.")
    else:
        phrak_print(add_manual_finding(ctx.app, **fields))


def _h_index(ctx: ChatContext) -> None:
    from .ui import Spinner

    app = ctx.app
    toks = ctx.rest.split()
    if "--stats" in toks:
        s = app.rag.stats()
        phrak_print(
            f"index :: {WHITE}{s['chunks']}{RESET} chunk(s) from "
            f"{WHITE}{s['indexed_files']}{RESET} file(s); "
            f"{WHITE}{s['pending']}{RESET} pending"
        )
        return
    rebuild = "--rebuild" in toks
    spinner = Spinner("rebuilding index" if rebuild else "indexing")
    label = "rebuilding index" if rebuild else "indexing workspace"
    spinner.start()
    try:
        stats = (
            app.rag.reindex(
                on_progress=lambda d, t, r: spinner.set_label(f"{label} {d}/{t}")
            )
            if rebuild
            else app.rag.sync(
                on_progress=lambda d, t, r: spinner.set_label(f"{label} {d}/{t}")
            )
        )
    except Exception as e:
        spinner.stop()
        phrak_print(f"index failed :: {e}")
        return
    finally:
        spinner.stop()
    touched = stats["added"] + stats["updated"] + stats["removed"]
    if touched:
        phrak_print(
            f"indexed {WHITE}{stats['chunks']}{RESET} chunk(s) :: "
            f"+{stats['added']} ~{stats['updated']} -{stats['removed']}"
        )
    else:
        phrak_print(f"{GREEN}already up to date{RESET}")


def _h_testcases(ctx: ChatContext) -> None:
    from .testcase_cmds import parse_testcase_flags, test_cases_list

    kwargs, err = parse_testcase_flags(ctx.rest)
    print(err or test_cases_list(ctx.app, **kwargs))


def _h_testcase(ctx: ChatContext) -> None:
    from .testcase_cmds import test_case_detail

    print()
    render_markdown(test_case_detail(ctx.app, ctx.rest))
    print()


def _h_testcase_status(ctx: ChatContext) -> None:
    from .testcase_cmds import set_test_case_status

    phrak_print(set_test_case_status(ctx.app, ctx.rest))


def _h_testcase_link(ctx: ChatContext) -> None:
    from .testcase_cmds import link_test_case

    phrak_print(link_test_case(ctx.app, ctx.rest))


def _h_testcase_note(ctx: ChatContext) -> None:
    from .testcase_cmds import note_test_case

    phrak_print(note_test_case(ctx.app, ctx.rest))


def _h_testcase_add(ctx: ChatContext) -> None:
    from .testcase_cmds import add_manual_test_case, prompt_for_test_case

    print(
        f"\n  {GREEN}new test case{RESET} "
        f"{GREY}(Ctrl-C to cancel; the id is generated){RESET}"
    )
    fields = prompt_for_test_case()
    print()
    if fields is None:
        phrak_print("cancelled — nothing added.")
    else:
        phrak_print(add_manual_test_case(ctx.app, **fields))


def _h_clear(ctx: ChatContext) -> None:
    ctx.session.clear()
    phrak_print("context cleared — starting a fresh thread.")


def _h_model(ctx: ChatContext) -> None:
    session, rest = ctx.session, ctx.rest
    if not rest:
        phrak_print(
            f"model :: {BGREEN}{session.model_desc}{RESET} "
            f"{GREY}(/model <name> to switch, /model default to reset){RESET}"
        )
    else:
        name = "" if rest in ("default", "reset") else rest
        phrak_print(f"model :: {BGREEN}{session.switch_model(name)}{RESET}")


def _h_cost(ctx: ChatContext) -> None:
    print(ctx.session.cost_summary())


def _h_verbose(ctx: ChatContext) -> None:
    ctx.session.verbose = not ctx.session.verbose
    state = "on (full tool output)" if ctx.session.verbose else "off (summary)"
    phrak_print(f"verbose :: {state}")


# ------------------------------------------------------------------- registry
# Grouped/ordered exactly as /help renders them, so one definition drives
# dispatch, Tab-complete, and the /help listing.
COMMANDS: tuple[Command, ...] = (
    # analyze
    Command(
        ("ask",),
        "analyze",
        "/ask <text>",
        "answer a question grounded in the codebase (RAG)",
        _h_ask,
    ),
    Command(
        ("index",),
        "analyze",
        "/index [--rebuild|--stats]",
        "refresh the code index (no AI)",
        _h_index,
    ),
    Command(
        ("run",),
        "analyze",
        "/run <text>",
        "full multi-agent assessment + saved report",
        _h_run,
    ),
    Command(
        ("route",),
        "analyze",
        "/route <text>",
        "auto-route to the single best-fit agent",
        _h_route,
    ),
    Command(
        ("see_threatmodel", "see-threatmodel"),
        "analyze",
        "/see_threatmodel",
        "replay the latest threat_model report",
        _h_see_threatmodel,
    ),
    Command(
        ("see_codereview", "see-codereview"),
        "analyze",
        "/see_codereview",
        "replay the latest code_review report",
        _h_see_codereview,
    ),
    # agents
    Command(
        ("agents",),
        "agents",
        "/agents [--verbose]",
        "list agents (and their tools)",
        _h_agents,
    ),
    # findings
    Command(
        ("findings",),
        "findings",
        "/findings [filters]",
        "list recorded findings across all runs",
        _h_findings,
    ),
    Command(
        ("finding",),
        "findings",
        "/finding <id>",
        "one finding in full: evidence, history, notes",
        _h_finding,
    ),
    Command(
        ("finding-add",),
        "findings",
        "/finding-add",
        "record a finding you verified yourself (no AI)",
        _h_finding_add,
    ),
    Command(
        ("triage",),
        "findings",
        "/triage <id> <status>",
        "record your verdict (add a note after it)",
        _h_triage,
    ),
    Command(
        ("note",),
        "findings",
        "/note <id> <text>",
        "attach a reviewer note",
        _h_note,
    ),
    # test cases
    Command(
        ("testcases",),
        "test cases",
        "/testcases [filters]",
        "the test-case backlog as a checklist",
        _h_testcases,
    ),
    Command(
        ("testcase",),
        "test cases",
        "/testcase <id>",
        "one test case in full",
        _h_testcase,
    ),
    Command(
        ("testcase-add",),
        "test cases",
        "/testcase-add",
        "write a test case by hand (no AI)",
        _h_testcase_add,
    ),
    Command(
        ("testcase-status",),
        "test cases",
        "/testcase-status <id> <s>",
        "new | in_progress | complete [result]",
        _h_testcase_status,
    ),
    Command(
        ("testcase-link",),
        "test cases",
        "/testcase-link <id> <fnd>",
        "tie a test to the finding it verifies",
        _h_testcase_link,
    ),
    Command(
        ("testcase-note",),
        "test cases",
        "/testcase-note <id> <text>",
        "record what happened when you ran it",
        _h_testcase_note,
    ),
    # session
    Command(
        ("clear",),
        "session",
        "/clear",
        "forget the conversation so far",
        _h_clear,
    ),
    Command(
        ("model",),
        "session",
        "/model [name]",
        "show or switch the chat model",
        _h_model,
    ),
    Command(
        ("cost",),
        "session",
        "/cost",
        "tokens and estimated spend this session",
        _h_cost,
    ),
    Command(
        ("verbose",),
        "session",
        "/verbose",
        "toggle full tool output",
        _h_verbose,
    ),
    # system
    Command(
        ("clone",),
        "system",
        "/clone <url> [dest] [--index]",
        "shallow-clone a repo to analyze",
        _h_clone,
    ),
    Command(
        ("config",),
        "system",
        "/config [--show]",
        "setup wizard (or show redacted config)",
        _h_config,
    ),
    Command(
        ("help", "?", "h", ""),
        "system",
        "/help",
        "show this list",
        _h_help,
    ),
    Command(
        ("quit", "exit", "q"),
        "system",
        "/quit",
        "exit PHRAK",
        _h_quit,
    ),
)

# Every name and alias -> its Command, for O(1) dispatch.
_BY_NAME: dict[str, Command] = {
    alias: cmd for cmd in COMMANDS for alias in cmd.names
}

# /help-only rows that aren't dispatchable commands (plain chat + @file refs),
# appended to the "system" section.
_SYSTEM_EXTRAS = (
    ("<text>", "just chat — PHRAK reads code and answers, keeping context"),
    ("@path/to/file", "inline a workspace file into your message"),
)


# ------------------------------------------------------------------- dispatch
def _run_agent_command(ctx: ChatContext, cmd: str) -> None:
    """Handle ``/<agent> <task>`` for any registered agent (dynamic command)."""
    from .cli import _land_report

    app, rest = ctx.app, ctx.rest
    # An assembly agent works from what's already stored, so it takes no task;
    # the rest need one.
    if not rest and app.registry.get(cmd).runner is None:
        print(f"usage: /{cmd} <task>")
        return
    print()
    out = app.orchestrator.run_agent(cmd, rest)
    render_markdown(out)
    _land_report(app, app.orchestrator.save_agent_report(cmd, rest, out))
    print()


def _unknown(cmd: str, all_names: list[str]) -> None:
    import difflib

    near = difflib.get_close_matches(cmd, all_names, n=1, cutoff=0.5)
    hint = f" did you mean {CYAN}/{near[0]}{RESET}?" if near else ""
    print(
        f"unknown command '/{cmd}'.{hint} "
        f"type {CYAN}/help{RESET} for the list."
    )


def dispatch(ctx: ChatContext, cmd: str, all_names: list[str]) -> bool:
    """Run the slash-command ``cmd``. Returns True if the REPL should exit.

    Resolution order mirrors the old chain: a built-in command (or its alias),
    then any registered agent by name, then a 'did you mean' suggestion.
    """
    command = _BY_NAME.get(cmd)
    if command is not None:
        return bool(command.handler(ctx))
    if cmd in ctx.app.registry.names():
        _run_agent_command(ctx, cmd)
        return False
    _unknown(cmd, all_names)
    return False


# ------------------------------------------------------------ help / listing
def command_names(app) -> list[str]:
    """All slash-command names available in chat, including dynamic agents.

    Primary names only (aliases and the bare-``/`` entry are omitted), followed
    by the registered agents, de-duped while preserving order.
    """
    names = [c.name for c in COMMANDS]
    names += list(app.registry.names())
    seen: dict[str, None] = {}
    for n in names:
        seen.setdefault(n, None)
    return list(seen)


def help_groups(app) -> list[tuple[str, list[tuple[str, str]]]]:
    """The /help sections as ``(title, [(usage, summary), ...])``.

    Static commands come from :data:`COMMANDS`; the agents section is expanded
    with one row per registered agent (an assembly agent is shown without a task
    argument), and the system section gets the plain-chat / ``@file`` notes.
    """
    by_group: dict[str, list[tuple[str, str]]] = {}
    for c in COMMANDS:
        by_group.setdefault(c.group, []).append((c.usage, c.summary))

    groups: list[tuple[str, list[tuple[str, str]]]] = []
    for title in GROUP_ORDER:
        rows = list(by_group.get(title, []))
        if title == "agents":
            agent_rows = [
                (
                    f"/{n}" if app.registry.get(n).runner else f"/{n} <text>",
                    app.registry.get(n).description,
                )
                for n in app.registry.names()
            ]
            rows = agent_rows + rows
        elif title == "system":
            rows = rows + list(_SYSTEM_EXTRAS)
        groups.append((title, rows))
    return groups
