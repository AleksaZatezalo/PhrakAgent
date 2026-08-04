#!/usr/bin/env python3
"""
Description: PHRAK Agent — command-line entry point for the AppSec multi-agent system.
Author: Aleksa Zatezalo
Date Created: 08-01-2026
"""

from __future__ import annotations

import argparse
import os
import sys

from .banner import (
    BGREEN,
    CYAN,
    GREEN,
    GREY,
    RESET,
    mini_banner,
    phrak_print,
    print_banner,
)
from .config import (
    CONFIG_FILENAME,
    Config,
    default_config_path,
    run_setup,
)
from .ui import render_markdown


def _config_path(args) -> str:
    """Resolve which config to use for this invocation.

    Precedence: an explicit ``-c`` path; else the workspace's
    ``.phrack/config.yaml``; else a legacy pre-.phrack ``config.yaml`` at the
    workspace/CWD root if one still exists (so old setups keep working).
    """
    if args.config:
        return args.config
    ws = args.workspace or "."
    primary = str(default_config_path(ws))
    if os.path.exists(primary):
        return primary
    legacy = os.path.join(ws, CONFIG_FILENAME) if args.workspace else CONFIG_FILENAME
    if os.path.exists(legacy):
        return legacy
    return primary  # doesn't exist yet -> setup wizard will create it here


def _ensure_config(path: str) -> None:
    """If no config exists at ``path``, walk the user through setup first."""
    if os.path.exists(path):
        return
    print_banner(None)
    print(f"  {GREEN}No configuration found.{RESET} Let's get you set up.\n")
    run_setup(path)
    print()


def _load_app(args):
    path = _config_path(args)
    _ensure_config(path)
    cfg = Config.load(path)
    if args.workspace:
        cfg.paths.workspace = args.workspace
    from .app import build_app

    app = build_app(cfg)
    # build_app has exported any stored provider key; say so early if the
    # configured provider still has none, rather than failing on the first call.
    if not getattr(args, "quiet", False):
        from .credentials import missing_key_hint

        hint = missing_key_hint(cfg)
        if hint:
            phrak_print(f"{GREY}{hint}{RESET}")
    return app


def _land_report(app, path: str, quiet: bool = False) -> None:
    """Announce where a report landed and fold it into the code index.

    Reports live in ``.phrack/reports``; indexing them into ``.phrack/rag``
    immediately means ``/ask`` can answer questions about a vulnerability the
    moment the run finishes, rather than only once ``/ask`` next syncs.
    Indexing needs the embedding backend, so a failure here is reported and
    swallowed — never enough to lose a completed run.
    """
    if not quiet:
        phrak_print(f"report saved :: {CYAN}{path}{RESET}")
    try:
        n = app.rag.index_file(path)
    except Exception as e:
        if not quiet:
            phrak_print(f"{GREY}(not indexed: {e}){RESET}")
        return
    if n and not quiet:
        phrak_print(f"{GREY}indexed {n} chunk(s) :: {app.config.rag_dir()}{RESET}")


# --------------------------------------------------------------- subcommands
def cmd_config(args) -> int:
    """Interactive setup wizard, or `--show` the current (redacted) config."""
    if getattr(args, "show", False):
        path = _config_path(args)
        if not os.path.exists(path):
            print(f"No config at {path}. Run `phrak config` to create one.")
            return 2
        cfg = Config.load(path)
        if args.workspace:
            cfg.paths.workspace = args.workspace
        print(f"# {path}\n")
        print(cfg.show())
        return 0
    run_setup(_config_path(args))
    return 0


def cmd_agents(args) -> int:
    app = _load_app(args)
    print_banner(app)
    return 0


def cmd_run(args) -> int:
    app = _load_app(args)
    quiet = getattr(args, "quiet", False)
    as_json = getattr(args, "json", False)
    if not quiet and not as_json:
        print_banner(app)
    request = " ".join(args.request)

    def on_step(i, step):
        if quiet or as_json:
            return
        model = app.models.describe(step.agent)
        phrak_print(
            f"step {i} :: {BGREEN}{step.agent}{RESET} {GREY}({model}){RESET} → {step.task}"
        )

    if args.single:
        if not quiet and not as_json:
            phrak_print(f"routing target :: {GREY}{request}{RESET}")
        result = app.orchestrator.run_single(request, on_step=on_step)
    else:
        if not quiet and not as_json:
            phrak_print(f"planning target :: {GREY}{request}{RESET}")
        result = app.orchestrator.run(request, on_step=on_step)

    if as_json:
        import json

        _land_report(app, result["report_path"], quiet=True)
        plan = [{"agent": s.agent, "task": s.task} for s in result.get("plan", [])]
        print(
            json.dumps(
                {
                    "request": request,
                    "plan": plan,
                    "routed_to": result.get("routed_to"),
                    "report": result["report"],
                    "report_path": result["report_path"],
                },
                indent=2,
            )
        )
        return 0
    if quiet:
        _land_report(app, result["report_path"], quiet=True)
        render_markdown(result["report"])
        return 0
    if result.get("routed_to"):
        phrak_print(f"routed to :: {BGREEN}{result['routed_to']}{RESET}")
    print(f"\n{GREEN}╔{'═' * 60}╗{RESET}")
    print(f"{GREEN}║{RESET}  {BGREEN}CONSOLIDATED REPORT{RESET}")
    print(f"{GREEN}╚{'═' * 60}╝{RESET}\n")
    render_markdown(result["report"])
    _land_report(app, result["report_path"])
    return 0


def cmd_agent(args) -> int:
    app = _load_app(args)
    print(mini_banner())
    phrak_print(f"engaging {BGREEN}{args.name}{RESET} ...\n")
    task = " ".join(args.task)
    out = app.orchestrator.run_agent(args.name, task)
    render_markdown(out)
    _land_report(app, app.orchestrator.save_agent_report(args.name, task, out))
    return 0


def _do_ask(app, question: str, reindex: bool = False, k=None) -> None:
    """Shared /ask + `phrak ask` behaviour: RAG over the workspace."""
    if reindex:
        phrak_print("reindexing workspace ...")
        stats = app.rag.reindex()
        phrak_print(f"indexed {stats['chunks']} chunks from {stats['added']} files")
    phrak_print(f"asking :: {GREY}{question}{RESET}\n")
    render_markdown(app.rag.ask(app.llm, question, k=k))


def cmd_ask(args) -> int:
    app = _load_app(args)
    print(mini_banner())
    _do_ask(app, " ".join(args.question), reindex=args.reindex, k=args.k)
    return 0


def cmd_chat(args) -> int:
    app = _load_app(args)
    print_banner(app)
    from . import repl
    from .chat import ChatSession

    session = ChatSession(app)
    commands = repl.setup_readline(app)
    from . import banner

    print(
        f"  {GREEN}chat mode{RESET} {GREY}({session.model_desc}){RESET} — "
        f"talk to PHRAK about the code in your workspace."
    )
    print(
        f"  type {CYAN}/help{RESET} for commands, {CYAN}Tab{RESET} to "
        f"autocomplete, {CYAN}↑/↓{RESET} to filter history. "
        f"{GREY}Or just type to chat.{RESET}\n"
    )
    while True:
        # Rebuilt every turn, reading the module colors live, so a runtime color
        # change takes effect on the next line rather than at the next restart.
        prompt = f"{banner.BGREEN}phrak➜ {banner.RESET}"
        try:
            line = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue

        if line.startswith("/"):
            cmd, _, rest = line[1:].partition(" ")
            cmd = cmd.lower()
            rest = rest.strip()

            if cmd in ("help", "?", "h", ""):
                repl.chat_help(app)
            elif cmd in ("quit", "exit", "q"):
                phrak_print("disconnecting...")
                break
            elif cmd == "agents":
                if "--verbose" in rest.split() or "-v" in rest.split():
                    from .session_cmds import list_tools_grouped

                    print(app.registry.catalog())
                    print("\n" + list_tools_grouped(app))
                else:
                    print(app.registry.catalog())
            elif cmd == "config":
                if rest.strip() == "--show":
                    print(app.config.show())
                else:
                    run_setup(_config_path(args))
                    phrak_print(
                        "config saved — restart PHRAK to apply the new " "settings."
                    )
            elif cmd == "clone":
                from .clone import clone_repo

                toks = rest.split()
                if not toks:
                    print("usage: /clone <git-url> [dest] [--index]")
                else:
                    do_index = "--index" in toks
                    toks = [t for t in toks if t != "--index"]
                    res = clone_repo(
                        app.config, toks[0], toks[1] if len(toks) > 1 else ""
                    )
                    phrak_print(res.message)
                    if res.ok and do_index:
                        app.config.paths.workspace = res.dest
                        stats = app.rag.reindex()
                        phrak_print(
                            f"workspace -> {res.dest}; indexed "
                            f"{stats['chunks']} chunks"
                        )
            elif cmd == "ask":
                if not rest:
                    print(
                        "usage: /ask <question>   (add --reindex to refresh "
                        "the index first)"
                    )
                    continue
                tokens = rest.split()
                reindex = "--reindex" in tokens
                question = " ".join(t for t in tokens if t != "--reindex")
                print()
                _do_ask(app, question, reindex=reindex)
                print()
            elif cmd == "run":
                if not rest:
                    print("usage: /run <request>")
                    continue
                result = app.orchestrator.run(
                    rest,
                    on_step=lambda i, s: phrak_print(
                        f"{BGREEN}{s.agent}{RESET} → {s.task}"
                    ),
                )
                print()
                render_markdown(result["report"])
                _land_report(app, result["report_path"])
                print()
            elif cmd == "route":
                if not rest:
                    print("usage: /route <request>")
                    continue
                result = app.orchestrator.run_single(
                    rest,
                    on_step=lambda i, s: phrak_print(
                        f"routed → {BGREEN}{s.agent}{RESET}"
                    ),
                )
                print()
                render_markdown(result["report"])
                _land_report(app, result["report_path"])
                print()
            elif cmd in app.registry.names():
                if not rest:
                    print(f"usage: /{cmd} <task>")
                    continue
                print()
                out = app.orchestrator.run_agent(cmd, rest)
                render_markdown(out)
                _land_report(app, app.orchestrator.save_agent_report(cmd, rest, out))
                print()
            else:
                import difflib

                near = difflib.get_close_matches(cmd, commands, n=1, cutoff=0.5)
                hint = f" did you mean {CYAN}/{near[0]}{RESET}?" if near else ""
                print(
                    f"unknown command '/{cmd}'.{hint} "
                    f"type {CYAN}/help{RESET} for the list."
                )
            continue

        # default: conversational turn with tool use + thread memory.
        reply = session.send(line)
        print()
        render_markdown(reply)
        print()
    return 0


def cmd_clone(args) -> int:
    app = _load_app(args)
    print(mini_banner())
    from .clone import clone_repo

    res = clone_repo(app.config, args.url, args.dest, recurse=args.recurse)
    phrak_print(res.message)
    if res.ok and args.index:
        app.config.paths.workspace = res.dest
        phrak_print(f"workspace -> {res.dest}; indexing ...")
        stats = app.rag.reindex()
        phrak_print(f"indexed {stats['chunks']} chunks from {stats['added']} files")
    return 0 if res.ok else 1


# ------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    from . import __version__

    p = argparse.ArgumentParser(description="Local AppSec agents + codebase Q&A")
    p.add_argument("--version", action="version", version=f"phrak {__version__}")
    p.add_argument(
        "-c",
        "--config",
        default="",
        help="config path (default: <workspace>/.phrack/config.yaml)",
    )
    p.add_argument("-w", "--workspace", default="", help="override workspace root")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument(
        "--quiet",
        action="store_true",
        help="suppress banners/status; print only results",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON where supported (run)",
    )
    # No subcommand => conversational chat (like `claude` with no args).
    p.set_defaults(func=cmd_chat)
    sub = p.add_subparsers(dest="cmd", required=False)

    sub.add_parser("chat", help="conversational mode (default)").set_defaults(
        func=cmd_chat
    )
    # `config` is the primary setup command; `setup` kept as an alias.
    sp = sub.add_parser("config", help="interactive setup wizard (no AI)")
    sp.add_argument(
        "--show",
        action="store_true",
        help="print the current config (secrets redacted) and exit",
    )
    sp.set_defaults(func=cmd_config)
    sub.add_parser("setup", help="alias for config").set_defaults(func=cmd_config)
    sub.add_parser("agents", help="list agents").set_defaults(func=cmd_agents)

    sp = sub.add_parser("run", help="orchestrate agents on a request")
    sp.add_argument("request", nargs="+")
    sp.add_argument(
        "-1",
        "--single",
        action="store_true",
        help="route to a single best-fit agent (fast, no synthesis)",
    )
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("agent", help="run a single agent")
    sp.add_argument("name")
    sp.add_argument("task", nargs="+")
    sp.set_defaults(func=cmd_agent)

    sp = sub.add_parser("ask", help="ask a question about the codebase (RAG)")
    sp.add_argument("question", nargs="+")
    sp.add_argument("-k", type=int, default=None, help="chunks to retrieve")
    sp.add_argument(
        "--reindex", action="store_true", help="rebuild the index before asking"
    )
    sp.set_defaults(func=cmd_ask)

    sub.add_parser("interactive", help="alias for chat").set_defaults(func=cmd_chat)

    sp = sub.add_parser("clone", help="shallow-clone a repo to analyze (no AI)")
    sp.add_argument("url")
    sp.add_argument("dest", nargs="?", default="")
    sp.add_argument(
        "--index",
        action="store_true",
        help="set the clone as workspace and build the RAG index",
    )
    sp.add_argument("--recurse", action="store_true", help="fetch submodules")
    sp.set_defaults(func=cmd_clone)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "no_color", False):
        os.environ["NO_COLOR"] = "1"
        from . import banner

        banner.set_color(False)
    try:
        return args.func(args)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
