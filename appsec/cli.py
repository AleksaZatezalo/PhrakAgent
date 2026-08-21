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
    WHITE,
    YELLOW,
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
from .ui import Spinner, render_markdown


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
    """Shared /ask + `phrak ask` behaviour: RAG over the workspace.

    The index is brought up to date before every question — incrementally, or
    from scratch with ``--reindex``. Syncing here rather than inside ``ask``
    keeps the wait visible (embedding a big workspace is not instant) and lets
    ``ask`` skip a second redundant walk.
    """
    spinner = Spinner("syncing code index")

    def _progress(done, total, rel):
        # Embedding is CPU-bound (minutes for a few hundred files) — show the
        # count so a first index reads as work, not as a freeze.
        spinner.set_label(f"{'rebuilding' if reindex else 'indexing'} {done}/{total}")

    if reindex:
        phrak_print("reindexing workspace ...")
        spinner.start()
        try:
            stats = app.rag.reindex(on_progress=_progress)
        finally:
            spinner.stop()
        phrak_print(f"indexed {stats['chunks']} chunks from {stats['added']} files")
    else:
        spinner.start()
        try:
            stats = app.rag.sync(on_progress=_progress)
        except Exception as e:
            stats = None
            spinner.stop()
            phrak_print(f"{GREY}index not refreshed ({e}) — answering anyway{RESET}")
        finally:
            spinner.stop()
        if stats and (stats["added"] or stats["updated"] or stats["removed"]):
            phrak_print(
                f"{GREY}index synced :: +{stats['added']} ~{stats['updated']} "
                f"-{stats['removed']} file(s), {stats['chunks']} chunk(s){RESET}"
            )
    phrak_print(f"asking :: {GREY}{question}{RESET}\n")
    render_markdown(app.rag.ask(app.llm, question, k=k, sync=False))


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
        f"autocomplete, {CYAN}↑/↓{RESET} to filter history, "
        f"{CYAN}@file{RESET} to attach code. "
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
            elif cmd == "findings":
                from .session_cmds import findings_list, parse_findings_flags

                kwargs, err = parse_findings_flags(rest)
                print(err or findings_list(app, **kwargs))
            elif cmd == "finding":
                from .session_cmds import finding_detail

                print()
                render_markdown(finding_detail(app, rest))
                print()
            elif cmd in ("see_threatmodel", "see-threatmodel"):
                from .session_cmds import show_agent_report

                print()
                render_markdown(show_agent_report(app, "threat_model"))
                print()
            elif cmd in ("see_codereview", "see-codereview"):
                from .session_cmds import show_agent_report

                print()
                render_markdown(show_agent_report(app, "code_review"))
                print()
            elif cmd == "triage":
                from .session_cmds import triage_finding

                phrak_print(triage_finding(app, rest))
            elif cmd == "note":
                from .session_cmds import note_finding

                phrak_print(note_finding(app, rest))
            elif cmd == "finding-add":
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
                    phrak_print(add_manual_finding(app, **fields))
            elif cmd == "index":
                toks = rest.split()
                if "--stats" in toks:
                    s = app.rag.stats()
                    phrak_print(
                        f"index :: {WHITE}{s['chunks']}{RESET} chunk(s) from "
                        f"{WHITE}{s['indexed_files']}{RESET} file(s); "
                        f"{WHITE}{s['pending']}{RESET} pending"
                    )
                    continue
                rebuild = "--rebuild" in toks
                spinner = Spinner("rebuilding index" if rebuild else "indexing")
                label = "rebuilding index" if rebuild else "indexing workspace"
                spinner.start()
                try:
                    stats = (
                        app.rag.reindex(
                            on_progress=lambda d, t, r: spinner.set_label(
                                f"{label} {d}/{t}"
                            )
                        )
                        if rebuild
                        else app.rag.sync(
                            on_progress=lambda d, t, r: spinner.set_label(
                                f"{label} {d}/{t}"
                            )
                        )
                    )
                except Exception as e:
                    spinner.stop()
                    phrak_print(f"index failed :: {e}")
                    continue
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
            elif cmd == "testcases":
                from .testcase_cmds import parse_testcase_flags, test_cases_list

                kwargs, err = parse_testcase_flags(rest)
                print(err or test_cases_list(app, **kwargs))
            elif cmd == "testcase":
                from .testcase_cmds import test_case_detail

                print()
                render_markdown(test_case_detail(app, rest))
                print()
            elif cmd == "testcase-status":
                from .testcase_cmds import set_test_case_status

                phrak_print(set_test_case_status(app, rest))
            elif cmd == "testcase-link":
                from .testcase_cmds import link_test_case

                phrak_print(link_test_case(app, rest))
            elif cmd == "testcase-note":
                from .testcase_cmds import note_test_case

                phrak_print(note_test_case(app, rest))
            elif cmd == "testcase-add":
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
                    phrak_print(add_manual_test_case(app, **fields))
            elif cmd == "clear":
                session.clear()
                phrak_print("context cleared — starting a fresh thread.")
            elif cmd == "model":
                if not rest:
                    phrak_print(
                        f"model :: {BGREEN}{session.model_desc}{RESET} "
                        f"{GREY}(/model <name> to switch, "
                        f"/model default to reset){RESET}"
                    )
                else:
                    name = "" if rest in ("default", "reset") else rest
                    phrak_print(f"model :: {BGREEN}{session.switch_model(name)}{RESET}")
            elif cmd == "cost":
                print(session.cost_summary())
            elif cmd == "verbose":
                session.verbose = not session.verbose
                state = "on (full tool output)" if session.verbose else "off (summary)"
                phrak_print(f"verbose :: {state}")
            elif cmd in app.registry.names():
                # An assembly agent works from what's already stored, so it
                # takes no task; the rest need one.
                if not rest and app.registry.get(cmd).runner is None:
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

        # default: conversational turn with tool use + thread memory. Any
        # `@path` reference is inlined first, and echoed back so a typo'd or
        # out-of-workspace path is visible now rather than as a confused answer
        # a minute from now.
        from .session_cmds import describe_at_refs, expand_at_refs

        for desc in describe_at_refs(line, app.config.paths.workspace):
            phrak_print(f"{GREY}attached {desc}{RESET}")
        reply = session.send(expand_at_refs(line, app.config.paths.workspace))
        print()
        render_markdown(reply)
        print()
    return 0


def cmd_findings(args) -> int:
    """List / inspect the durable finding store outside chat (and for CI)."""
    app = _load_app(args)
    from .session_cmds import finding_detail, findings_json, findings_list

    if getattr(args, "json", False):
        print(findings_json(app))
        return 0
    if not getattr(args, "quiet", False):
        print(mini_banner())
    if args.id:
        render_markdown(finding_detail(app, args.id))
        return 0
    print(
        findings_list(
            app,
            severity=args.severity,
            status=args.status,
            resurfaced=args.resurfaced,
        )
    )
    return 0


def cmd_index(args) -> int:
    """Build or refresh the code index — no AI, no model, no network.

    Embedding is local and CPU-bound: a few hundred files takes minutes. Doing
    it here, deliberately, is what keeps it from happening inside an agent's
    tool call mid-assessment.
    """
    import time

    path = _config_path(args)
    _ensure_config(path)
    cfg = Config.load(path)
    if args.workspace:
        cfg.paths.workspace = args.workspace
    cfg.ensure_dirs()

    from .rag import CodeIndex

    idx = CodeIndex(cfg)
    quiet = getattr(args, "quiet", False)
    as_json = getattr(args, "json", False)
    if not quiet and not as_json:
        print(mini_banner())

    # --stats reports and changes nothing.
    if args.stats:
        s = idx.stats()
        if as_json:
            import json

            print(json.dumps(s, indent=2))
            return 0
        phrak_print(
            f"index :: {WHITE}{s['chunks']}{RESET} chunk(s) from "
            f"{WHITE}{s['indexed_files']}{RESET} file(s) :: {CYAN}{cfg.rag_dir()}{RESET}"
        )
        phrak_print(
            f"workspace :: {WHITE}{s['workspace_files']}{RESET} indexable file(s)"
        )
        if s["pending"]:
            phrak_print(
                f"{YELLOW}{s['pending']} file(s) pending{RESET} "
                f"{GREY}({s['new']} new, {s['changed']} changed, "
                f"{s['orphaned']} removed) — run `phrak index`{RESET}"
            )
        else:
            phrak_print(f"{GREEN}up to date{RESET} {GREY}— nothing to do{RESET}")
        return 0

    spinner = Spinner("preparing")
    label = "rebuilding index" if args.rebuild else "indexing workspace"

    def _progress(done, total, rel):
        spinner.set_label(f"{label} {done}/{total}")

    started = time.time()
    if not quiet and not as_json:
        spinner.start()
    try:
        if args.rebuild:
            stats = idx.reindex(on_progress=_progress)
        else:
            stats = idx.sync(on_progress=_progress)
    except Exception as e:
        spinner.stop()
        print(f"error: could not index the workspace: {e}", file=sys.stderr)
        return 1
    finally:
        spinner.stop()
    elapsed = time.time() - started

    if as_json:
        import json

        print(json.dumps({**stats, "seconds": round(elapsed, 2)}, indent=2))
        return 0
    touched = stats["added"] + stats["updated"] + stats["removed"]
    if touched:
        phrak_print(
            f"indexed {WHITE}{stats['chunks']}{RESET} chunk(s) :: "
            f"+{stats['added']} new, ~{stats['updated']} changed, "
            f"-{stats['removed']} removed {GREY}({elapsed:.1f}s){RESET}"
        )
    else:
        phrak_print(f"{GREEN}already up to date{RESET} {GREY}({elapsed:.1f}s){RESET}")
    if not quiet:
        phrak_print(f"{GREY}index :: {cfg.rag_dir()}{RESET}")
    return 0


def cmd_report(args) -> int:
    """Assemble the consolidated assessment report (alias for the agent)."""
    app = _load_app(args)
    quiet = getattr(args, "quiet", False)
    if not quiet:
        print(mini_banner())
        phrak_print("assembling consolidated report ...")
    task = " ".join(getattr(args, "note", []) or [])
    out = app.orchestrator.run_agent("generate_report", task)
    if getattr(args, "out", ""):
        from pathlib import Path

        Path(args.out).expanduser().write_text(out)
        phrak_print(f"written :: {CYAN}{args.out}{RESET}")
    else:
        render_markdown(out)
    _land_report(
        app,
        app.orchestrator.save_agent_report("generate_report", task, out),
        quiet=quiet,
    )
    return 0


def cmd_testcases(args) -> int:
    """List / inspect the test-case backlog outside chat (and for CI)."""
    app = _load_app(args)
    from .testcase_cmds import test_case_detail, test_cases_json, test_cases_list

    if getattr(args, "json", False):
        print(test_cases_json(app))
        return 0
    if not getattr(args, "quiet", False):
        print(mini_banner())
    if args.id:
        render_markdown(test_case_detail(app, args.id))
        return 0
    print(
        test_cases_list(
            app,
            status=args.status,
            severity=args.severity,
            finding_id=args.finding,
            unlinked=args.unlinked,
        )
    )
    return 0


def cmd_add_finding(args) -> int:
    """Record a hand-verified finding. Flags for scripting, prompts without them."""
    app = _load_app(args)
    from .session_cmds import add_manual_finding, prompt_for_finding

    if not args.title:
        if not getattr(args, "quiet", False):
            print(mini_banner())
            print(
                f"  {GREEN}new verified finding{RESET} "
                f"{GREY}(Ctrl-C to cancel; the id is generated){RESET}"
            )
        fields = prompt_for_finding()
        if fields is None:
            print("cancelled — nothing recorded.")
            return 130
        print(add_manual_finding(app, **fields))
        return 0
    print(
        add_manual_finding(
            app,
            title=args.title,
            category=args.category,
            severity=args.severity,
            file=args.file,
            line=args.line,
            end_line=args.end_line,
            description=args.description,
            recommendation=args.recommendation,
            cwe=args.cwe,
            owasp=args.owasp,
            disproof=args.disproof,
        )
    )
    return 0


def cmd_add_testcase(args) -> int:
    """Add a hand-written test case. Flags for scripting, prompts without them."""
    app = _load_app(args)
    from .testcase_cmds import add_manual_test_case, prompt_for_test_case

    if not args.title:
        if not getattr(args, "quiet", False):
            print(mini_banner())
            print(
                f"  {GREEN}new test case{RESET} "
                f"{GREY}(Ctrl-C to cancel; the id is generated){RESET}"
            )
        fields = prompt_for_test_case()
        if fields is None:
            print("cancelled — nothing added.")
            return 130
        print(add_manual_test_case(app, **fields))
        return 0
    print(
        add_manual_test_case(
            app,
            title=args.title,
            target=args.target,
            steps=args.steps,
            expected_result=args.expected,
            severity=args.severity,
            objective=args.objective,
            preconditions=args.preconditions,
            finding_id=args.finding,
        )
    )
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
        help="emit machine-readable JSON where supported (run, findings)",
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
    # Optional: an assembly agent like generate_report works from stored
    # artifacts and needs no task.
    sp.add_argument("task", nargs="*")
    sp.set_defaults(func=cmd_agent)

    sp = sub.add_parser("ask", help="ask a question about the codebase (RAG)")
    sp.add_argument("question", nargs="+")
    sp.add_argument("-k", type=int, default=None, help="chunks to retrieve")
    sp.add_argument(
        "--reindex", action="store_true", help="rebuild the index before asking"
    )
    sp.set_defaults(func=cmd_ask)

    sp = sub.add_parser("findings", help="list or inspect recorded findings")
    sp.add_argument("id", nargs="?", default="", help="show one finding in full")
    sp.add_argument("--severity", default="", help="filter by severity")
    sp.add_argument("--status", default="", help="filter by effective status")
    sp.add_argument(
        "--resurfaced",
        action="store_true",
        help="only findings whose evidence changed since a human verdict",
    )
    sp.set_defaults(func=cmd_findings)

    sp = sub.add_parser(
        "index",
        help="build or refresh the code index (no AI) so /ask and agents are fast",
    )
    sp.add_argument(
        "--rebuild",
        action="store_true",
        help="wipe and re-embed everything (slow; for a changed chunk size or model)",
    )
    sp.add_argument(
        "--stats",
        action="store_true",
        help="report what's indexed and what's pending, without changing anything",
    )
    sp.set_defaults(func=cmd_index)

    sp = sub.add_parser(
        "report",
        help="assemble the consolidated assessment report (generate_report)",
    )
    sp.add_argument("note", nargs="*", help="optional scope note for the header")
    sp.add_argument("--out", default="", help="write to this file instead of stdout")
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("testcases", help="list or inspect the test-case backlog")
    sp.add_argument("id", nargs="?", default="", help="show one test case in full")
    sp.add_argument("--status", default="", help="new | in_progress | complete")
    sp.add_argument("--severity", default="", help="filter by severity")
    sp.add_argument("--finding", default="", help="only tests verifying this finding")
    sp.add_argument(
        "--unlinked", action="store_true", help="only tests not tied to a finding"
    )
    sp.set_defaults(func=cmd_testcases)

    sp = sub.add_parser(
        "add-finding", help="record a hand-verified finding (no AI; prompts if bare)"
    )
    sp.add_argument("--title", default="")
    sp.add_argument("--category", default="")
    sp.add_argument("--severity", default="")
    sp.add_argument("--file", default="")
    sp.add_argument("--line", default="")
    sp.add_argument("--end-line", dest="end_line", default="")
    sp.add_argument("--description", default="")
    sp.add_argument("--recommendation", default="")
    sp.add_argument("--cwe", default="", help="comma-separated, e.g. CWE-89")
    sp.add_argument("--owasp", default="", help="comma-separated")
    sp.add_argument("--disproof", default="")
    sp.set_defaults(func=cmd_add_finding)

    sp = sub.add_parser(
        "add-testcase", help="add a test case by hand (no AI; prompts if bare)"
    )
    sp.add_argument("--title", default="")
    sp.add_argument("--target", default="", help="endpoint / parameter / file:line")
    sp.add_argument("--steps", default="", help="newline- or ' | '-separated")
    sp.add_argument("--expected", default="", help="expected result")
    sp.add_argument("--severity", default="medium")
    sp.add_argument("--objective", default="")
    sp.add_argument("--preconditions", default="")
    sp.add_argument("--finding", default="", help="finding id this test verifies")
    sp.set_defaults(func=cmd_add_testcase)

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
