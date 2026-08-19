"""
Description: REPL command list + /help rendering.
Author: Aleksa Zatezalo
Date Created: 08-01-2026
"""

from __future__ import annotations

from types import SimpleNamespace

from appsec import repl


class _Registry:
    def names(self):
        return ["code_review", "threat_model", "generate_report"]

    def get(self, name):
        # generate_report is an assembly agent: it carries a runner and takes
        # no task argument, so /help renders it without one.
        return SimpleNamespace(
            description=f"{name} description",
            runner=(lambda *a, **k: "") if name == "generate_report" else None,
        )


def _app():
    cfg = SimpleNamespace(paths=SimpleNamespace(reports_dir="./data/reports"))
    return SimpleNamespace(registry=_Registry(), config=cfg)


def test_command_names_includes_agents_and_builtins():
    names = repl.command_names(_app())
    assert "help" in names and "run" in names
    assert "ask" in names and "config" in names
    assert "code_review" in names and "threat_model" in names
    assert "clean" not in names  # removed command
    assert "yolo" not in names  # removed command
    assert "skill" not in names  # removed chat command (phrak skill still exists)
    assert len(names) == len(set(names))  # de-duped


def test_command_names_includes_findings_and_session_commands():
    names = repl.command_names(_app())
    for n in ("findings", "finding", "triage", "note"):
        assert n in names
    for n in ("clear", "model", "cost", "verbose"):
        assert n in names


def _help_output() -> str:
    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        repl.chat_help(_app())
    return buf.getvalue()


def test_chat_help_renders():
    out = _help_output()
    assert "/help" in out and "/threat_model" in out
    assert "/ask" in out and "/config" in out
    assert "/clean" not in out


def test_chat_help_documents_findings_session_and_at_refs():
    out = _help_output()
    assert "/findings" in out and "/triage" in out and "/note" in out
    assert "/clear" in out and "/model" in out and "/cost" in out
    assert "@path/to/file" in out


def test_chat_help_documents_test_case_and_manual_entry_commands():
    out = _help_output()
    for cmd in ("/testcases", "/testcase-status", "/testcase-link", "/testcase-add"):
        assert cmd in out
    assert "/finding-add" in out


def test_chat_help_renders_assembly_agents_without_a_task_argument():
    out = _help_output()
    assert "/generate_report " in out  # listed...
    assert "/generate_report <text>" not in out  # ...but takes no task
    assert "/code_review <text>" in out  # a normal agent still does


def test_findings_subcommand_parses():
    from appsec.cli import build_parser

    args = build_parser().parse_args(["findings", "--severity", "high", "--resurfaced"])
    assert args.cmd == "findings"
    assert args.severity == "high" and args.resurfaced is True
    assert args.id == ""
    assert build_parser().parse_args(["findings", "F-123"]).id == "F-123"
