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
        return ["code_review", "threat_model"]

    def get(self, name):
        return SimpleNamespace(description=f"{name} description")


def _app():
    cfg = SimpleNamespace(paths=SimpleNamespace(reports_dir="./data/reports"))
    return SimpleNamespace(registry=_Registry(), config=cfg)


def test_command_names_includes_agents_and_builtins():
    names = repl.command_names(_app())
    assert "help" in names and "run" in names
    assert "ask" in names and "config" in names
    assert "code_review" in names and "threat_model" in names
    assert "clean" not in names  # removed command
    assert "yolo" not in names   # removed command
    assert "skill" not in names  # removed chat command (phrak skill still exists)
    assert len(names) == len(set(names))  # de-duped


def test_chat_help_renders():
    import io
    import contextlib

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        repl.chat_help(_app())
    out = buf.getvalue()
    assert "/help" in out and "/threat_model" in out
    assert "/ask" in out and "/config" in out
    assert "/clean" not in out
