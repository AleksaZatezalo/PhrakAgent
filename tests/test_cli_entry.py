"""
Description: The `phrakagent [DIR]` console-script entry point.
Author: Aleksa Zatezalo
Date Created: 09-03-2026
"""

from __future__ import annotations

import os

import pytest

from appsec import cli


@pytest.fixture
def captured_main(monkeypatch):
    """Replace cli.main with a stub that records the argv it was handed."""
    seen = {}

    def _stub(argv=None):
        seen["argv"] = argv
        return 0

    monkeypatch.setattr(cli, "main", _stub)
    return seen


def test_directory_positional_becomes_workspace(tmp_path, captured_main):
    rc = cli.phrak_agent_main([str(tmp_path)])
    assert rc == 0
    assert captured_main["argv"] == ["-w", os.path.abspath(str(tmp_path))]


def test_no_argument_uses_current_directory(captured_main):
    cli.phrak_agent_main([])
    assert captured_main["argv"] == ["-w", os.path.abspath(".")]


def test_trailing_arguments_pass_through(tmp_path, captured_main):
    cli.phrak_agent_main([str(tmp_path), "run", "review this"])
    assert captured_main["argv"] == [
        "-w",
        os.path.abspath(str(tmp_path)),
        "run",
        "review this",
    ]


def test_leading_flag_is_passthrough_with_cwd_workspace(captured_main):
    cli.phrak_agent_main(["--no-color"])
    assert captured_main["argv"] == ["-w", os.path.abspath("."), "--no-color"]


def test_home_directory_is_expanded(tmp_path, captured_main, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    cli.phrak_agent_main(["~"])
    assert captured_main["argv"] == ["-w", str(tmp_path)]


def test_missing_directory_errors_without_calling_main(capsys, captured_main):
    rc = cli.phrak_agent_main(["/no/such/dir/really"])
    assert rc == 2
    assert "argv" not in captured_main  # main was never reached
    assert "not a directory" in capsys.readouterr().err


def test_both_console_scripts_are_declared():
    # Guard the packaging contract: both entry points resolve to real callables.
    assert callable(cli.main)
    assert callable(cli.phrak_agent_main)
