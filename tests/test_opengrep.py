"""
Description: Opengrep analyzer adapter (appsec.tools.opengrep_tools).
Author: Aleksa Zatezalo
Date Created: 07-30-2026
"""

from __future__ import annotations

from pathlib import Path

import appsec.tools.opengrep_tools as og
from appsec.tools.common import CliResult
from appsec.tools.opengrep_tools import (
    _exclude_args,
    _format,
    opengrep_scan,
    scan_secrets,
)


def _result(root: Path, name: str, line: int, sev: str, check: str, msg: str) -> dict:
    return {
        "path": str(root / name),
        "start": {"line": line},
        "extra": {"severity": sev, "message": msg},
        "check_id": f"rules.{check}",
    }


def test_format_orders_by_severity_and_relativizes(runtime):
    root = Path(runtime.paths.workspace).resolve()
    data = {"results": [
        _result(root, "a.py", 5, "WARNING", "weak-hash", "weak hash"),
        _result(root, "b.py", 9, "ERROR", "sql-injection", "SQLi from user input"),
    ]}
    out = _format(data, "auto")
    assert "2 finding(s) from opengrep (auto):" in out
    # ERROR must be listed before WARNING
    assert out.index("sql-injection") < out.index("weak-hash")
    assert "b.py:9 [ERROR] sql-injection" in out


def test_format_empty(runtime):
    assert "No findings from opengrep" in _format({"results": []}, "auto")


def test_exclude_args_cover_state_dirs(runtime):
    args = _exclude_args()
    assert "--exclude" in args
    values = [args[i + 1] for i in range(0, len(args), 2)]
    # PHRAK's own state dir and the analyzer workspace are never scanned.
    assert ".phrack" in values and "workspace" in values


def test_opengrep_scan_reports_missing_binary(runtime, monkeypatch):
    monkeypatch.setenv("PHRAK_OPENGREP_BIN", "___no_such_opengrep___")
    out = opengrep_scan.invoke({"path": "."})
    assert "not installed" in out
    assert "opengrep" in out


def test_opengrep_scan_reports_internal_error_honestly(runtime, monkeypatch):
    # exit 2 with no stdout == fatal internal error (e.g. OOM), NOT "no findings".
    monkeypatch.setattr(og, "run_cli", lambda *a, **k: CliResult(
        stdout="", stderr="Fatal: out of memory", returncode=2))
    out = opengrep_scan.invoke({"path": "."})
    assert "exit 2" in out
    assert "out of memory" in out


def test_scan_secrets_uses_secrets_ruleset(runtime, monkeypatch):
    captured: dict[str, list[str]] = {}

    def fake_run_cli(cmd, timeout, require_bin=True):
        captured["cmd"] = cmd
        return CliResult(stdout='{"results": []}', returncode=0)

    monkeypatch.setattr(og, "run_cli", fake_run_cli)
    out = scan_secrets.invoke({"path": "."})
    cmd = captured["cmd"]
    assert "--config" in cmd
    assert cmd[cmd.index("--config") + 1] == og.SECRETS_CONFIG
    assert "No findings from opengrep" in out


def test_code_review_wires_opengrep_only():
    from appsec.agents.code_review import _tools

    names = {getattr(t, "name", "") for t in _tools()}
    assert {"opengrep_scan", "scan_secrets"} <= names
    # the removed analyzers must be gone
    assert "semgrep_scan" not in names
    assert "codeql_scan" not in names
    assert "joern_scan" not in names


def test_chat_wires_opengrep_only():
    from appsec.chat import _build_tools

    names = {getattr(t, "name", "") for t in _build_tools()}
    assert "opengrep_scan" in names
    assert "semgrep_scan" not in names
