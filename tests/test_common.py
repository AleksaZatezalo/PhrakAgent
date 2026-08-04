"""
Description: Shared tool helpers: workspace sandbox, subprocess runner, loopback guard.
Author: Aleksa Zatezalo
Date Created: 07-31-2026
"""

from __future__ import annotations

import sys

import pytest

from appsec.tools import common


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://localhost:5000", True),
        ("http://127.0.0.1:8080/x", True),
        ("http://[::1]:9000", True),
        ("http://example.com", False),
        ("http://8.8.8.8/", False),
    ],
)
def test_is_local(url, expected):
    assert common.is_local(url) is expected


def test_normalize_url_adds_scheme():
    assert common.normalize_url("localhost:5000") == "http://localhost:5000"
    assert common.normalize_url("https://x") == "https://x"


@pytest.mark.parametrize(
    "host,expected",
    [
        ("127.0.0.1", True),
        ("localhost", True),
        ("::1", True),
        ("[::1]", True),
        ("2130706433", True),  # decimal 127.0.0.1
        ("0x7f000001", True),  # hex 127.0.0.1
        ("::ffff:127.0.0.1", True),  # IPv4-mapped loopback
        ("8.8.8.8", False),
        ("169.254.169.254", False),  # cloud metadata — not loopback
        ("0x08080808", False),  # hex 8.8.8.8
        ("2851995648", False),  # decimal 169.254.0.0
    ],
)
def test_host_is_loopback_encodings(host, expected):
    assert common.host_is_loopback(host) is expected


def test_is_local_rejects_encoded_public_ip():
    assert common.is_local("http://0x08080808:80/") is False
    assert common.is_local("http://2130706433:5000/") is True


def test_guard_local_refuses_remote():
    _, err = common.guard_local("http://evil.com")
    assert err and "REFUSED" in err


def test_guard_local_accepts_loopback():
    url, err = common.guard_local("127.0.0.1:5000")
    assert err is None
    assert url == "http://127.0.0.1:5000"


def test_guard_local_reports_missing_binary():
    _, err = common.guard_local("http://localhost", "totally_missing_binary_xyz")
    assert err and "not installed" in err


def test_run_cli_captures_stdout():
    res = common.run_cli([sys.executable, "-c", "print('hi')"], timeout=10)
    assert res.error is None
    assert res.returncode == 0
    assert "hi" in res.stdout


def test_run_cli_missing_binary():
    res = common.run_cli(["___no_such_binary___"], timeout=5)
    assert res.error and "not installed" in res.error


def test_run_cli_missing_binary_required_logs_failure(capsys):
    # a non-optional missing binary reads as a red failure (✗)
    common.run_cli(["___no_such_binary___"], timeout=5)
    out = capsys.readouterr().out
    assert "✗" in out and "not installed" in out


def test_run_cli_missing_binary_optional_is_quiet(capsys):
    # an optional probe (has a fallback) logs a dim note, NOT a failure
    res = common.run_cli(["___no_such_binary___"], timeout=5, optional=True)
    out = capsys.readouterr().out
    assert "✗" not in out
    assert "trying fallback" in out
    # return contract is unchanged so the caller still falls back
    assert res.error and "not installed" in res.error


def test_run_cli_timeout():
    res = common.run_cli(
        [sys.executable, "-c", "import time; time.sleep(5)"], timeout=1
    )
    assert res.error and "timed out" in res.error


def test_resolve_in_workspace_ok(runtime):
    p = common.resolve_in_workspace("vuln_app.py")
    assert p.name == "vuln_app.py"


def test_resolve_in_workspace_rejects_escape(runtime):
    with pytest.raises(ValueError):
        common.resolve_in_workspace("../../../etc/passwd")
