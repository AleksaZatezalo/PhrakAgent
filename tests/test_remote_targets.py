"""
Description: The authorized-remote-target escape hatch in guard_local — off by
    default, and even on, only for an allowlisted host.
Author: Aleksa Zatezalo
Date Created: 09-22-2026
"""

from __future__ import annotations

from appsec.scope import reset_rate_limit, scope_path
from appsec.tools.common import guard_local

# 8.8.8.8 never resolves to loopback, so it exercises the remote path even in a
# sandbox whose DNS maps hostnames to 127.0.0.1.
REMOTE = "http://8.8.8.8/"


def _write_scope(config, hosts):
    scope_path(config).parent.mkdir(parents=True, exist_ok=True)
    lines = ["enabled: true", "allowed_hosts:"] + [f"  - {h}" for h in hosts]
    scope_path(config).write_text("\n".join(lines) + "\n")


def setup_function(_):
    reset_rate_limit()


def test_remote_refused_by_default(runtime):
    assert runtime.allow_remote_targets is False
    _write_scope(runtime, ["8.8.8.8"])  # allowlisted, but flag is off
    _url, err = guard_local(REMOTE)
    assert err and "not an authorized remote target" in err


def test_remote_refused_when_not_allowlisted(runtime):
    runtime.allow_remote_targets = True
    _write_scope(runtime, ["other.example.com"])  # different host
    _url, err = guard_local(REMOTE)
    assert err and "authorized remote target" in err


def test_remote_refused_when_scope_absent(runtime):
    runtime.allow_remote_targets = True  # flag on but no scope file at all
    _url, err = guard_local(REMOTE)
    assert err and "authorized remote target" in err


def test_remote_allowed_when_flag_and_allowlist(runtime):
    runtime.allow_remote_targets = True
    _write_scope(runtime, ["8.8.8.8"])
    _url, err = guard_local(REMOTE)
    assert err is None


def test_loopback_still_allowed_without_remote_flag(runtime):
    _url, err = guard_local("http://127.0.0.1:8000/")
    assert err is None
