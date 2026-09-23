"""
Description: `scope` command helpers — show/edit the scope policy on disk.
Author: Aleksa Zatezalo
Date Created: 09-22-2026
"""

from __future__ import annotations

from appsec.scope import load_policy, scope_path
from appsec.scope_cmds import (
    define_scope_interactive,
    edit_scope,
    parse_and_apply,
    render_scope,
)


def _script_answers(monkeypatch, answers):
    """Feed `define_scope_interactive`'s prompts a fixed list of replies."""
    it = iter(answers)

    def fake_ask(prompt, default=""):
        try:
            return next(it)
        except StopIteration:
            return default

    monkeypatch.setattr("appsec.config._ask", fake_ask)


def test_render_no_policy(config):
    out = render_scope(config)
    assert "no scope policy" in out and "--init" in out


def test_init_creates_default(config):
    out = edit_scope(config, init=True)
    assert scope_path(config).exists()
    p = load_policy(config)
    assert p.enabled and "127.0.0.1" in p.allowed_hosts
    assert "scope saved" in out


def test_edits_accumulate_and_persist(config):
    edit_scope(config, allow_hosts=["Target.Example.com"], allow_ports=[443])
    edit_scope(config, deny_paths=["/admin"], rate=30)
    p = load_policy(config)
    assert "target.example.com" in p.allowed_hosts  # lowercased
    assert 443 in p.allowed_ports
    assert "/admin" in p.denied_paths
    assert p.rate_limit_per_min == 30


def test_remove_host(config):
    edit_scope(config, allow_hosts=["a.com", "b.com"])
    edit_scope(config, remove_hosts=["a.com"])
    p = load_policy(config)
    assert p.allowed_hosts == ["b.com"]


def test_rate_zero_is_an_edit(config):
    edit_scope(config, rate=5)
    edit_scope(config, rate=0)  # unlimited — a real edit, not "no change"
    assert load_policy(config).rate_limit_per_min == 0


def test_remote_host_hint_without_flag(config):
    edit_scope(config, allow_hosts=["8.8.8.8"])
    assert config.allow_remote_targets is False
    assert "allow_remote_targets" in render_scope(config)


def test_parse_and_apply_show_and_edit(config):
    assert "no scope policy" in parse_and_apply(config, ["--show"])
    out = parse_and_apply(config, ["--allow-host", "x.com", "--rate", "10"])
    assert "scope saved" in out
    p = load_policy(config)
    assert "x.com" in p.allowed_hosts and p.rate_limit_per_min == 10


def test_parse_and_apply_rejects_bad_port(config):
    assert "invalid port" in parse_and_apply(config, ["--allow-port", "nope"])


# --------------------------------------------------------------- interactive
def test_interactive_defines_policy(config, monkeypatch, tmp_path):
    # enable, hosts, ports, allow-paths, deny-paths, rate, (remote toggle)
    _script_answers(
        monkeypatch, ["y", "8.8.8.8", "443", "", "/admin", "30", "y"]
    )
    cpath = str(tmp_path / "config.yaml")
    out = define_scope_interactive(config, config_path=cpath)
    assert "scope saved" in out
    p = load_policy(config)
    assert p.enabled and p.allowed_hosts == ["8.8.8.8"]
    assert p.allowed_ports == [443] and p.denied_paths == ["/admin"]
    assert p.rate_limit_per_min == 30
    # a remote host + "y" flips the config flag and persists it
    assert config.allow_remote_targets is True
    assert "allow_remote_targets: true saved" in out


def test_interactive_loopback_no_remote_prompt(config, monkeypatch):
    _script_answers(monkeypatch, ["y", "127.0.0.1", "", "", "", "0"])
    out = define_scope_interactive(config)
    assert config.allow_remote_targets is False
    assert "allow_remote_targets: true saved" not in out


def test_bare_scope_runs_wizard(config, monkeypatch):
    _script_answers(monkeypatch, ["y", "localhost", "", "", "", "0"])
    out = parse_and_apply(config, [])  # bare /scope
    assert "scope saved" in out
    assert load_policy(config).allowed_hosts == ["localhost"]


def test_interactive_bad_port_aborts(config, monkeypatch):
    _script_answers(monkeypatch, ["y", "localhost", "notaport", "", "", "0"])
    out = define_scope_interactive(config)
    assert "invalid port" in out and not scope_path(config).exists()
