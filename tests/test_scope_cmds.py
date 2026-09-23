"""
Description: `scope` command helpers — show/edit the scope policy on disk.
Author: Aleksa Zatezalo
Date Created: 09-22-2026
"""

from __future__ import annotations

from appsec.scope import load_policy, scope_path
from appsec.scope_cmds import edit_scope, parse_and_apply, render_scope


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
    assert "no scope policy" in parse_and_apply(config, [])
    out = parse_and_apply(config, ["--allow-host", "x.com", "--rate", "10"])
    assert "scope saved" in out
    p = load_policy(config)
    assert "x.com" in p.allowed_hosts and p.rate_limit_per_min == 10


def test_parse_and_apply_rejects_bad_port(config):
    assert "invalid port" in parse_and_apply(config, ["--allow-port", "nope"])
