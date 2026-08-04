"""Scope / target policy (appsec.scope) — Phase 7."""

from __future__ import annotations

from appsec.scope import (
    ScopePolicy,
    check_rate_limit,
    load_policy,
    reset_rate_limit,
    scope_path,
)


def test_disabled_policy_allows_everything():
    p = ScopePolicy(enabled=False, allowed_hosts=["127.0.0.1"])
    assert p.check_url("http://localhost:9999/anything") is None


def test_host_and_port_narrowing():
    p = ScopePolicy(enabled=True, allowed_hosts=["127.0.0.1"], allowed_ports=[5000])
    assert p.check_url("http://127.0.0.1:5000/x") is None
    assert "allowed_hosts" in p.check_url("http://localhost:5000/x")
    assert "port" in p.check_url("http://127.0.0.1:8080/x")


def test_path_allow_and_deny():
    p = ScopePolicy(enabled=True, allowed_paths=["/api"], denied_paths=["/api/admin"])
    assert p.check_url("http://127.0.0.1:5000/api/users") is None
    assert "denied prefix" in p.check_url("http://127.0.0.1:5000/api/admin/reset")
    assert "allowed prefix" in p.check_url("http://127.0.0.1:5000/other")


def test_check_host_port_ignores_path():
    p = ScopePolicy(enabled=True, allowed_paths=["/api"], allowed_hosts=["127.0.0.1"])
    # a base URL (path "/") should pass host/port-only checks even if allowed_paths set
    assert p.check_host_port("http://127.0.0.1:5000/") is None


def test_rate_limit_window():
    reset_rate_limit()
    p = ScopePolicy(enabled=True, rate_limit_per_min=2)
    t = 1000.0
    assert check_rate_limit(p, now=t) is None
    assert check_rate_limit(p, now=t + 1) is None
    assert "RATE LIMITED" in check_rate_limit(p, now=t + 2)
    # after the window rolls, allowed again
    assert check_rate_limit(p, now=t + 61) is None
    reset_rate_limit()


def test_load_policy_missing_file_disabled(config):
    pol = load_policy(config)
    assert pol.enabled is False


def test_load_policy_from_file(config):
    scope_path(config).parent.mkdir(parents=True, exist_ok=True)
    scope_path(config).write_text(
        "allowed_hosts: [127.0.0.1]\nallowed_ports: [5000]\nrate_limit_per_min: 30\n"
    )
    pol = load_policy(config)
    assert pol.enabled is True
    assert pol.allowed_ports == [5000]
    assert pol.rate_limit_per_min == 30


def test_guard_local_enforces_scope(runtime, config):
    """guard_local keeps the loopback floor AND applies scope narrowing."""
    from appsec.tools.common import guard_local

    # write a scope that only allows port 5000
    scope_path(config).parent.mkdir(parents=True, exist_ok=True)
    scope_path(config).write_text("allowed_ports: [5000]\n")
    reset_rate_limit()

    _url, err = guard_local("http://127.0.0.1:5000/")
    assert err is None
    _url, err = guard_local("http://127.0.0.1:8080/")
    assert err and "OUT OF SCOPE" in err
    # non-loopback is still refused first, regardless of scope
    _url, err = guard_local("http://example.com:5000/")
    assert err and "loopback" in err
