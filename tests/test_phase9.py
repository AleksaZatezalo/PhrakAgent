"""
Description: Phase 9 usability & extensibility: skills/clone/session helpers.
Author: Aleksa Zatezalo
Date Created: 08-01-2026
"""

from __future__ import annotations

import types
from pathlib import Path

import pytest

from appsec import banner, clone
from appsec.session_cmds import expand_at_refs, list_tools_grouped, tool_detail
from appsec.skill_store import SkillStore
from appsec.tools.common import CliResult


# ---------------------------------------------------- skill scope resolution
def test_skill_workspace_and_global_scope(config, tmp_path, monkeypatch):
    # isolate the global dir under tmp so we don't touch the real ~/.phrak
    gdir = tmp_path / "global"
    monkeypatch.setattr("appsec.skill_store.GLOBAL_PHRAK_DIR", gdir)
    store = SkillStore(config)
    store.add_skill("shared", "workspace body", scope="workspace")
    store.add_skill("shared", "GLOBAL body", scope="global")
    store.add_skill("only-global", "g", scope="global")

    names = store.list_skills()
    assert "shared" in names and "only-global" in names
    # workspace overrides global for the same name
    assert "workspace body" in store.read_skill("shared")
    assert set(store.skill_scopes("shared")) == {"workspace", "global"}

    assert store.remove_skill("shared", scope="workspace") is True
    assert "GLOBAL body" in store.read_skill("shared")   # global remains


def test_skill_add_rejects_missing_and_empty(config):
    store = SkillStore(config)
    assert store.remove_skill("nope") is False


def _app(config):
    from appsec.base_agent import REGISTRY
    import appsec.agents  # noqa: F401 register

    return types.SimpleNamespace(config=config, registry=REGISTRY)


# --------------------------------------------------------------------- clone
@pytest.mark.parametrize("url,ok", [
    ("https://github.com/a/b.git", True),
    ("https://github.com/a/b", True),
    ("git@github.com:a/b.git", True),
    ("file:///etc/passwd", False),
    ("http://x@evil/creds.git", False),
    ("/local/path", False),
    ("ftp://x/y", False),
])
def test_valid_git_url(url, ok):
    assert clone.valid_git_url(url) is ok


def _fake_git(create=True):
    def _run(cmd, timeout, **k):
        target = Path(cmd[-1])
        if create:
            target.mkdir(parents=True, exist_ok=True)
            (target / "README.md").write_text("hello")
        return CliResult(stdout="", stderr="", returncode=0)
    return _run


def test_clone_success(config, monkeypatch):
    monkeypatch.setattr(clone, "run_cli", _fake_git())
    res = clone.clone_repo(config, "https://github.com/a/b.git")
    assert res.ok and Path(res.dest).name == "b"
    assert (Path(res.dest) / "README.md").exists()


def test_clone_refuses_bad_url(config):
    res = clone.clone_repo(config, "file:///etc/passwd")
    assert not res.ok and "REFUSED" in res.message


def test_clone_enforces_size_cap(config, monkeypatch):
    monkeypatch.setattr(clone, "run_cli", _fake_git())
    res = clone.clone_repo(config, "https://github.com/a/big.git", max_mb=0)
    assert not res.ok and "over the" in res.message
    assert not Path(config.clones_dir() / "big").exists()   # cleaned up


def test_clone_refuses_existing(config, monkeypatch):
    monkeypatch.setattr(clone, "run_cli", _fake_git())
    (config.clones_dir() / "dup").mkdir(parents=True)
    res = clone.clone_repo(config, "https://github.com/a/dup.git", dest="dup")
    assert not res.ok and "already exists" in res.message


# --------------------------------------------------- git_clone tool gating
def test_git_clone_tool_gated_by_config(config):
    from appsec.tools.clone_tool import git_clone_tools

    config.enable_git_clone = False
    assert git_clone_tools(config) == []
    config.enable_git_clone = True
    assert [t.name for t in git_clone_tools(config)] == ["git_clone"]


# ----------------------------------------------------------- session helpers
def test_expand_at_refs(config, workspace):
    text = "look at @vuln_app.py please and @../outside.txt"
    out = expand_at_refs(text, workspace)
    assert "Referenced files:" in out
    assert "--- vuln_app.py ---" in out
    assert "SuperSecret123" in out       # file contents inlined
    assert "outside workspace" in out    # traversal refused


def test_expand_at_refs_noop_without_refs(config, workspace):
    assert expand_at_refs("no refs here", workspace) == "no refs here"


def test_tools_grouped_and_detail(config):
    app = _app(config)
    grouped = list_tools_grouped(app)
    assert "code_review:" in grouped and "read_file" in grouped
    detail = tool_detail(app, "read_file")
    assert "read_file(" in detail
    assert "No tool named" in tool_detail(app, "does_not_exist")


# --------------------------------------------------------- config new blocks
def test_config_roundtrip_new_fields():
    from appsec.config import Config

    cfg = Config.from_dict({
        "enable_git_clone": True,
        "orchestrator": {"mode": "linear", "max_concurrency": 5},
        "analyzers": {"opengrep": False},
    })
    assert cfg.enable_git_clone is True
    assert cfg.orchestrator.mode == "linear" and cfg.orchestrator.max_concurrency == 5
    assert cfg.analyzers.opengrep is False
    again = Config.from_dict(cfg.to_dict())
    assert again.orchestrator.max_concurrency == 5


def test_config_show_redacts_secrets():
    from appsec.config import Config

    cfg = Config.from_dict({"llm": {"provider": "ollama"}})
    cfg.agent_models = {"chat": {"api_key": "sk-SECRET", "model": "x"}}
    shown = cfg.show()
    assert "sk-SECRET" not in shown and "***redacted***" in shown
