"""
Description: Shared pytest fixtures for the PHRAK test bench.
Author: Aleksa Zatezalo
Date Created: 07-29-2026
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the repo importable without an editable install.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from appsec.config import Config, PathsConfig, RagConfig  # noqa: E402

SAMPLE_VULN_APP = """\
import sqlite3
from flask import Flask, request

app = Flask(__name__)
DB_PASSWORD = "SuperSecret123!"   # hardcoded secret


@app.route("/user")
def get_user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    q = "SELECT * FROM users WHERE id = '" + uid + "'"   # SQL injection
    return str(conn.execute(q).fetchall())


@app.route("/ping")
def ping():
    import os
    host = request.args.get("host")
    return os.popen("ping -c 1 " + host).read()   # command injection
"""


@pytest.fixture
def workspace(tmp_path) -> Path:
    """A temp workspace containing a small vulnerable Flask app."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "vuln_app.py").write_text(SAMPLE_VULN_APP)
    (ws / "requirements.txt").write_text("flask\n")
    return ws


@pytest.fixture
def config(tmp_path, workspace) -> Config:
    """A Config pointing entirely at temp dirs."""
    cfg = Config(
        paths=PathsConfig(
            workspace=str(workspace),
            skills_dir=str(tmp_path / "skills"),
            reports_dir=str(tmp_path / "reports"),
        ),
        rag=RagConfig(persist_dir=str(tmp_path / "rag")),
    )
    cfg.ensure_dirs()
    return cfg


@pytest.fixture
def runtime(config):
    """Install ``config`` into the global runtime for the duration of a test."""
    from appsec import runtime as rt

    rt.RUNTIME.config = config
    yield config
    rt.RUNTIME.config = None


@pytest.fixture
def skills(config):
    """A learned-skills store backed by a temp skills dir."""
    from appsec.skill_store import SkillStore

    return SkillStore(config)


class FakeLLM:
    """Minimal stand-in for a chat model: returns a canned or scripted response."""

    def __init__(self, reply="", raises=False):
        self.reply = reply
        self.raises = raises
        self.calls = []

    def invoke(self, prompt):
        self.calls.append(prompt)
        if self.raises:
            raise RuntimeError("llm unavailable")

        class _R:
            content = self.reply

        return _R()
