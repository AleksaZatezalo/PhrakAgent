"""
Description: Opengrep taint-mode integration — end-to-end against a fixture repo.

Runs the real `opengrep` binary against a vulnerable-by-design fixture (skipped
if opengrep isn't on PATH) and asserts that the resulting SecurityFinding
carries a supporting TaintPathReference derived from the JSON `dataflow_trace`.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from appsec.analyzers.opengrep import OpengrepAdapter, normalize
from appsec.tools.opengrep_tools import DEFAULT_TAINT_CONFIG, _run

pytestmark = pytest.mark.skipif(
    shutil.which("opengrep") is None, reason="opengrep not installed"
)

VULN_PY = """\
import sqlite3
from flask import Flask, request
app = Flask(__name__)

@app.route("/u")
def u():
    uid = request.args.get("id")
    conn = sqlite3.connect("x.db")
    q = "SELECT * FROM users WHERE id = " + uid
    return conn.execute(q).fetchall()
"""


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    (tmp_path / "vuln.py").write_text(VULN_PY)
    from appsec import runtime
    from appsec.config import Config

    cfg = Config()
    cfg.paths.workspace = str(tmp_path)
    runtime.init_runtime(cfg)
    yield tmp_path
    runtime.RUNTIME.config = None


def test_taint_config_exists():
    """Bundled taint ruleset ships in the package."""
    p = Path(DEFAULT_TAINT_CONFIG)
    assert p.exists() and p.is_dir()
    assert any(p.glob("*.yaml"))


def test_taint_scan_emits_dataflow_trace(workspace):
    """A real taint scan produces JSON with a dataflow_trace section."""
    data, err = _run("vuln.py", DEFAULT_TAINT_CONFIG)
    assert err is None, err
    results = data.get("results", [])
    assert results, "expected at least one taint result"
    r = results[0]
    trace = r.get("extra", {}).get("dataflow_trace")
    assert trace is not None, "opengrep taint result missing dataflow_trace"
    assert "taint_source" in trace
    assert "taint_sink" in trace


def test_normalize_builds_supporting_taint_path(workspace):
    """normalize() lifts dataflow_trace into a supporting TaintPathReference."""
    data, err = _run("vuln.py", DEFAULT_TAINT_CONFIG)
    assert err is None, err
    findings = normalize(data, workspace, config=DEFAULT_TAINT_CONFIG)
    assert findings, "expected at least one normalized finding"
    f = next((x for x in findings if x.taint_paths), None)
    assert f is not None, "expected a finding with a taint path"
    tp = f.taint_paths[0]
    assert tp.source.path == "vuln.py"
    assert tp.source.line == 7  # request.args.get(...) is on line 7
    assert tp.sink.path == "vuln.py"
    assert tp.sink.line == 10  # conn.execute(q) on line 10
    # A taint-mode hit gives us complete source→sink evidence; mode is
    # inter_procedural (opengrep's OSS engine is at least intra-file dataflow).
    assert tp.completeness == "complete"
    assert tp.analysis_mode in ("intra_procedural", "inter_procedural")
    # Steps include the intermediate variables Opengrep reported.
    assert len(tp.steps) >= 1
    # The category is data-flow — has_supporting_taint_path() is true.
    assert f.is_dataflow_category()
    assert f.has_supporting_taint_path()


def test_taint_finding_id_stable_across_runs(workspace):
    """Same code, same rules → same finding fingerprint."""
    d1, _ = _run("vuln.py", DEFAULT_TAINT_CONFIG)
    d2, _ = _run("vuln.py", DEFAULT_TAINT_CONFIG)
    f1 = normalize(d1, workspace, config=DEFAULT_TAINT_CONFIG)
    f2 = normalize(d2, workspace, config=DEFAULT_TAINT_CONFIG)
    assert f1 and f2
    ids1 = sorted(x.fingerprint for x in f1)
    ids2 = sorted(x.fingerprint for x in f2)
    assert ids1 == ids2


def test_adapter_run_returns_taint_findings(workspace):
    """OpengrepAdapter.run(taint=True) surfaces taint findings via AnalyzerResult."""
    adapter = OpengrepAdapter()
    if not adapter.is_available():
        pytest.skip("opengrep not available")
    res = adapter.run(path="vuln.py", config=DEFAULT_TAINT_CONFIG)
    assert res.error is None
    assert any(f.taint_paths for f in res.findings)
