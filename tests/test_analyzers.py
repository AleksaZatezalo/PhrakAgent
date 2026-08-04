"""
Description: Phase 6 — analyzer normalization, dependency audit, sanitizer tables.
Author: Aleksa Zatezalo
Date Created: 07-30-2026
"""

from __future__ import annotations

import json
from pathlib import Path

import appsec.analyzers.dependencies as deps
import appsec.tools.analyzer_tools as at
from appsec.analyzers.base import AnalyzerAdapter, AnalyzerResult, finalize_findings
from appsec.analyzers.dependencies import (
    DependencyAuditAdapter,
    parse_cargo_audit,
    parse_govulncheck,
    parse_npm_audit,
    parse_pip_audit,
)
from appsec.analyzers.opengrep import OpengrepAdapter, normalize
from appsec.analyzers.sanitizers import assess, canonical_category, canonical_sanitizer
from appsec.models.findings import FindingEvidence, SecurityFinding


# --------------------------------------------------------------- protocol
def test_adapters_satisfy_protocol():
    assert isinstance(OpengrepAdapter(), AnalyzerAdapter)
    assert isinstance(DependencyAuditAdapter(), AnalyzerAdapter)


# --------------------------------------------------------------- opengrep normalize
def _og_result(root: Path, name: str, line: int, sev: str, check: str, msg: str,
               cwe=None, owasp=None) -> dict:
    meta: dict = {}
    if cwe is not None:
        meta["cwe"] = cwe
    if owasp is not None:
        meta["owasp"] = owasp
    return {
        "check_id": f"python.lang.security.{check}",
        "path": str(root / name),
        "start": {"line": line}, "end": {"line": line},
        "extra": {"severity": sev, "message": msg, "metadata": meta},
    }


def test_normalize_maps_severity_cwe_and_status(runtime):
    root = Path(runtime.paths.workspace).resolve()
    data = {"results": [
        _og_result(root, "vuln_app.py", 12, "ERROR", "sql-injection",
                   "SQL injection via user input",
                   cwe=["CWE-89: SQL Injection"], owasp=["A03:2021 - Injection"]),
    ]}
    [f] = normalize(data, root)
    assert f.severity == "high"                 # ERROR -> high
    assert f.status == "unconfirmed"            # a pattern hit is a lead
    assert f.confidence <= 0.6
    assert "CWE-89" in f.cwe_ids
    assert f.owasp_categories == ["A03:2021 - Injection"]
    assert f.category == "sql-injection"        # rule short name -> dataflow category
    assert f.is_dataflow_category()
    assert f.source_tools == ["opengrep"]
    assert f.evidence[0].evidence_type == "analyzer_hit"
    assert f.affected_files == ["vuln_app.py"]


def test_opengrep_adapter_run_normalizes(runtime, monkeypatch):
    root = Path(runtime.paths.workspace).resolve()
    data = {"results": [_og_result(root, "vuln_app.py", 12, "WARNING", "weak", "weak")]}
    # bypass the real CLI: _run returns parsed JSON
    monkeypatch.setattr("appsec.analyzers.opengrep._run", lambda p, c: (data, None))
    monkeypatch.setattr("appsec.analyzers.opengrep._format", lambda d, c: "raw summary")
    result = OpengrepAdapter().run(".")
    assert result.tool == "opengrep"
    assert len(result.findings) == 1
    assert result.summary == "raw summary"


def test_opengrep_adapter_run_surfaces_error(runtime, monkeypatch):
    monkeypatch.setattr("appsec.analyzers.opengrep._run",
                        lambda p, c: (None, "opengrep is not installed"))
    result = OpengrepAdapter().run(".")
    assert result.error and "not installed" in result.error
    assert result.findings == []


# --------------------------------------------------------------- finalize pipeline
def _grounded(root_name: str, line: int, conf: float, status: str) -> SecurityFinding:
    return SecurityFinding(
        title="t", category="static-analysis", severity="high",
        confidence=conf, status=status,
        evidence=[FindingEvidence(path=root_name, start_line=line, end_line=line,
                                  evidence_type="analyzer_hit")],
        source_tools=["opengrep"],
    )


def test_finalize_downgrades_ungrounded_and_drops_invalid(runtime):
    root = Path(runtime.paths.workspace)
    grounded = _grounded("vuln_app.py", 12, 0.9, "new")
    ungrounded = _grounded("does_not_exist.py", 3, 0.9, "new")
    invalid = SecurityFinding(title="no evidence", severity="high")  # no evidence/taint
    out = finalize_findings([grounded, ungrounded, invalid], root)
    by_file = {f.affected_files[0] if f.affected_files else f.evidence[0].path: f
               for f in out}
    # invalid dropped
    assert all(f.title != "no evidence" for f in out)
    # ungrounded downgraded
    ung = next(f for f in out if f.evidence[0].path == "does_not_exist.py")
    assert ung.status == "unconfirmed" and ung.confidence <= 0.4
    # grounded kept as-is
    g = next(f for f in out if f.evidence[0].path == "vuln_app.py")
    assert g.status == "new" and g.confidence == 0.9


# --------------------------------------------------------------- dependency parsers
def test_parse_pip_audit():
    data = {"dependencies": [
        {"name": "flask", "version": "0.12.0", "vulns": [
            {"id": "PYSEC-2019-179", "fix_versions": ["0.12.3"],
             "aliases": ["CVE-2019-1010083"],
             "description": "DoS via crafted encoding (CWE-400)."}]},
        {"name": "clean", "version": "1.0", "vulns": []},
    ]}
    [f] = parse_pip_audit(data, "requirements.txt")
    assert f.category == "vulnerable-dependency"
    assert "flask" in f.title and "PYSEC-2019-179" in f.title
    assert "CWE-400" in f.cwe_ids
    assert "0.12.3" in f.recommendation
    assert f.source_tools == ["pip-audit"]
    assert f.evidence[0].path == "requirements.txt"


def test_parse_npm_audit():
    data = {"vulnerabilities": {"lodash": {
        "name": "lodash", "severity": "high", "range": "<4.17.21",
        "via": [{"title": "Prototype Pollution", "url": "https://ghsa/x",
                 "cwe": ["CWE-1321"], "source": 123}],
        "fixAvailable": {"name": "lodash", "version": "4.17.21"}}}}
    [f] = parse_npm_audit(data, "package.json")
    assert f.severity == "high"
    assert "CWE-1321" in f.cwe_ids
    assert "Prototype Pollution" in f.title
    assert "lodash@4.17.21" in f.recommendation
    assert f.source_tools == ["npm-audit"]


def test_parse_cargo_audit():
    data = {"vulnerabilities": {"found": True, "count": 1, "list": [{
        "advisory": {"id": "RUSTSEC-2021-0001", "title": "time segfault",
                     "description": "OOB", "url": "https://x",
                     "categories": ["memory-corruption"]},
        "package": {"name": "time", "version": "0.1.0"},
        "versions": {"patched": [">=0.2.23"]}}]}}
    [f] = parse_cargo_audit(data, "Cargo.toml")
    assert "time" in f.title and "RUSTSEC-2021-0001" in f.title
    assert ">=0.2.23" in f.recommendation
    assert f.source_tools == ["cargo-audit"]


def test_parse_govulncheck_reachable_only():
    text = (
        json.dumps({"osv": {"id": "GO-2021-0001", "summary": "stdlib bug",
                            "affected": [{"package": {"name": "golang.org/x/text"}}],
                            "references": [{"url": "https://x"}]}})
        + "\n"
        + json.dumps({"finding": {"osv": "GO-2021-0001",
                                  "trace": [{"function": "Parse",
                                             "module": "golang.org/x/text"}]}})
    )
    [f] = parse_govulncheck(text, "go.mod")
    assert "GO-2021-0001" in f.title
    assert f.source_tools == ["govulncheck"]
    assert f.category == "vulnerable-dependency"


def test_dependency_adapter_detects_manifests_and_degrades(runtime, monkeypatch):
    # conftest workspace ships requirements.txt -> python ecosystem present.
    monkeypatch.setattr(deps.shutil, "which", lambda _b: None)   # no auditors installed
    adapter = DependencyAuditAdapter()
    assert adapter.supports(".") is True
    assert adapter.is_available() is False
    result = adapter.run(".")
    assert result.findings == []
    assert "pip-audit not installed" in result.summary


# --------------------------------------------------------------- sanitizer table
def test_html_escape_is_not_sql_safe():
    a = assess("html.escape", "sql injection")
    assert a.effective is False and a.false_assumption is True
    b = assess("html.escape", "xss")
    assert b.effective is True and b.false_assumption is False


def test_shlex_quote_depends_on_shell():
    with_shell = assess("shlex.quote", "command injection", shell=True)
    assert with_shell.effective is False and with_shell.false_assumption is True
    arg_array = assess("shlex.quote", "command injection", shell=False)
    assert arg_array.effective is True


def test_urlparse_is_not_ssrf_safe():
    a = assess("urlparse", "ssrf")
    assert a.effective is False and a.false_assumption is True


def test_prefix_check_requires_canonicalization():
    before = assess("startswith", "path traversal", canonicalized=False)
    assert before.effective is False and before.false_assumption is True
    after = assess("startswith", "path traversal", canonicalized=True)
    assert after.effective is True


def test_authn_is_not_authz():
    a = assess("authentication", "idor")
    assert a.effective is False and a.false_assumption is True
    b = assess("authorization", "broken-access-control")
    assert b.effective is True


def test_parameterized_query_fixes_sqli():
    assert assess("parameterized query", "sql injection").effective is True


def test_category_and_sanitizer_aliasing():
    assert canonical_category("SQLi") == "sql_injection"
    assert canonical_category("directory-traversal") == "path_traversal"
    assert canonical_sanitizer("os.path.realpath") == "canonicalize"
    assert canonical_sanitizer("html.escape()") == "html_escape"


def test_unknown_sanitizer_is_unknown():
    a = assess("some_custom_filter", "xss")
    assert a.effective is None and a.false_assumption is False


# --------------------------------------------------------------- tools
def test_check_sanitizer_tool_flags_false_assumption():
    out = at.check_sanitizer.invoke(
        {"sanitizer": "html.escape", "vuln_class": "sql injection"})
    assert "NOT EFFECTIVE" in out and "FALSE-SANITIZER" in out


def test_analyzer_scan_tool_records_findings(runtime, monkeypatch):
    from appsec.runtime import begin_findings, take_findings

    root = Path(runtime.paths.workspace).resolve()

    class _FakeAdapter:
        def run(self, path=".."):
            return AnalyzerResult(tool="opengrep", summary="s", findings=[
                _grounded("vuln_app.py", 12, 0.5, "unconfirmed")])

    monkeypatch.setattr(at, "OpengrepAdapter", _FakeAdapter)
    begin_findings()
    out = at.analyzer_scan.invoke({"path": "."})
    captured = take_findings()
    assert len(captured) == 1
    assert "Recorded 1 structured finding" in out


def test_code_review_wires_phase6_tools():
    from appsec.agents.code_review import _tools

    names = {getattr(t, "name", "") for t in _tools()}
    assert {"analyzer_scan", "dependency_audit", "check_sanitizer"} <= names
    assert {"opengrep_scan", "scan_secrets", "report_finding"} <= names
