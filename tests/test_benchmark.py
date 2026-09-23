"""
Description: Benchmark scoring + ground-truth loading (no LLM, no network).
Author: Aleksa Zatezalo
Date Created: 09-22-2026
"""

from __future__ import annotations

from appsec import benchmark
from appsec.models.findings import FindingEvidence, SecurityFinding


def _finding(title="", category="", cwe=None, file="vuln_app.py", line=None):
    ev = [FindingEvidence(path=file, start_line=line, reason="x")] if line else []
    return SecurityFinding(
        title=title,
        category=category,
        severity="high",
        cwe_ids=list(cwe or []),
        affected_files=[file] if file else [],
        evidence=ev,
    )


# ------------------------------------------------------------- ground truth
def test_ground_truth_loads_all_labels():
    target, truths = benchmark.load_ground_truth("vuln_app")
    assert target == "vuln_app.py"
    ids = {t.id for t in truths}
    assert ids == {"GT-SQLI", "GT-CMDI", "GT-SECRET", "GT-DEBUG"}
    sqli = next(t for t in truths if t.id == "GT-SQLI")
    assert sqli.cwe == "CWE-89"
    assert sqli.line == 19


def test_target_source_is_shipped():
    names = {p.name for p in benchmark.target_files()}
    assert "vuln_app.py" in names


# ------------------------------------------------------------------ scoring
def test_perfect_match_scores_full():
    _, truths = benchmark.load_ground_truth("vuln_app")
    findings = [
        _finding(cwe=["CWE-89"], line=19),
        _finding(cwe=["CWE-78"], line=28),
        _finding(cwe=["CWE-798"], line=11),
        _finding(cwe=["CWE-489"], line=32),
    ]
    s = benchmark.score(findings, truths)
    assert (s.tp, s.fp, s.fn) == (4, 0, 0)
    assert s.recall == 1.0 and s.precision == 1.0 and s.f1 == 1.0


def test_missed_truth_drops_recall():
    _, truths = benchmark.load_ground_truth("vuln_app")
    findings = [_finding(cwe=["CWE-89"], line=19)]  # only SQLi
    s = benchmark.score(findings, truths)
    assert s.tp == 1 and s.fn == 3
    assert s.recall == 0.25 and s.precision == 1.0


def test_spurious_finding_drops_precision():
    _, truths = benchmark.load_ground_truth("vuln_app")
    findings = [
        _finding(cwe=["CWE-89"], line=19),
        _finding(title="totally made up", category="misc", cwe=["CWE-1004"]),
    ]
    s = benchmark.score(findings, truths)
    assert s.tp == 1 and s.fp == 1
    assert s.precision == 0.5


def test_keyword_and_file_match_without_cwe():
    """No CWE on the finding — a keyword hit plus the right file still matches."""
    _, truths = benchmark.load_ground_truth("vuln_app")
    f = _finding(title="SQL injection in the user route", file="vuln_app.py", line=19)
    s = benchmark.score([f], truths)
    assert s.tp == 1


def test_keyword_without_file_does_not_match():
    _, truths = benchmark.load_ground_truth("vuln_app")
    f = _finding(title="SQL injection somewhere", file="other.py", line=1)
    s = benchmark.score([f], truths)
    assert s.tp == 0 and s.fp == 1


def test_each_truth_claims_one_finding():
    """Two findings for the same vuln => one TP, one FP (one-to-one matching)."""
    _, truths = benchmark.load_ground_truth("vuln_app")
    findings = [_finding(cwe=["CWE-89"], line=19), _finding(cwe=["CWE-89"], line=19)]
    s = benchmark.score(findings, truths)
    assert s.tp == 1 and s.fp == 1


def test_empty_findings_score_zero():
    _, truths = benchmark.load_ground_truth("vuln_app")
    s = benchmark.score([], truths)
    assert s.tp == 0 and s.recall == 0.0 and s.precision == 0.0 and s.f1 == 0.0


# --------------------------------------------------------------- rendering
def test_render_table_and_json_roundtrip():
    _, truths = benchmark.load_ground_truth("vuln_app")
    rows = [
        benchmark.ResultRow(
            provider="ollama",
            model="qwen2.5-coder:7b",
            score=benchmark.score([_finding(cwe=["CWE-89"], line=19)], truths),
            input_tokens=100,
            output_tokens=50,
            calls=3,
            elapsed=12.5,
        ),
        benchmark.ResultRow(
            provider="anthropic", model="claude-opus-5", score=None, error="no key"
        ),
    ]
    table = benchmark.render_table(rows)
    assert "ollama:qwen2.5-coder:7b" in table
    assert "no key" in table

    js = benchmark.results_json(rows)
    assert js[0]["total_tokens"] == 150
    assert js[0]["recall"] == 0.25
    assert js[1]["error"] == "no key"
