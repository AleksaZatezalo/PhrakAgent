"""
Description: Shared severity ranking + prose-salvage helpers.
Author: Aleksa Zatezalo
Date Created: 09-03-2026
"""

from __future__ import annotations

from appsec import salvage
from appsec.models.findings import SEVERITIES, severity_rank


# --------------------------------------------------------------- severity_rank
def test_severity_rank_orders_most_severe_first():
    ranks = [severity_rank(s) for s in SEVERITIES]
    assert ranks == sorted(ranks)
    assert severity_rank("critical") < severity_rank("low")


def test_severity_rank_sorts_unknown_last():
    assert severity_rank("banana") == len(SEVERITIES)
    assert severity_rank("banana") > severity_rank("info")


def test_severity_rank_matches_the_old_inline_dict():
    # The dict this helper replaced, verbatim, plus its .get(_, 5) default.
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for sev in (*SEVERITIES, "", "weird"):
        assert severity_rank(sev) == order.get(sev, 5)


# ------------------------------------------------------------------- summary
def test_summary_drops_zero_tracks():
    assert salvage.summary(2, 3) == "2 finding(s), 3 test case(s)"
    assert salvage.summary(2, 0) == "2 finding(s)"
    assert salvage.summary(0, 1) == "1 test case(s)"
    assert salvage.summary(0, 0) == ""


# ---------------------------------------------------------------- parse_report
def _report() -> str:
    return (
        "## Summary\nOne issue found.\n\n"
        "Title: SQL Injection in login\n"
        "Category: a03-injection\n"
        "Severity: High\n"
        "Description: Unsanitized username reaches the query.\n"
        "File: vuln_app.py\n"
        "Line: 11\n"
    )


def test_parse_report_extracts_a_finding():
    res = salvage.parse_report(_report(), source_agent="code_review")
    assert res  # truthy when anything recovered
    assert len(res.findings) == 1
    assert "SQL Injection in login" in res.findings[0].title


def test_parse_report_empty_text_is_falsy_and_empty():
    res = salvage.parse_report("   ", source_agent="x")
    assert not res
    assert res.findings == [] and res.test_cases == []


def test_parse_report_can_disable_a_track():
    # A findings-only agent must not have a test-case-shaped block invented.
    res = salvage.parse_report(_report(), source_agent="x", test_cases=False)
    assert res.test_cases == []
