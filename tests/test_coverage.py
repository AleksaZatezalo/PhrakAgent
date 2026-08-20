"""
Description: Test-case coverage — link existing tests to findings and backfill.
Author: Aleksa Zatezalo
Date Created: 08-20-2026

Every finding, including an unconfirmed one, must end up with a test case that
verifies it. These pin the two halves: unambiguous content-linking of an
existing test case, and generation of a linked verification case for a finding
nothing covers.
"""

from __future__ import annotations

from appsec.coverage import ensure_test_case_coverage
from appsec.models.findings import FindingEvidence, SecurityFinding
from appsec.models.testcases import SecurityTestCase
from appsec.store import FindingStore
from appsec.store import TestCaseStore as TCStore  # aliased: not a test class


def _finding(title, sev="high", desc="", path="", line=None):
    ev = [FindingEvidence(path=path, start_line=line, end_line=line, reason=desc)]
    return SecurityFinding(
        title=title,
        category="",
        severity=sev,
        description=desc,
        status="unconfirmed",
        confidence=0.4,
        evidence=ev,
    ).ensure_identity()


def _case(title, target, tref="", sev="high"):
    return SecurityTestCase(
        title=title,
        target=target,
        steps=["do a thing"],
        expected_result="it is safe",
        severity=sev,
        threat_ref=tref,
        source_agent="test_case",
    ).ensure_identity()


def test_backfills_a_test_case_for_an_uncovered_finding(runtime):
    f = _finding("Exposure of Password Hashes in the Database", "medium")
    FindingStore(runtime).upsert([f])

    r = ensure_test_case_coverage(runtime)
    assert r["generated"] == 1
    cases = TCStore(runtime).list()
    assert len(cases) == 1
    assert cases[0].finding_id == f.id
    assert cases[0].source_agent == "coverage"
    assert cases[0].severity == "medium"
    assert cases[0].target  # a non-empty target is required for a valid test case


def test_links_an_existing_test_case_by_strong_title_overlap(runtime):
    f = _finding("Brute Force Attack on Admin Panel Login")
    FindingStore(runtime).upsert([f])
    tc = _case(
        "Verify Multi-Factor Authentication for Admin Panel Logins",
        "views.py:login",
        tref="T-01",
    )
    TCStore(runtime).upsert([tc])

    r = ensure_test_case_coverage(runtime)
    assert r["linked"] == 1
    assert r["generated"] == 0  # the finding is now covered by the linked test
    linked = TCStore(runtime).get(tc.id)
    assert linked.finding_id == f.id


def test_ambiguous_match_is_not_linked_but_is_backfilled(runtime):
    # Two findings share "admin panel"; a test that matches both equally must not
    # be linked to a guess — the uncovered finding gets a generated case instead.
    f1 = _finding("Brute Force Attack on Admin Panel Login")
    f2 = _finding("Privilege Escalation in Admin Panel")
    FindingStore(runtime).upsert([f1, f2])
    tc = _case("Verify Role Based Access Control for Admin Panel", "views.py:admin")
    TCStore(runtime).upsert([tc])

    ensure_test_case_coverage(runtime)
    still = TCStore(runtime).get(tc.id)
    assert still.finding_id == ""  # ambiguous → left unlinked
    covered = {c.finding_id for c in TCStore(runtime).list() if c.finding_id}
    assert f1.id in covered and f2.id in covered  # both backfilled


def test_is_idempotent(runtime):
    f = _finding("SQL Injection in Login")
    FindingStore(runtime).upsert([f])
    first = ensure_test_case_coverage(runtime)
    assert first["generated"] == 1
    second = ensure_test_case_coverage(runtime)
    assert second == {"linked": 0, "generated": 0}
    assert len(TCStore(runtime).list()) == 1


def test_no_findings_is_a_noop(runtime):
    assert ensure_test_case_coverage(runtime) == {"linked": 0, "generated": 0}
    assert TCStore(runtime).list() == []
