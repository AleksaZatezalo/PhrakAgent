"""
Description: Deterministic extraction of findings / test cases from prose reports.
Author: Aleksa Zatezalo
Date Created: 08-20-2026

The extractor is the reliable backstop for weak local models that WRITE a
structured report but never CALL report_finding / report_test_case. These cases
use the exact report shapes qwen2.5-coder:7b produced in the field.
"""

from __future__ import annotations

from appsec.extract import findings_from_report
from appsec.extract import test_cases_from_report as _test_cases_from_report

# code_review direct output: "Finding N:" + Title/Category/Severity/File/Line.
CODE_REVIEW_REPORT = """
Finding 1: DEBUG mode enabled without explicit definition

Title: DEBUG mode enabled without explicit definition
Category: a05-security-misconfiguration
Severity: Medium
Description: The DEBUG setting in settings.py is not explicitly defined.
File: vulnbank/settings.py
Line: 12

Finding 2: Admin access without authentication

Title: Admin access without authentication
Category: a01-broken-access-control
Severity: High
Description: The admin endpoint has no authentication checks.
File: vulnbank/urls.py
Line: 3
"""

# /run synthesized output: numbered list, bullet "Component:"/"Severity:" attrs.
SYNTH_REPORT = """
Confirmed Findings (by severity)

Critical

 1 SQL Injection in Transfer Form
    * Component: bank/views.py (transfer view)
    * Severity: Critical
    * Description: The transfer form is vulnerable to SQL injection.
 2 Insecure Password Storage
    * Component: bank/models.py (User model)
    * Severity: High
    * Description: User passwords are stored without proper hashing.

Prioritized Remediation Roadmap

 1 Implement SQL Injection Prevention
    * Use parameterized queries instead of raw SQL.
"""

# test_case direct output: "N Title:" + Target/Steps/Expected Result/Severity.
TEST_CASE_REPORT = """
  1 Title: Verify Password Hashing is Correctly Implemented
     * Linked Finding/Threat: CWE-798: Hard-coded secret
     * Target: bank/models.py: Line 30
     * Preconditions: None
     * Steps:
        1 Create a user with a password.
        2 Retrieve the hashed password from the database.
        3 Compare both hashes for equality.
     * Expected Result: The hashes should be equal.
     * Severity: Critical
     * Finding ID: FND-ab12cd34ef
  2 Title: Check for SQL Injection Vulnerabilities in User Input
     * Target: bank/views.py: Line 100
     * Steps:
        1 Login with a username containing a SQL injection payload.
        2 Observe the response.
     * Expected Result: The system should reject the login attempt.
     * Severity: High
"""


def test_findings_from_code_review_report():
    findings = findings_from_report(CODE_REVIEW_REPORT, source_agent="code_review")
    assert len(findings) == 2
    by_title = {f.title: f for f in findings}
    debug = by_title["DEBUG mode enabled without explicit definition"]
    assert debug.severity == "medium"
    assert debug.affected_files == ["vulnbank/settings.py"]
    assert debug.evidence[0].start_line == 12
    assert debug.category == "a05-security-misconfiguration"
    admin = by_title["Admin access without authentication"]
    assert admin.severity == "high"
    assert admin.evidence[0].start_line == 3


def test_findings_from_synthesized_report_and_skips_remediation():
    findings = findings_from_report(SYNTH_REPORT, source_agent="synthesis")
    titles = {f.title for f in findings}
    # both real findings recovered...
    assert "SQL Injection in Transfer Form" in titles
    assert "Insecure Password Storage" in titles
    # ...but the remediation-roadmap item (no severity/file/desc attrs) is not.
    assert "Implement SQL Injection Prevention" not in titles
    assert len(findings) == 2
    sqli = next(f for f in findings if f.title == "SQL Injection in Transfer Form")
    assert sqli.severity == "critical"
    assert sqli.affected_files == ["bank/views.py"]


def test_test_cases_from_report():
    cases = _test_cases_from_report(TEST_CASE_REPORT, source_agent="test_case")
    assert len(cases) == 2
    first = cases[0]
    assert first.title == "Verify Password Hashing is Correctly Implemented"
    assert first.target.startswith("bank/models.py")
    assert len(first.steps) == 3
    assert first.expected_result.startswith("The hashes should be equal")
    assert first.severity == "critical"
    assert first.finding_id == "FND-ab12cd34ef"


def test_test_case_report_yields_no_findings():
    # A test-case block (steps/expected/target) must not be mis-read as a finding.
    assert findings_from_report(TEST_CASE_REPORT) == []


def test_code_review_report_yields_no_test_cases():
    # A finding block (no steps/expected/target) must not become a test case.
    assert _test_cases_from_report(CODE_REVIEW_REPORT) == []


def test_empty_and_junk_text_yield_nothing():
    for txt in ("", "   ", "just some prose with no structure at all."):
        assert findings_from_report(txt) == []
        assert _test_cases_from_report(txt) == []


def test_finding_without_locatable_file_is_unconfirmed(tmp_path):
    report = """
Finding 1: Something vague

Title: Something vague
Severity: High
Description: A concern with no file reference.
"""
    findings = findings_from_report(report, workspace=tmp_path)
    assert len(findings) == 1
    assert findings[0].status == "unconfirmed"
    assert findings[0].confidence <= 0.4
