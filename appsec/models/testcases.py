"""
Description: Structured security test-case model (the manual test plan's unit of work).
Author: Aleksa Zatezalo
Date Created: 08-18-2026
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .findings import SEVERITIES

# Execution state of a test case. Deliberately about *the operator's progress*,
# not about the verdict — whether the test passed is recorded in ``result``, and
# a test that proved a bug real is triaged on the linked finding, not here.
TEST_STATUSES = ("new", "in_progress", "complete")

# What running the test showed. Only meaningful once status is ``complete``.
TEST_RESULTS = ("", "pass", "fail", "blocked", "inconclusive")

_STATUS_ALIASES = {
    "in-progress": "in_progress",
    "inprogress": "in_progress",
    "wip": "in_progress",
    "started": "in_progress",
    "done": "complete",
    "completed": "complete",
    "closed": "complete",
    "todo": "new",
    "open": "new",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _norm(text: str | None) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def normalize_status(value: str) -> str:
    """Map a user-typed status onto the vocabulary ('' if unrecognized)."""
    v = _norm(value).replace(" ", "_")
    v = _STATUS_ALIASES.get(v, v)
    return v if v in TEST_STATUSES else ""


def normalize_result(value: str) -> str:
    """Map a user-typed result onto the vocabulary ('!' sentinel if invalid)."""
    v = _norm(value)
    if v in ("", "none", "-"):
        return ""
    return v if v in TEST_RESULTS else "!"


@dataclass
class SecurityTestCase:
    """One manually-executable security test.

    Mirrors :class:`~appsec.models.findings.SecurityFinding`: a stable
    fingerprint keyed on what makes the test *distinct* (title + target), so the
    same test authored by two runs of the ``test_case`` agent collapses into one
    record and keeps the operator's progress on it.
    """

    title: str = ""
    objective: str = ""  # what this test is trying to establish
    target: str = ""  # endpoint / parameter / file:line under test
    preconditions: str = ""
    steps: list[str] = field(default_factory=list)
    expected_result: str = ""  # what proves the issue present-or-absent
    severity: str = "medium"
    id: str = ""
    fingerprint: str = ""
    # Traceability. ``finding_id`` links to a SecurityFinding; ``threat_ref`` is
    # free text for a threat-model element that has no id of its own.
    finding_id: str = ""
    threat_ref: str = ""
    # Operator progress + outcome.
    status: str = "new"
    result: str = ""
    notes: list[str] = field(default_factory=list)
    source_agent: str = ""  # "" for a hand-written test case
    created_at: datetime = field(default_factory=_now)
    updated_at: datetime = field(default_factory=_now)

    # -- identity ------------------------------------------------------------
    def compute_fingerprint(self) -> str:
        """Stable across runs for the *same* test (title + what it targets)."""
        basis = "|".join([_norm(self.title), _norm(self.target)])
        return hashlib.sha256(basis.encode()).hexdigest()[:16]

    def ensure_identity(self) -> "SecurityTestCase":
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()
        if not self.id:
            self.id = f"TC-{self.fingerprint[:8]}"
        return self

    # -- serialization -------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        self.ensure_identity()
        d = asdict(self)
        d["created_at"] = self.created_at.isoformat()
        d["updated_at"] = self.updated_at.isoformat()
        return d

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SecurityTestCase":
        raw = dict(raw or {})
        for key in ("created_at", "updated_at"):
            if isinstance(raw.get(key), str):
                try:
                    raw[key] = datetime.fromisoformat(raw[key])
                except ValueError:
                    raw[key] = _now()
        allowed = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in raw.items() if k in allowed})

    # -- rendering -----------------------------------------------------------
    def to_markdown(self) -> str:
        self.ensure_identity()
        link = self.finding_id or self.threat_ref or "—"
        out = [
            f"### {self.title or '(untitled test case)'}  `{self.id}`",
            "",
            f"Status: {self.status.replace('_', ' ').title()}"
            + (f"   Result: {self.result}" if self.result else ""),
            f"Severity: {self.severity.title()}",
            f"Verifies: {link}",
            f"Target: {self.target or '—'}",
        ]
        if self.objective:
            out += ["", f"Objective: {self.objective}"]
        if self.preconditions:
            out += ["", f"Preconditions: {self.preconditions}"]
        if self.steps:
            out += ["", "Steps:"]
            out += [f"{i}. {s}" for i, s in enumerate(self.steps, 1)]
        if self.expected_result:
            out += ["", f"Expected result: {self.expected_result}"]
        if self.notes:
            out += ["", "Notes:"]
            out += [f"- {n}" for n in self.notes]
        return "\n".join(out)


def validate_test_case(tc: SecurityTestCase) -> list[str]:
    """Structural validation. Returns human-readable errors (empty = ok)."""
    errs: list[str] = []
    if not tc.title:
        errs.append("title is required")
    if not tc.target:
        errs.append("target is required (endpoint / parameter / file:line)")
    if not tc.steps:
        errs.append("at least one step is required")
    if not tc.expected_result:
        errs.append(
            "expected_result is required — what proves the issue present or absent"
        )
    if tc.severity not in SEVERITIES:
        errs.append(f"invalid severity {tc.severity!r} (allowed: {SEVERITIES})")
    if tc.status not in TEST_STATUSES:
        errs.append(f"invalid status {tc.status!r} (allowed: {TEST_STATUSES})")
    if tc.result not in TEST_RESULTS:
        errs.append(f"invalid result {tc.result!r} (allowed: {TEST_RESULTS})")
    return errs


def dedupe_test_cases(cases: list[SecurityTestCase]) -> list[SecurityTestCase]:
    """Collapse test cases sharing a fingerprint, keeping the richer one."""
    by_fp: dict[str, SecurityTestCase] = {}
    for tc in cases:
        tc.ensure_identity()
        prev = by_fp.get(tc.fingerprint)
        if prev is None:
            by_fp[tc.fingerprint] = tc
            continue
        # keep whichever carries more detail; prefer an existing finding link
        if len(tc.steps) > len(prev.steps):
            tc.finding_id = tc.finding_id or prev.finding_id
            by_fp[tc.fingerprint] = tc
        else:
            prev.finding_id = prev.finding_id or tc.finding_id
    return list(by_fp.values())
