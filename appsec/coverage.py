"""
Description: Tie test cases to the findings they verify, and backfill coverage.
Author: Aleksa Zatezalo
Date Created: 08-20-2026

In a full `/run` the findings are only known once the pipeline synthesizes (and
PHRAK salvages them from the report), which is AFTER the `test_case` agent has
already run — so its test cases link to the threat refs it invented (T-01…), not
to the finding ids (FND-…). This module reconciles that after the fact, without a
model:

  1. LINK — an unlinked test case is pointed at the finding it clearly matches
     (strong, unambiguous title-token overlap only — never a guess).
  2. BACKFILL — every finding still without a linked test case gets a minimal,
     finding-linked verification test case, so no finding (confirmed OR
     unconfirmed) is left without something to verify it.

Deterministic and idempotent: once a finding is covered (some test case links to
it), later runs neither relink nor regenerate.
"""

from __future__ import annotations

import re

from .config import Config
from .models.testcases import SecurityTestCase

# Generic words that carry no matching signal between a finding and a test case.
_STOP = {
    "verify", "check", "test", "the", "a", "an", "of", "in", "on", "for", "to",
    "and", "or", "is", "are", "be", "via", "with", "without", "proper", "improper",
    "potential", "possible", "implement", "implementation", "ensure", "attack",
    "attacks", "vulnerability", "vulnerabilities", "issue", "issues", "against",
    "using", "use", "additional", "measures", "security", "controls", "control",
    "prevent", "preventing", "review", "finding", "system", "application", "app",
}


def _tokens(text: str) -> set[str]:
    """Significant, singularized lower-case tokens for fuzzy matching."""
    out: set[str] = set()
    for raw in re.findall(r"[A-Za-z][A-Za-z0-9]+", (text or "").lower()):
        if raw in _STOP or len(raw) < 3:
            continue
        out.add(raw[:-1] if raw.endswith("s") and len(raw) > 3 else raw)
    return out


def _finding_target(f) -> str:
    """What the verification test actually targets — a real location when we have
    one, otherwise an honest pointer back to the finding."""
    if f.evidence and f.evidence[0].path:
        return f.evidence[0].location()
    if f.affected_files:
        return f.affected_files[0]
    return f"component described in {f.id}"


def _match_finding(case: SecurityTestCase, findings: list) -> "object | None":
    """The finding a test case unambiguously verifies, or None.

    Requires the best title-token overlap to be >= 2 AND strictly beat the
    runner-up — so a test that could plausibly map to two findings (both mention
    "admin panel") is left for the backfill step rather than linked to a guess.
    """
    ct = _tokens(case.title) | _tokens(case.target)
    scored = sorted(
        ((len(ct & _tokens(f.title)), f) for f in findings),
        key=lambda p: p[0],
        reverse=True,
    )
    if not scored or scored[0][0] < 2:
        return None
    if len(scored) > 1 and scored[1][0] == scored[0][0]:
        return None  # ambiguous — two findings match equally well
    return scored[0][1]


def _verification_case(f) -> SecurityTestCase:
    """A minimal, honest verification test case for a finding with no coverage."""
    target = _finding_target(f)
    desc = (f.description or f.title).strip()
    steps = [
        f"Locate the code/behaviour described in {f.id} at {target}.",
        f"Attempt to trigger the weakness: {desc[:160]}",
        "Observe whether the described impact actually occurs.",
    ]
    if f.recommendation:
        steps.append(f"Check whether the remediation is absent: {f.recommendation[:160]}")
    return SecurityTestCase(
        title=f"Verify finding: {f.title}",
        objective=f"Confirm or rule out {f.title} ({f.id}).",
        target=target,
        steps=steps,
        expected_result=(
            "The weakness cannot be triggered — the finding is not exploitable as "
            "described (issue absent). A successful trigger confirms it."
        ),
        severity=f.severity,
        finding_id=f.id,
        source_agent="coverage",
    ).ensure_identity()


def ensure_test_case_coverage(config: Config) -> dict:
    """Link and backfill so every finding has a test case. Returns counts.

    ``{"linked": n, "generated": m}`` — linked existing test cases pointed at a
    finding, and freshly generated verification cases for uncovered findings.
    """
    from .store import FindingStore, TestCaseStore

    fstore, tstore = FindingStore(config), TestCaseStore(config)
    findings = [r.as_finding() for r in fstore.list()]
    if not findings:
        return {"linked": 0, "generated": 0}
    cases = tstore.list()

    # 1) LINK unlinked test cases to the finding they clearly verify.
    linked = 0
    for tc in cases:
        if tc.finding_id:
            continue
        match = _match_finding(tc, findings)
        if match is not None:
            tstore.link_finding(tc.id, match.id)
            tc.finding_id = match.id
            linked += 1

    # 2) BACKFILL a verification case for every finding still uncovered.
    covered = {tc.finding_id for tc in tstore.list() if tc.finding_id}
    fresh = [_verification_case(f) for f in findings if f.id not in covered]
    if fresh:
        tstore.upsert(fresh)
    return {"linked": linked, "generated": len(fresh)}
