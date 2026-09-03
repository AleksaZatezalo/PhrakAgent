"""
Description: Shared prose->structured salvage: turn a report the model WROTE into
    trackable findings / test cases, for the two places that must recover them.
Author: Aleksa Zatezalo
Date Created: 09-03-2026

Two independent paths need to reconstruct structured items from a prose report a
weak model produced without calling the capture tools:

- an ``Agent`` whose run left ``/findings`` empty transcribes its own report into
  the run's collectors (:func:`parse_report`), and
- the ``Orchestrator`` recovers items from the *consolidated* report into the
  durable stores when no agent recorded anything (:func:`into_stores`).

Both used to inline the same :mod:`appsec.extract` calls, workspace resolution,
and "N finding(s), M test case(s)" phrasing. This module is the one place that
knows how to do it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from . import extract


@dataclass
class Salvage:
    """The structured items recovered from a prose report."""

    findings: list = field(default_factory=list)  # SecurityFinding
    test_cases: list = field(default_factory=list)  # SecurityTestCase

    def __bool__(self) -> bool:
        return bool(self.findings or self.test_cases)


def _workspace() -> Optional[Any]:
    """The workspace root for validating finding locations, or None if unknown.

    Best-effort: outside a configured runtime (some unit tests) there is no
    workspace, and extraction simply skips the file/line validation step.
    """
    try:
        from .tools.common import workspace

        return workspace()
    except Exception:
        return None


def parse_report(
    text: str,
    *,
    source_agent: str = "",
    findings: bool = True,
    test_cases: bool = True,
) -> Salvage:
    """Deterministically parse a prose report into structured items.

    No model call, no tokens. Findings are validated against the workspace files
    when a workspace is resolvable. Either track can be turned off — e.g. an
    agent that records findings but authors no test cases passes
    ``test_cases=False`` so a stray test-case-shaped block isn't invented.
    """
    res = Salvage()
    if not (text or "").strip():
        return res
    if findings:
        res.findings = extract.findings_from_report(
            text, source_agent=source_agent, workspace=_workspace()
        )
    if test_cases:
        res.test_cases = extract.test_cases_from_report(text, source_agent=source_agent)
    return res


def summary(n_findings: int, n_test_cases: int) -> str:
    """"N finding(s), M test case(s)", dropping a zero track; "" when both zero."""
    return ", ".join(
        p
        for p in (
            f"{n_findings} finding(s)" if n_findings else "",
            f"{n_test_cases} test case(s)" if n_test_cases else "",
        )
        if p
    )


def into_stores(
    config,
    text: str,
    *,
    source_agent: str,
    run_id: str,
    findings: bool = True,
    test_cases: bool = True,
) -> Salvage:
    """Parse ``text`` and merge the recovered items into the durable stores.

    The orchestrator's post-synthesis recovery: when the agents recorded nothing
    this run, populate the finding / taint / test-case stores from the
    consolidated report so ``/findings`` and ``/testcases`` aren't empty. Raises
    on a store failure — the caller decides whether that's fatal (it isn't).
    """
    from .store import FindingStore, TaintStore, TestCaseStore

    res = parse_report(
        text, source_agent=source_agent, findings=findings, test_cases=test_cases
    )
    if res.findings:
        FindingStore(config).upsert(res.findings, run_id=run_id)
        TaintStore(config).upsert(res.findings, run_id=run_id)
    if res.test_cases:
        TestCaseStore(config).upsert(res.test_cases)
    return res
