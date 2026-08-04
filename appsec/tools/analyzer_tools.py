"""
Description: Phase-6 analyzer tools — normalized analyzer leads + a false-sanitizer check.
Author: Aleksa Zatezalo
Date Created: 07-30-2026
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..analyzers import DependencyAuditAdapter, OpengrepAdapter, finalize_findings
from ..analyzers.base import AnalyzerResult
from ..analyzers.sanitizers import assess
from ..runtime import record_finding, require_config
from .common import ANALYSIS_MAX, workspace


def _analyzer_enabled(name: str) -> bool:
    """Respect the config.analyzers on/off switches (default on)."""
    try:
        return bool(getattr(require_config().analyzers, name, True))
    except Exception:
        return True


def _record_and_summarize(result: AnalyzerResult) -> str:
    if result.error:
        return result.error
    findings = finalize_findings(result.findings, workspace())
    for f in findings:
        record_finding(f)
    lines = [result.summary] if result.summary else []
    if findings:
        n_unconf = sum(1 for f in findings if f.status == "unconfirmed")
        lines.append(
            f"\nRecorded {len(findings)} structured finding(s) "
            f"({len(findings) - n_unconf} grounded, {n_unconf} unconfirmed):"
        )
        for f in findings:
            loc = f.evidence[0].location() if f.evidence else "?"
            lines.append(f"- {f.id} [{f.severity}] {f.title}  @ {loc}")
    return "\n".join(lines)[:ANALYSIS_MAX]


@tool
def analyzer_scan(path: str = ".") -> str:
    """Run Opengrep and record its hits as structured, workspace-grounded findings
    (status 'unconfirmed' — they are leads to verify by reading the code). Findings
    are deduped with anything you later confirm via report_finding. Use this to
    capture leads in the findings store; use opengrep_scan for a quick text read."""
    if not _analyzer_enabled("opengrep"):
        return "opengrep analyzer is disabled in config (analyzers.opengrep=false)."
    return _record_and_summarize(OpengrepAdapter().run(path))


@tool
def dependency_audit(path: str = ".") -> str:
    """Audit dependency manifests for KNOWN-VULNERABLE versions and record each as a
    structured 'vulnerable-dependency' finding. Uses pip-audit / npm audit /
    govulncheck / cargo audit per ecosystem (each optional; missing auditors are
    skipped with a note). This is deeper than analyze_dependencies, which only dumps
    manifests."""
    if not _analyzer_enabled("dependency_audit"):
        return ("dependency_audit is disabled in config "
                "(analyzers.dependency_audit=false).")
    return _record_and_summarize(DependencyAuditAdapter().run(path))


@tool
def check_sanitizer(
    sanitizer: str,
    vuln_class: str,
    shell: bool = False,
    canonicalized: bool = False,
) -> str:
    """Check whether a control actually mitigates a vulnerability class BEFORE you
    treat a finding as sanitized — avoids false-sanitizer assumptions.

    `sanitizer` is the control seen in code (e.g. 'html.escape', 'shlex.quote',
    'urlparse', 'startswith', 'parameterized query', 'authentication'). `vuln_class`
    is the sink class (e.g. 'sql injection', 'command injection', 'xss', 'path
    traversal', 'ssrf', 'idor'). `shell`=True if the command is built for a shell
    (relevant to shlex.quote); `canonicalized`=True if a path was realpath'd BEFORE
    a prefix check (relevant to path traversal). Returns EFFECTIVE / NOT EFFECTIVE /
    UNKNOWN with a reason, flagging a false-sanitizer assumption when one applies."""
    return assess(
        sanitizer, vuln_class, shell=shell, canonicalized=canonicalized
    ).render()


def analyzer_tools() -> list:
    return [analyzer_scan, dependency_audit, check_sanitizer]
