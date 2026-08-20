"""
Description: Deterministic extraction of structured findings / test cases from a
model's PROSE report — a fallback for when the model never called
report_finding / report_test_case itself.

Author: Aleksa Zatezalo
Date Created: 08-20-2026

Small local models (e.g. qwen2.5-coder:7b) reliably WRITE a structured report
but unreliably CALL the capture tools, so /findings and /testcases end up empty
even though the prose is full of issues. Rather than depend on the model to
emit tool calls, this module parses the report text it already produced into
:class:`SecurityFinding` / :class:`SecurityTestCase` objects.

It is intentionally deterministic (no LLM, no tokens, unit-testable) and
conservative: a block is only recorded when it carries the attributes that
define a real finding/test case, so remediation-roadmap items and bare
section headers are skipped rather than recorded as empty findings.
"""

from __future__ import annotations

import re

from .models.findings import (
    FindingEvidence,
    SecurityFinding,
    validate_against_workspace,
    validate_finding,
)
from .models.testcases import SecurityTestCase, validate_test_case

# ------------------------------------------------------------------ tokenizing
# An attribute, once any leading list marker is stripped: "Severity: High".
# The key is letters/spaces/slashes so multi-word keys ("Expected Result",
# "Linked Finding/Threat") match; the value is the rest of the line.
_ATTR = re.compile(r"^([A-Za-z][A-Za-z /_]{1,38}?)\s*[:=]\s*(.*)$")

# A leading list marker: "1 ", "1. ", "2) ", "- ", "* ", "• ".
_MARKER = re.compile(r"^(?:(\d+)[.)]?|[-*•])\s+(.*)$")


def _deemph(s: str) -> str:
    """Strip markdown emphasis so `**Key:**`, `__Key__`, and `` `Key` `` are seen
    as plain ``Key``. Models routinely bold attribute labels
    (``- **Severity:** High``); without this, every such line fails key matching
    and the whole finding/test-case block is silently dropped."""
    s = s.replace("**", "").replace("__", "").replace("`", "")
    return s

# Severity words we accept, mapped onto the finding vocabulary.
_SEV = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}

# Canonical attribute names ← the many labels a model uses for each.
_KEYS = {
    "title": "title",
    "test case": "title",
    "name": "title",
    "severity": "severity",
    "risk": "severity",
    "priority": "severity",
    "category": "category",
    "type": "category",
    "class": "category",
    "file": "file",
    "location": "file",
    "component": "file",
    "affected file": "file",
    "affected files": "file",
    "path": "file",
    "line": "line",
    "lines": "line",
    "description": "description",
    "desc": "description",
    "impact": "description",
    "summary": "description",
    "details": "description",
    "cwe": "cwe",
    "owasp": "owasp",
    "recommendation": "recommendation",
    "remediation": "recommendation",
    "fix": "recommendation",
    "mitigation": "recommendation",
    "disproof": "disproof",
    "confidence": "confidence",
    "steps": "steps",
    "steps to reproduce": "steps",
    "reproduction": "steps",
    "repro": "steps",
    "expected result": "expected",
    "expected results": "expected",
    "expected": "expected",
    "expected outcome": "expected",
    "target": "target",
    "objective": "objective",
    "goal": "objective",
    "preconditions": "preconditions",
    "precondition": "preconditions",
    "prerequisites": "preconditions",
    "finding id": "link",
    "linked finding": "link",
    "linked finding/threat": "link",
    "linked finding / threat": "link",
    "threat": "link",
    "threat ref": "link",
    "verifies": "link",
}

# Attributes whose value is a numbered list that may spill onto following lines.
_MULTILINE = {"steps"}


def _clean_title(text: str) -> str:
    """Strip markdown emphasis, a trailing `FND-...` id, and a parenthetical
    severity tag from a candidate title line."""
    t = text.strip()
    t = re.sub(r"`[^`]*`", "", t)  # drop inline-code ids like `FND-ab12cd34ef`
    t = t.strip(" *#_").strip()
    t = re.sub(r"^\d+[.)]\s+", "", t)  # a leading list number that rode along
    t = re.sub(r"\s*\((?:critical|high|medium|low|info)\)\s*$", "", t, flags=re.I)
    return t.strip()


def _header_title(line: str) -> str | None:
    """Return the title if ``line`` is a markdown/``Finding N``/``**bold**`` header."""
    s = line.strip()
    for pat in (
        r"^#{1,6}\s+(.*)$",  # markdown header
        r"^Finding\s+\d+\s*[:.\-]?\s*(.*)$",  # "Finding 1: ..."
        r"^\*\*(.+?)\*\*\s*$",  # "**Title**"
    ):
        m = re.match(pat, s, re.I)
        if m and _clean_title(m.group(1)):
            return _clean_title(m.group(1))
    return None


def _canon_sev(value: str, default: str = "medium") -> str:
    v = (value or "").strip().lower()
    for word, sev in _SEV.items():
        if re.search(rf"\b{word}\b", v):
            return sev
    return default


def _split_steps(raw: str) -> list[str]:
    parts: list[str] = []
    for chunk in re.split(r"\n|\\n|\s\|\s|;", raw or ""):
        s = re.sub(r"^\s*(?:\d+[.)]|[-*•])\s*", "", chunk).strip()
        if s:
            parts.append(s)
    return parts


def _parse_location(file_val: str, line_val: str) -> tuple[str, int | None]:
    """Pull a workspace path and (optional) line out of the model's freeform
    "File"/"Location"/"Component"/"Target" text."""
    path = ""
    m = re.search(r"([\w./\-]+\.[A-Za-z0-9_]+)", file_val or "")
    if m:
        path = m.group(1)
    line: int | None = None
    # A bare "Line: 12" value is just the number.
    if line_val and line_val.strip().isdigit():
        line = int(line_val.strip())
    if line is None:
        for src in (line_val, file_val):
            if not src:
                continue
            m = re.search(r"[Ll]ine\s*(\d+)|:(\d+)\b", src)
            if m:
                line = int(m.group(1) or m.group(2))
                break
    return path, line


def _cwes(*vals: str) -> list[str]:
    found: list[str] = []
    for v in vals:
        for m in re.findall(r"CWE[-\s]?(\d+)", v or "", re.I):
            tag = f"CWE-{m}"
            if tag not in found:
                found.append(tag)
    return found


def _finding_id(link: str) -> str:
    m = re.search(r"\bFND-[0-9a-f]{6,}\b", link or "", re.I)
    return m.group(0) if m else ""


# ------------------------------------------------------------------ block parse
class _Record(dict):
    def __init__(self) -> None:
        super().__init__()
        self["steps"] = []


def _attr(content: str) -> tuple[str, str] | None:
    """Return (canonical_key, value) if ``content`` is a known ``Key: value``."""
    m = _ATTR.match(content)
    if not m:
        return None
    key = re.sub(r"\s+", " ", m.group(1).strip().lower())
    canon = _KEYS.get(key)
    return (canon, m.group(2).strip()) if canon else None


def _records(text: str) -> list[_Record]:
    """Segment a report into attribute-bearing records.

    A record starts at a header, a numbered list item, or a ``Title:`` attribute,
    and accumulates the ``key: value`` attributes beneath it (bulleted or not). A
    ``Steps:`` attribute pulls in the numbered sub-lines that follow it, until the
    next attribute or record boundary.
    """
    records: list[_Record] = []
    cur: _Record | None = None
    collecting_steps = False

    def flush() -> None:
        nonlocal cur, collecting_steps
        if cur is not None and _has_content(cur):
            records.append(cur)
        cur = None
        collecting_steps = False

    def ensure() -> _Record:
        nonlocal cur
        if cur is None:
            cur = _Record()
        return cur

    def apply_attr(canon: str, val: str) -> None:
        nonlocal collecting_steps
        if canon == "title":
            if cur is not None and cur.get("title") and _has_content(cur):
                flush()
            ensure()["title"] = _clean_title(val)
            return
        rec = ensure()
        if canon in _MULTILINE:
            collecting_steps = True
            if val:
                rec["steps"].extend(_split_steps(val))
            return
        collecting_steps = False
        rec[canon] = val

    for raw in (text or "").splitlines():
        if not raw.strip():
            collecting_steps = False
            continue
        stripped = _deemph(raw.strip())

        # A markdown / "Finding N" / **bold** header always starts a record.
        header = _header_title(stripped)
        if header is not None:
            flush()
            ensure()["title"] = header
            continue

        mk = _MARKER.match(stripped)
        content = mk.group(2).strip() if mk else stripped
        numbered = bool(mk and mk.group(1))  # a "1." item, not a "-" bullet
        attr = _attr(content)

        if collecting_steps and cur is not None:
            # Inside a Steps: list. A known attribute (incl. the next record's
            # "Title:") ends the list; anything else is another step line.
            if attr is None:
                cur["steps"].append(content)
                continue
            collecting_steps = False

        if numbered and attr is None:
            # "1 SQL Injection in Transfer Form" — a new numbered record.
            flush()
            ensure()["title"] = _clean_title(content)
            continue

        if attr is not None:
            # "1 Title: ..." / "• Severity: High" / "File: x.py"
            if numbered and attr[0] == "title":
                flush()
            apply_attr(*attr)
            continue
        # Unrecognized prose line — ignore (don't corrupt the current record).

    flush()
    return records


def _has_content(rec: _Record) -> bool:
    """A record worth keeping has a title and at least one substantive attribute."""
    if not rec.get("title"):
        return False
    keys = set(rec) - {"title"}
    if rec.get("steps"):
        return True
    return bool(keys & {"severity", "file", "description", "cwe", "expected", "target"})


def _is_test_case(rec: _Record) -> bool:
    return bool(rec.get("steps") or rec.get("expected") or rec.get("target"))


# ---------------------------------------------------------------- public API
def findings_from_report(text: str, source_agent: str = "", workspace=None) -> list:
    """Parse confirmed-style findings out of a prose report.

    ``workspace`` (a path) grounds evidence: a finding whose file/line can't be
    located is still recorded, but downgraded to ``unconfirmed`` — same policy as
    the report_finding tool, so a hand-written and a parsed finding behave alike.
    """
    out: list[SecurityFinding] = []
    for rec in _records(text):
        if _is_test_case(rec):
            continue
        title = rec.get("title", "")
        desc = rec.get("description", "")
        path, line = _parse_location(rec.get("file", ""), rec.get("line", ""))
        try:
            conf = float(re.search(r"[\d.]+", rec.get("confidence", "")).group(0))
        except (AttributeError, ValueError):
            conf = 0.5
        conf = min(max(conf, 0.0), 1.0)
        evidence = [
            FindingEvidence(
                path=path,
                start_line=line,
                end_line=line,
                reason=(desc or title)[:200],
                evidence_type="source_reference" if path else "note",
            )
        ]
        finding = SecurityFinding(
            title=title,
            category=rec.get("category", "") or rec.get("owasp", ""),
            severity=_canon_sev(rec.get("severity", "")),
            description=desc,
            recommendation=rec.get("recommendation", ""),
            disproof=rec.get("disproof", ""),
            confidence=conf,
            status="new",
            cwe_ids=_cwes(rec.get("cwe", ""), rec.get("category", ""), title),
            affected_files=[path] if path else [],
            evidence=evidence,
            source_agent=source_agent,
            source_tools=["extracted_from_report"],
        ).ensure_identity()

        if validate_finding(finding):
            continue  # structurally unusable — skip rather than store junk
        if not path:
            # Nothing to ground against; record but mark it needs verification.
            finding.status = "unconfirmed"
            finding.confidence = min(finding.confidence, 0.4)
        elif workspace is not None and validate_against_workspace(finding, workspace):
            finding.status = "unconfirmed"
            finding.confidence = min(finding.confidence, 0.4)
        finding.ensure_identity()
        out.append(finding)
    return out


def test_cases_from_report(text: str, source_agent: str = "") -> list:
    """Parse authored test cases out of a prose report.

    Only records that carry the fields a trackable test needs (title, target,
    steps, expected result) survive — a bare "Verify X (High)" line with no steps
    is skipped rather than stored as an empty, un-runnable checklist item.
    """
    out: list[SecurityTestCase] = []
    for rec in _records(text):
        if not _is_test_case(rec):
            continue
        path, line = _parse_location(rec.get("target", "") or rec.get("file", ""), "")
        target = rec.get("target", "") or rec.get("file", "")
        link = rec.get("link", "")
        case = SecurityTestCase(
            title=rec.get("title", ""),
            objective=rec.get("objective", ""),
            target=target,
            preconditions=rec.get("preconditions", ""),
            steps=rec.get("steps", []),
            expected_result=rec.get("expected", ""),
            severity=_canon_sev(rec.get("severity", "")),
            finding_id=_finding_id(link),
            threat_ref="" if _finding_id(link) else link.strip(),
            status="new",
            source_agent=source_agent,
        ).ensure_identity()
        if validate_test_case(case):
            continue  # missing a required field — can't track it, skip
        out.append(case)
    return out
