"""Dependency-audit adapter — known-vulnerable dependency versions.

Runs the ecosystem's native auditor over the manifests found under the target and
normalizes each advisory into a ``vulnerable-dependency`` :class:`SecurityFinding`
whose evidence points at the manifest. Supported:

* **pip-audit** — Python (`requirements*.txt`, `pyproject.toml`, `Pipfile`)
* **npm audit** — Node (`package.json`)
* **govulncheck** — Go (`go.mod`)
* **cargo audit** — Rust (`Cargo.toml` / `Cargo.lock`)

Every auditor is optional: if its binary is absent the ecosystem is skipped with a
note (the run never fails). Auditors query an advisory database, which may require
network access — that is the auditor's behaviour, surfaced honestly to the caller.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from ..models.findings import FindingEvidence, SecurityFinding
from ..tools.common import excluded_dirs, run_cli, workspace
from .base import AnalyzerResult, extract_cwe

AUDIT_TIMEOUT = 300
_MAX_PER_ECOSYSTEM = 100

# advisory severity strings -> PHRAK severities
_SEVERITY = {
    "critical": "critical", "high": "high", "moderate": "medium",
    "medium": "medium", "low": "low", "info": "info", "informational": "info",
}


def _severity(raw: object) -> str:
    return _SEVERITY.get(str(raw or "").strip().lower(), "medium")


def _dep_finding(
    package: str, version: str, advisory_id: str, summary: str, severity: str,
    fixed: str, manifest: str, tool: str, refs: list[str], cwe_text: object = "",
) -> SecurityFinding:
    ver = f" {version}" if version else ""
    rec = f"Upgrade {package} to {fixed}." if fixed else \
        f"Upgrade {package} to a non-vulnerable version (see advisory)."
    return SecurityFinding(
        title=f"Vulnerable dependency: {package}{ver} ({advisory_id})",
        description=summary or f"{package}{ver} is affected by {advisory_id}.",
        category="vulnerable-dependency",
        severity=_severity(severity),
        confidence=0.75,          # a version match against an advisory DB is factual
        status="new",
        cwe_ids=extract_cwe(cwe_text, summary, advisory_id),
        affected_symbols=[package],
        affected_files=[manifest] if manifest else [],
        references=[r for r in refs if r],
        recommendation=rec,
        evidence=[FindingEvidence(
            path=manifest,
            reason=f"{package}{ver}: {advisory_id}",
            evidence_type="analyzer_hit",
        )],
        source_tools=[tool],
        source_agent="dependency_audit",
    ).ensure_identity()


# --------------------------------------------------------------- parsers
def parse_pip_audit(data: object, manifest: str) -> list[SecurityFinding]:
    """pip-audit ``--format json`` → findings. Handles both the ``{dependencies:[]}``
    and bare-list shapes."""
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    out: list[SecurityFinding] = []
    for dep in deps or []:
        name = dep.get("name", "")
        version = dep.get("version", "")
        for v in dep.get("vulns", []) or []:
            vid = v.get("id", "") or (v.get("aliases", [""]) or [""])[0]
            fixed = ", ".join(v.get("fix_versions", []) or [])
            out.append(_dep_finding(
                name, version, vid, v.get("description", ""),
                v.get("severity", ""), fixed, manifest, "pip-audit",
                v.get("aliases", []) or [], v.get("description", ""),
            ))
    return out[:_MAX_PER_ECOSYSTEM]


def parse_npm_audit(data: object, manifest: str) -> list[SecurityFinding]:
    """npm audit ``--json`` (v7+) → findings from the ``vulnerabilities`` map."""
    if not isinstance(data, dict):
        return []
    out: list[SecurityFinding] = []
    for name, v in (data.get("vulnerabilities", {}) or {}).items():
        severity = v.get("severity", "")
        title, url, cwe, vid = "", "", [], ""
        for via in v.get("via", []) or []:
            if isinstance(via, dict):
                title = via.get("title", title)
                url = via.get("url", url)
                cwe = via.get("cwe", cwe) or cwe
                vid = via.get("source", vid) or vid
        fixed = ""
        fa = v.get("fixAvailable")
        if isinstance(fa, dict):
            fixed = f"{fa.get('name', name)}@{fa.get('version', '')}"
        elif fa is True:
            fixed = "a fixed version (`npm audit fix`)"
        out.append(_dep_finding(
            name, v.get("range", ""), title or f"GHSA/{vid or 'advisory'}",
            title, severity, fixed, manifest, "npm-audit",
            [url] if url else [], cwe,
        ))
    return out[:_MAX_PER_ECOSYSTEM]


def parse_govulncheck(text: str, manifest: str) -> list[SecurityFinding]:
    """govulncheck ``-json`` → findings. The output is a stream of concatenated
    JSON objects; collect OSV definitions and emit one finding per OSV that has a
    call-stack ``finding`` (i.e. actually reachable)."""
    osvs: dict[str, dict] = {}
    reachable: set[str] = set()
    dec = json.JSONDecoder()
    idx, n = 0, len(text)
    while idx < n:
        while idx < n and text[idx] in " \t\r\n":
            idx += 1
        if idx >= n:
            break
        try:
            obj, end = dec.raw_decode(text, idx)
        except json.JSONDecodeError:
            break
        idx = end
        if not isinstance(obj, dict):
            continue
        if "osv" in obj and isinstance(obj["osv"], dict):
            oid = obj["osv"].get("id", "")
            if oid:
                osvs[oid] = obj["osv"]
        if "finding" in obj and isinstance(obj["finding"], dict):
            oid = obj["finding"].get("osv", "")
            trace = obj["finding"].get("trace") or []
            # a frame with a "function" means the vuln is on a real call path
            if oid and any(isinstance(f, dict) and f.get("function") for f in trace):
                reachable.add(oid)
    out: list[SecurityFinding] = []
    for oid in reachable or osvs.keys():
        osv = osvs.get(oid, {})
        summary = osv.get("summary") or osv.get("details", "")[:200]
        aff = (osv.get("affected") or [{}])[0]
        pkg = aff.get("package", {}).get("name", "")
        refs = [r.get("url", "") for r in osv.get("references", []) or []]
        out.append(_dep_finding(
            pkg or "go module", "", oid, summary, "", "", manifest,
            "govulncheck", refs, summary,
        ))
    return out[:_MAX_PER_ECOSYSTEM]


def parse_cargo_audit(data: object, manifest: str) -> list[SecurityFinding]:
    """cargo audit ``--json`` → findings from ``vulnerabilities.list``."""
    if not isinstance(data, dict):
        return []
    lst = (data.get("vulnerabilities", {}) or {}).get("list", []) or []
    out: list[SecurityFinding] = []
    for item in lst:
        adv = item.get("advisory", {}) or {}
        pkg = item.get("package", {}) or {}
        patched = ", ".join((item.get("versions", {}) or {}).get("patched", []) or [])
        out.append(_dep_finding(
            pkg.get("name", ""), pkg.get("version", ""), adv.get("id", ""),
            adv.get("title", "") or adv.get("description", ""), "", patched,
            manifest, "cargo-audit", [adv.get("url", "")], adv.get("categories", ""),
        ))
    return out[:_MAX_PER_ECOSYSTEM]


# --------------------------------------------------------------- adapter
_PY_MANIFESTS = ("requirements.txt", "requirements.in", "pyproject.toml", "Pipfile")


class DependencyAuditAdapter:
    """Runs each ecosystem's auditor over the manifests present under the target."""

    name = "dependency_audit"

    _AUDITORS = ("pip-audit", "npm", "govulncheck", "cargo")

    def is_available(self) -> bool:
        return any(shutil.which(b) for b in self._AUDITORS)

    def supports(self, path: str = ".") -> bool:
        return bool(self._manifests(path))

    def _manifests(self, path: str) -> dict[str, list[Path]]:
        root = (workspace() / path).resolve()
        skip = set(excluded_dirs()) | {"node_modules", "vendor", ".git"}
        found: dict[str, list[Path]] = {}

        def _add(key: str, p: Path) -> None:
            found.setdefault(key, []).append(p)

        if root.is_file():
            candidates = [root]
        else:
            candidates = [
                p for p in root.rglob("*")
                if p.is_file() and not (set(p.parts) & skip)
            ]
        for p in candidates:
            nm = p.name
            if nm in _PY_MANIFESTS:
                _add("python", p)
            elif nm == "package.json":
                _add("node", p)
            elif nm == "go.mod":
                _add("go", p)
            elif nm in ("Cargo.toml", "Cargo.lock"):
                _add("rust", p)
        return found

    def run(self, path: str = ".") -> AnalyzerResult:
        manifests = self._manifests(path)
        if not manifests:
            return AnalyzerResult(
                tool=self.name, summary="No dependency manifests found.",
            )
        root = workspace()
        findings: list[SecurityFinding] = []
        notes: list[str] = []
        for eco, files in manifests.items():
            fs, note = self._audit_ecosystem(eco, files, root)
            findings += fs
            if note:
                notes.append(note)
        summary = (
            f"{len(findings)} vulnerable-dependency finding(s)."
            if findings else "No known-vulnerable dependencies found."
        )
        if notes:
            summary += "\n" + "\n".join(f"- {n}" for n in notes)
        return AnalyzerResult(
            tool=self.name, findings=findings, summary=summary,
            available=self.is_available(),
        )

    def _audit_ecosystem(self, eco: str, files: list[Path], root: Path):
        rel = lambda p: str(p.resolve().relative_to(root)) if root in p.resolve().parents \
            or p.resolve() == root else str(p)  # noqa: E731
        if eco == "python":
            return self._audit_python(files, rel)
        if eco == "node":
            return self._audit_json_cmd(
                "npm", ["npm", "audit", "--json"], files[0], rel, parse_npm_audit)
        if eco == "go":
            return self._audit_go(files[0], rel)
        if eco == "rust":
            manifest = next((f for f in files if f.name == "Cargo.toml"), files[0])
            return self._audit_json_cmd(
                "cargo", ["cargo", "audit", "--json"], manifest, rel, parse_cargo_audit)
        return [], None

    def _audit_python(self, files, rel):
        if not shutil.which("pip-audit"):
            return [], "pip-audit not installed — Python deps not audited."
        reqs = [f for f in files if f.name in ("requirements.txt", "requirements.in")]
        findings: list[SecurityFinding] = []
        targets = reqs or files[:1]
        for f in targets:
            cmd = ["pip-audit", "--format", "json", "--progress-spinner", "off"]
            if f.name in ("requirements.txt", "requirements.in"):
                cmd += ["--requirement", str(f)]
                res = run_cli(cmd, timeout=AUDIT_TIMEOUT)
            else:
                res = run_cli(cmd, timeout=AUDIT_TIMEOUT, cwd=f.parent)
            data = _loads(res.stdout)
            if data is None:
                return findings, f"pip-audit produced no JSON: {res.output[:200]}"
            findings += parse_pip_audit(data, rel(f))
        return findings, None

    def _audit_json_cmd(self, binary, cmd, manifest, rel, parser):
        if not shutil.which(binary):
            return [], f"{binary} not installed — {manifest.name} not audited."
        res = run_cli(cmd, timeout=AUDIT_TIMEOUT, cwd=manifest.parent)
        data = _loads(res.stdout)
        if data is None:
            return [], f"{binary} produced no JSON: {res.output[:200]}"
        return parser(data, rel(manifest)), None

    def _audit_go(self, manifest, rel):
        if not shutil.which("govulncheck"):
            return [], "govulncheck not installed — Go deps not audited."
        res = run_cli(["govulncheck", "-json", "./..."],
                      timeout=AUDIT_TIMEOUT, cwd=manifest.parent)
        if not res.stdout.strip():
            return [], f"govulncheck produced no output: {res.output[:200]}"
        return parse_govulncheck(res.stdout, rel(manifest)), None


def _loads(text: str) -> object | None:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
