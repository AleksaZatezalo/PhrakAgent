"""
Description: Static-analysis helpers used by the threat-modeling / dynamic-scan agents.
Author: Aleksa Zatezalo
Date Created: 07-29-2026
"""

from __future__ import annotations

from langchain_core.tools import tool

from .common import ANALYSIS_MAX, workspace

_DEP_FILES = [
    "requirements.txt",
    "requirements.in",
    "pyproject.toml",
    "Pipfile",
    "package.json",
    "yarn.lock",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "composer.json",
]

_FINGERPRINTS = {
    "Flask": ["flask"],
    "Django": ["django"],
    "FastAPI": ["fastapi"],
    "Express": ["express"],
    "React": ["react"],
    "Vue": ["vue"],
    "Spring": ["spring-boot", "springframework"],
    "Rails": ["rails"],
    "Laravel": ["laravel/framework"],
    "Go net/http": ["net/http"],
    "Docker": ["FROM "],
    "Kubernetes": ["apiVersion:"],
}


@tool
def analyze_dependencies(path: str = ".") -> str:
    """Find and dump dependency manifests (requirements.txt, package.json, go.mod,
    etc.) so their packages/versions can be checked for known-vulnerable libs."""
    root = (workspace() / path).resolve()
    found = []
    for name in _DEP_FILES:
        for f in root.rglob(name):
            if "node_modules" in f.parts or ".git" in f.parts:
                continue
            try:
                content = f.read_text(errors="replace")[:4000]
            except Exception:
                continue
            found.append(f"### {f.relative_to(root)}\n{content}")
    return (
        ("\n\n".join(found))[:ANALYSIS_MAX]
        if found
        else "No dependency manifests found."
    )


@tool
def fingerprint_stack(path: str = ".") -> str:
    """Identify frameworks/technologies used by the project from manifests and
    config files, to guide which threats/vuln classes matter."""
    deps = analyze_dependencies.invoke({"path": path}).lower()
    found = [
        name
        for name, markers in _FINGERPRINTS.items()
        if any(m.lower() in deps for m in markers)
    ]
    root = (workspace() / path).resolve()
    if (root / "Dockerfile").exists() or list(root.rglob("Dockerfile")):
        found.append("Docker")
    return "Detected stack: " + (", ".join(sorted(set(found))) or "unknown")


def analysis_tools() -> list:
    return [fingerprint_stack, analyze_dependencies]
