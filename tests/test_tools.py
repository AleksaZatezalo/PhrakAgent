"""
Description: Tool behaviour + safety guards (filesystem, analysis).
Author: Aleksa Zatezalo
Date Created: 07-31-2026
"""

from __future__ import annotations

from appsec.tools.analysis import (
    analyze_dependencies,
    fingerprint_stack,
)
from appsec.tools.filesystem import list_dir, read_file, search_code


# ------------------------------------------------------------- filesystem
def test_read_file_reads_within_workspace(runtime):
    out = read_file.invoke({"path": "vuln_app.py"})
    assert "SELECT" in out


def test_read_file_rejects_escape(runtime):
    out = read_file.invoke({"path": "../../../etc/passwd"})
    assert out.startswith("Path '")


def test_read_file_missing(runtime):
    assert read_file.invoke({"path": "nope.py"}).startswith("Not a file")


def test_list_dir(runtime):
    assert "vuln_app.py" in list_dir.invoke({"path": "."})


def test_search_code(runtime):
    out = search_code.invoke({"pattern": "app.route", "path": "."})
    assert "vuln_app.py" in out


# --------------------------------------------------------------- analysis
def test_fingerprint_detects_flask(runtime):
    assert "Flask" in fingerprint_stack.invoke({"path": "."})


def test_analyze_dependencies(runtime):
    assert "flask" in analyze_dependencies.invoke({"path": "."}).lower()
