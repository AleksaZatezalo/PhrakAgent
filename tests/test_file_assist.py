"""File-assist: workspace overview + rescuing a model that asks for pasted code."""

from __future__ import annotations

from appsec import file_assist
from appsec.tools.filesystem import read_file


def test_find_tool():
    assert file_assist.find_tool([read_file], "read_file") is read_file
    assert file_assist.find_tool([read_file], "missing") is None


def test_workspace_files_lists_source(runtime):
    files = file_assist.workspace_files()
    assert "vuln_app.py" in files


def test_workspace_overview_present_with_read_tool(runtime):
    overview = file_assist.workspace_overview([read_file])
    assert "vuln_app.py" in overview


def test_workspace_overview_empty_without_read_tool(runtime):
    assert file_assist.workspace_overview([]) == ""


def test_rescue_reads_real_file_when_model_hallucinates(runtime):
    # Model asked for a nonexistent app.py; it should fall back to vuln_app.py.
    msg = file_assist.maybe_satisfy_file_request(
        [read_file], "Please provide the contents of app.py."
    )
    assert msg is not None
    assert "vuln_app.py" in msg and "SELECT" in msg


def test_rescue_ignores_non_requests(runtime):
    answer = "Here is the final report. Severity: High. Remediation: sanitize."
    assert file_assist.maybe_satisfy_file_request([read_file], answer) is None
