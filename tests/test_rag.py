"""
Description: Codebase RAG index: file discovery + chunking (pure logic, no embeddings).
Author: Aleksa Zatezalo
Date Created: 07-31-2026
"""

from __future__ import annotations

from appsec.rag import CodeIndex


def test_iter_files_filters_by_ext_and_excluded_dirs(config, workspace):
    idx = CodeIndex(config)
    rels = {idx._rel(p) for p in idx._iter_files()}
    assert "vuln_app.py" in rels  # .py is indexed
    assert "requirements.txt" in rels  # .txt is indexed

    # files under an excluded dir (or a hidden dir) are skipped
    (workspace / "venv").mkdir()
    (workspace / "venv" / "lib.py").write_text("x = 1\n")
    (workspace / ".hidden").mkdir()
    (workspace / ".hidden" / "secret.py").write_text("y = 2\n")
    # a non-source extension is skipped
    (workspace / "photo.png").write_bytes(b"\x89PNG")

    rels = {idx._rel(p) for p in idx._iter_files()}
    assert "venv/lib.py" not in rels
    assert ".hidden/secret.py" not in rels
    assert "photo.png" not in rels


def test_chunk_windows_with_overlap(config):
    idx = CodeIndex(config)
    idx.rag.chunk_lines = 3
    idx.rag.chunk_overlap = 1
    text = "\n".join(str(i) for i in range(1, 8))  # 7 lines
    chunks = idx._chunk(text)
    # step = size - overlap = 2 -> windows start at lines 1,3,5,7 (1-indexed)
    assert [c[0] for c in chunks] == [1, 3, 5, 7]
    assert chunks[0][1] == 3  # end line inclusive
    assert chunks[0][2].splitlines() == ["1", "2", "3"]


# ------------------------------------------------------------ single-file index
def _stub_writes(idx, monkeypatch, chunks=2):
    """Record _delete_path/_add_file calls instead of touching an embedding model."""
    seen: dict = {"deleted": [], "added": []}

    def _delete(rel):
        seen["deleted"].append(rel)

    def _add(fp, rel, mtime):
        seen["added"].append((rel, mtime))
        return chunks

    monkeypatch.setattr(idx, "_delete_path", _delete)
    monkeypatch.setattr(idx, "_add_file", _add)
    return seen


def test_index_file_keys_an_absolute_path_off_the_workspace(
    config, workspace, monkeypatch
):
    """A saved report arrives as an absolute path but must land under the same
    workspace-relative key ``sync`` would use, or /ask would index it twice."""
    idx = CodeIndex(config)
    seen = _stub_writes(idx, monkeypatch)
    reports = workspace / ".phrack" / "reports"
    reports.mkdir(parents=True)
    report = reports / "report-20260731-120000-code_review.md"
    report.write_text("# code_review Report\n\nSQL injection at vuln_app.py:11\n")

    assert idx.index_file(report) == 2
    assert (
        seen["added"][0][0] == ".phrack/reports/report-20260731-120000-code_review.md"
    )
    # stale chunks for a re-written report are dropped first
    assert seen["deleted"] == [".phrack/reports/report-20260731-120000-code_review.md"]


def test_index_file_ignores_a_missing_path(config, monkeypatch):
    idx = CodeIndex(config)
    seen = _stub_writes(idx, monkeypatch)
    assert idx.index_file(config.reports_dir() / "nope.md") == 0
    assert seen["added"] == [] and seen["deleted"] == []


def test_chunk_empty_text():
    from appsec.config import Config

    assert CodeIndex(Config())._chunk("") == []
