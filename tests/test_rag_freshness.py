"""
Description: /ask and rag_search refresh the index before answering (no stale hits).
Author: Aleksa Zatezalo
Date Created: 08-18-2026
"""

from __future__ import annotations

from appsec.rag import CodeIndex


class _LLM:
    """Captures the prompt it was asked to answer."""

    def __init__(self, reply="answer"):
        self.reply = reply
        self.prompts = []

    def invoke(self, prompt):
        self.prompts.append(prompt)

        class _R:
            content = self.reply

        return _R()


def _index(config, monkeypatch, *, count=5, hits=None, sync_raises=False):
    """A CodeIndex whose store access is stubbed; records sync() calls."""
    idx = CodeIndex(config)
    calls = {"sync": 0}

    def _sync(on_progress=None):
        calls["sync"] += 1
        if sync_raises:
            raise RuntimeError("embeddings backend down")
        idx._synced = True  # what the real sync() sets, and sync_once() reads
        return {"added": 1, "updated": 0, "removed": 0, "chunks": 3}

    monkeypatch.setattr(idx, "sync", _sync)
    monkeypatch.setattr(idx, "count", lambda: count)
    monkeypatch.setattr(
        idx,
        "search",
        lambda q, k=None: hits if hits is not None else [("a.py:1-5", "x")],
    )
    return idx, calls


# ------------------------------------------------------------------ ask()
def test_ask_syncs_even_when_index_is_already_populated(config, monkeypatch):
    """The regression: a non-empty index used to be answered from as-is, so
    edits made after the first index were invisible to /ask."""
    idx, calls = _index(config, monkeypatch, count=500)
    idx.ask(_LLM(), "how does auth work?")
    assert calls["sync"] == 1


def test_ask_still_builds_an_empty_index_when_sync_is_suppressed(config, monkeypatch):
    idx, calls = _index(config, monkeypatch, count=0)
    idx.ask(_LLM(), "q", sync=False)
    assert calls["sync"] == 1  # empty index must still be built


def test_ask_skips_redundant_sync_when_caller_already_synced(config, monkeypatch):
    idx, calls = _index(config, monkeypatch, count=500)
    idx.ask(_LLM(), "q", sync=False)
    assert calls["sync"] == 0


def test_ask_warns_instead_of_failing_when_sync_breaks(config, monkeypatch):
    idx, _ = _index(config, monkeypatch, count=500, sync_raises=True)
    out = idx.ask(_LLM("the answer"), "q")
    assert "Could not refresh the code index" in out
    assert "embeddings backend down" in out
    assert "the answer" in out  # still answers, just flagged


def test_ask_warns_about_staleness_even_with_no_hits(config, monkeypatch):
    idx, _ = _index(config, monkeypatch, count=500, hits=[], sync_raises=True)
    out = idx.ask(_LLM(), "q")
    assert "Could not refresh the code index" in out


# ------------------------------------------------------------- rag_search
def test_rag_search_syncs_once_not_once_per_call(config, runtime, monkeypatch):
    """The regression that hung a real run: syncing per tool call re-ran a
    multi-minute embed inside every call of every parallel agent."""
    from appsec.tools import rag_tool

    idx, calls = _index(config, monkeypatch, count=500)
    monkeypatch.setattr(rag_tool, "_get_index", lambda: idx)
    for _ in range(5):
        rag_tool.rag_search.func("jwt verification")
    assert calls["sync"] == 1


def test_rag_search_still_refreshes_a_stale_index_at_least_once(
    config, runtime, monkeypatch
):
    from appsec.tools import rag_tool

    idx, calls = _index(config, monkeypatch, count=500)
    monkeypatch.setattr(rag_tool, "_get_index", lambda: idx)
    rag_tool.rag_search.func("q")
    assert calls["sync"] == 1  # not skipped just because the index is non-empty


def test_parallel_agents_share_one_sync(config, runtime, monkeypatch):
    """The DAG runs agents in threads; they must not each embed the workspace."""
    import threading
    import time

    from appsec.tools import rag_tool

    idx = CodeIndex(config)
    calls = {"sync": 0}

    def _slow_sync(on_progress=None):
        calls["sync"] += 1
        time.sleep(0.2)  # stand in for a real embed
        idx._synced = True
        return {"added": 0, "updated": 0, "removed": 0, "chunks": 0}

    monkeypatch.setattr(idx, "sync", _slow_sync)
    monkeypatch.setattr(idx, "search", lambda q, k=None: [("a.py:1-5", "x")])
    monkeypatch.setattr(rag_tool, "_get_index", lambda: idx)

    barrier = threading.Barrier(4)

    def agent():
        barrier.wait()
        for _ in range(3):
            rag_tool.rag_search.func("q")

    threads = [threading.Thread(target=agent) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert calls["sync"] == 1  # 4 agents x 3 calls, one sync between them


def test_sync_once_is_a_noop_after_the_first(config, monkeypatch):
    idx, calls = _index(config, monkeypatch, count=500)
    assert idx.sync_once()["chunks"] == 3
    assert idx.sync_once() == {"added": 0, "updated": 0, "removed": 0, "chunks": 0}
    assert calls["sync"] == 1


# --------------------------------------------------------- sync convergence
def test_empty_files_are_skipped_so_sync_converges(config, workspace, monkeypatch):
    """An empty file chunks to nothing, so _add_file stores no metadata for it.

    It was therefore never recorded as indexed and every later sync counted it
    as 'added' again — forever. On a Django-style tree of empty __init__.py
    files that means sync never reaches a clean no-op.
    """
    (workspace / "__init__.py").write_text("")
    (workspace / "pkg").mkdir()
    (workspace / "pkg" / "__init__.py").write_text("")

    idx = CodeIndex(config)
    rels = {idx._rel(p) for p in idx._iter_files()}
    assert "vuln_app.py" in rels  # real files still indexed
    assert "__init__.py" not in rels
    assert "pkg/__init__.py" not in rels


def test_sync_reaches_a_true_noop(config, workspace, monkeypatch):
    (workspace / "__init__.py").write_text("")
    idx = CodeIndex(config)
    added: list[str] = []
    monkeypatch.setattr(idx, "_indexed_mtimes", lambda: getattr(idx, "_fake", {}))
    monkeypatch.setattr(idx, "_delete_path", lambda rel: None)

    def _add(fp, rel, mtime):
        added.append(rel)
        idx._fake = {**getattr(idx, "_fake", {}), rel: mtime}
        return 2

    monkeypatch.setattr(idx, "_add_file", _add)

    first = idx.sync()
    assert first["added"] > 0
    second = idx.sync()
    assert second == {"added": 0, "updated": 0, "removed": 0, "chunks": 0}


def test_sync_reports_progress_for_a_large_index(config, workspace, monkeypatch):
    for i in range(5):
        (workspace / f"mod{i}.py").write_text(f"x = {i}\n")
    idx = CodeIndex(config)
    monkeypatch.setattr(idx, "_indexed_mtimes", lambda: {})
    monkeypatch.setattr(idx, "_add_file", lambda fp, rel, mtime: 1)
    seen = []
    idx.sync(on_progress=lambda done, total, rel: seen.append((done, total)))
    assert seen  # callback fired
    assert seen[-1][0] == seen[-1][1]  # finishes at done == total


# ------------------------------------------------------------ phrak index
def test_stats_reports_pending_work_without_changing_anything(
    config, workspace, monkeypatch
):
    idx = CodeIndex(config)
    monkeypatch.setattr(idx, "count", lambda: 0)
    monkeypatch.setattr(idx, "_indexed_mtimes", lambda: {})
    s = idx.stats()
    assert s["workspace_files"] > 0
    assert s["new"] == s["workspace_files"]
    assert s["pending"] == s["new"]
    assert s["changed"] == 0 and s["orphaned"] == 0


def test_stats_counts_changed_and_orphaned(config, workspace, monkeypatch):
    idx = CodeIndex(config)
    monkeypatch.setattr(idx, "count", lambda: 10)
    # vuln_app.py indexed at a bogus mtime -> changed; ghost.py gone -> orphaned
    monkeypatch.setattr(
        idx,
        "_indexed_mtimes",
        lambda: {"vuln_app.py": 1.0, "requirements.txt": 1.0, "ghost.py": 1.0},
    )
    s = idx.stats()
    assert s["changed"] == 2  # both indexed files have a different real mtime
    assert s["orphaned"] == 1  # ghost.py is no longer on disk
    assert s["pending"] == s["new"] + s["changed"] + s["orphaned"]


def test_stats_is_clean_when_the_index_matches_disk(config, workspace, monkeypatch):
    idx = CodeIndex(config)
    monkeypatch.setattr(idx, "count", lambda: 4)
    real = {idx._rel(p): p.stat().st_mtime for p in idx._iter_files()}
    monkeypatch.setattr(idx, "_indexed_mtimes", lambda: real)
    s = idx.stats()
    assert s["pending"] == 0
    assert s["new"] == 0 and s["changed"] == 0 and s["orphaned"] == 0


def test_index_subcommand_parses():
    from appsec.cli import build_parser

    args = build_parser().parse_args(["index"])
    assert args.cmd == "index"
    assert args.rebuild is False and args.stats is False
    assert build_parser().parse_args(["index", "--rebuild"]).rebuild is True
    assert build_parser().parse_args(["index", "--stats"]).stats is True


def test_reindex_passes_progress_through(config, workspace, monkeypatch):
    idx = CodeIndex(config)
    seen = []
    monkeypatch.setattr(idx, "_indexed_mtimes", lambda: {})
    monkeypatch.setattr(idx, "_add_file", lambda fp, rel, mtime: 1)
    monkeypatch.setattr(idx, "_delete_path", lambda rel: None)

    class _Coll:
        def get(self, *a, **k):
            return {"ids": []}

    monkeypatch.setattr(type(idx), "store", property(lambda self: _Coll()))
    idx.reindex(on_progress=lambda d, t, r: seen.append(d))
    assert seen == list(range(1, len(seen) + 1))


def test_rag_search_flags_a_failed_sync(config, runtime, monkeypatch):
    from appsec.tools import rag_tool

    idx, _ = _index(config, monkeypatch, count=500, sync_raises=True)
    monkeypatch.setattr(rag_tool, "_get_index", lambda: idx)
    out = rag_tool.rag_search.func("jwt verification")
    assert "index not refreshed" in out
    assert "a.py:1-5" in out or "x" in out  # results still returned
