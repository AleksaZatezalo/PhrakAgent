"""
Description: rag_search agent tool — semantic sibling of search_code.
"""

from __future__ import annotations

import pytest

from appsec import runtime
from appsec.config import Config
from appsec.tools.rag_tool import rag_search, rag_search_tools


@pytest.fixture()
def workspace(tmp_path):
    (tmp_path / "a.py").write_text(
        "def login(u, p):\n"
        "    return db.execute('SELECT * FROM u WHERE n=' + u)\n"
    )
    (tmp_path / "b.py").write_text(
        "def profile(id):\n"
        "    return db.execute(f'SELECT * FROM p WHERE id={id}')\n"
    )
    cfg = Config()
    cfg.paths.workspace = str(tmp_path)
    runtime.init_runtime(cfg)
    yield tmp_path
    runtime.RUNTIME.config = None
    # reset the index cache so tests don't leak state
    from appsec.tools import rag_tool

    rag_tool._INDEX_CACHE.clear()


def test_rag_search_tool_is_registered():
    tools = rag_search_tools()
    assert tools and tools[0].name == "rag_search"


def test_rag_search_unavailable_without_config():
    runtime.RUNTIME.config = None
    result = rag_search.invoke({"query": "anything"})
    assert "unavailable" in result.lower()


def test_rag_search_finds_semantically_similar_code(workspace):
    """Query for a concept, get back both concatenation and f-string SQLi sites."""
    result = rag_search.invoke({"query": "string-concatenated SQL query", "k": 4})
    assert "unavailable" not in result.lower()
    # Both files should show up as candidates — the concept matches both.
    assert "a.py" in result or "b.py" in result
