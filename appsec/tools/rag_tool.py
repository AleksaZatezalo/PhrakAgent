"""
Description: Semantic search over the workspace RAG index, exposed as an agent tool.

Wraps :class:`appsec.rag.CodeIndex` so agents (code_review, threat_model,
test_case) can find sibling instances of a pattern the way ``search_code``
finds exact matches. Complements ripgrep: use ``search_code`` when you know
the string, ``rag_search`` when you know the concept. Fails soft when the
runtime config isn't initialised (e.g. isolated unit tests) — tool just
returns a hint instead of raising.
"""

from __future__ import annotations

from langchain_core.tools import tool

# Cache the CodeIndex per (workspace, config) so repeated agent queries don't
# rebuild embeddings. Small module-level dict, keyed by workspace path.
_INDEX_CACHE: dict[str, object] = {}


def _get_index():
    """Return a CodeIndex for the active workspace, or None if unavailable."""
    try:
        from ..rag import CodeIndex
        from ..runtime import require_config

        cfg = require_config()
    except Exception:
        return None
    key = str(cfg.paths.workspace)
    idx = _INDEX_CACHE.get(key)
    if idx is None:
        try:
            idx = CodeIndex(cfg)
            _INDEX_CACHE[key] = idx
        except Exception:
            return None
    return idx


@tool
def rag_search(query: str, k: int = 6) -> str:
    """Semantic search over the workspace code index.

    Use this when ripgrep (`search_code`) can't help because you know the
    CONCEPT but not the exact string — e.g. "code that decodes JWTs without
    verifying the signature", "endpoints that touch the file system", "places
    that shell out". Returns up to `k` chunks as `path:start-end` blocks. If
    the same bug class appears in more than one place, this is how you find
    the others.
    """
    idx = _get_index()
    if idx is None:
        return "rag_search unavailable (no workspace / index)."
    try:
        if idx.count() == 0:
            idx.sync()
        hits = idx.search(query, k=k)
    except Exception as e:
        return f"rag_search failed: {e}"
    if not hits:
        return f"No semantic matches for: {query!r}"
    out = []
    for header, body in hits:
        # Content already starts with the "# path:start-end" header line.
        out.append(body if body.startswith("# ") else f"# {header}\n{body}")
    return "\n\n".join(out)[:8000]


def rag_search_tools() -> list:
    return [rag_search]
