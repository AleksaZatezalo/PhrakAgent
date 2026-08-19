"""
Description: Codebase RAG — ask questions grounded in the working-directory code & docs.
Author: Aleksa Zatezalo
Date Created: 08-01-2026
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Optional

from langchain_core.embeddings import Embeddings
from langchain_core.language_models.chat_models import BaseChatModel

from .config import PHRACK_DIRNAME, Config, EmbeddingsConfig, RagConfig
from .llm import message_text


# ---------------------------------------------------------------- embeddings
class _DefaultEmbeddings(Embeddings):
    """Local ONNX MiniLM embeddings via chromadb — no external model to pull."""

    def __init__(self) -> None:
        from chromadb.utils import embedding_functions

        self._ef = embedding_functions.DefaultEmbeddingFunction()

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [list(map(float, v)) for v in self._ef(texts)]

    def embed_query(self, text: str) -> list[float]:
        return list(map(float, self._ef([text])[0]))


def build_embeddings(cfg: EmbeddingsConfig, ollama_base_url: str) -> Embeddings:
    """Embeddings are always local — ``ollama_base_url`` is where the Ollama
    server lives, which is *not* the LLM's base URL when the LLM is Claude
    (see :meth:`Config.ollama_base_url`)."""
    provider = cfg.provider.lower()
    if provider == "ollama":
        from langchain_ollama import OllamaEmbeddings

        return OllamaEmbeddings(model=cfg.model, base_url=ollama_base_url)
    return _DefaultEmbeddings()


_ANSWER_PROMPT = """You are PHRAK, answering a question about the code and \
documentation in the current working directory. Use ONLY the context excerpts \
below — do not rely on outside knowledge or invent files.

Cite every claim with the source it came from, formatted as `path:start-end` \
(the header shown above each excerpt). If the context does not contain the \
answer, say so plainly and suggest where in the codebase to look next.

QUESTION: {question}

CONTEXT EXCERPTS:
{context}
"""


class CodeIndex:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.rag: RagConfig = config.rag
        self.workspace = Path(config.paths.workspace)
        self._embeddings: Optional[Embeddings] = None
        self._store = None  # built lazily so import/startup stays cheap
        # Embedding is CPU-bound and writes to one SQLite-backed store, so the
        # DAG's parallel agents must not sync at the same time: they would
        # duplicate the work and contend on the same file.
        self._sync_lock = threading.RLock()
        self._synced = False

    # ------------------------------------------------------------- backing
    @property
    def store(self):
        if self._store is None:
            from langchain_chroma import Chroma

            self._embeddings = build_embeddings(
                self.rag.embeddings, self.config.ollama_base_url()
            )
            self._store = Chroma(
                collection_name=self.rag.collection,
                embedding_function=self._embeddings,
                persist_directory=str(self.config.rag_dir()),
            )
        return self._store

    def count(self) -> int:
        try:
            return self.store._collection.count()
        except Exception:
            return 0

    # ----------------------------------------------------------- discovery
    def _iter_files(self):
        exts = set(self.rag.include_ext)
        excluded = set(self.rag.exclude_dirs)
        max_bytes = self.rag.max_file_kb * 1024
        root = self.workspace
        # Index the workspace's own .phrack artifacts (reports, learned skills,
        # config) so /ask can answer questions about them too — but never the
        # vector-store directory itself (that would index the index).
        store_dir = self.config.rag_dir().resolve()
        for dirpath, dirnames, filenames in os.walk(root):
            # prune excluded and hidden dirs in place — but keep .phrack, and
            # never descend into the vector store directory.
            dirnames[:] = [
                d
                for d in dirnames
                if d not in excluded
                and (not d.startswith(".") or d == PHRACK_DIRNAME)
                and (Path(dirpath) / d).resolve() != store_dir
            ]
            for name in filenames:
                if Path(name).suffix.lower() not in exts:
                    continue
                fp = Path(dirpath) / name
                try:
                    size = fp.stat().st_size
                except OSError:
                    continue
                if size > max_bytes:
                    continue
                # Skip empty files. They chunk to nothing, so _add_file stores
                # no metadata for them — which means _indexed_mtimes never sees
                # them and every later sync "adds" them again, forever. A repo
                # full of empty __init__.py files would never reach a clean
                # no-op sync. There is nothing in them to retrieve anyway.
                if size == 0:
                    continue
                yield fp

    def _rel(self, fp: Path) -> str:
        """Workspace-relative path — the stable key every chunk is stored under.

        ``sync`` walks from ``self.workspace`` so its paths are already relative
        to it, but :meth:`index_file` is handed absolute paths (a report under
        ``.phrack/reports``); try the resolved root too so both produce the same
        key for the same file.
        """
        for base in (self.workspace, self.workspace.expanduser().resolve()):
            try:
                return str(fp.relative_to(base))
            except ValueError:
                continue
        return str(fp)

    def _chunk(self, text: str) -> list[tuple[int, int, str]]:
        """Split into overlapping line windows: (start_line, end_line, text)."""
        lines = text.splitlines()
        if not lines:
            return []
        size = max(1, self.rag.chunk_lines)
        overlap = max(0, min(self.rag.chunk_overlap, size - 1))
        step = size - overlap
        chunks: list[tuple[int, int, str]] = []
        i = 0
        n = len(lines)
        while i < n:
            window = lines[i : i + size]
            start, end = i + 1, min(i + size, n)  # 1-indexed, inclusive
            body = "\n".join(window).strip()
            if body:
                chunks.append((start, end, body))
            i += step
        return chunks

    # ---------------------------------------------------------------- sync
    def _indexed_mtimes(self) -> dict[str, float]:
        """Map of indexed path -> the mtime recorded for its chunks."""
        try:
            data = self.store.get(include=["metadatas"])
        except Exception:
            return {}
        out: dict[str, float] = {}
        for meta in data.get("metadatas", []) or []:
            p = (meta or {}).get("path")
            if p is not None:
                out[p] = (meta or {}).get("mtime", 0.0)
        return out

    def _delete_path(self, rel: str) -> None:
        try:
            got = self.store.get(where={"path": rel})
            ids = got.get("ids", [])
            if ids:
                self.store.delete(ids=ids)
        except Exception:
            pass

    def _add_file(self, fp: Path, rel: str, mtime: float) -> int:
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return 0
        chunks = self._chunk(text)
        if not chunks:
            return 0
        texts, metas, ids = [], [], []
        for start, end, body in chunks:
            header = f"{rel}:{start}-{end}"
            texts.append(f"# {header}\n{body}")
            metas.append({"path": rel, "start": start, "end": end, "mtime": mtime})
            ids.append(f"{rel}::{start}-{end}")
        self.store.add_texts(texts, metadatas=metas, ids=ids)
        return len(texts)

    def sync(self, on_progress=None) -> dict:
        """Incrementally bring the index in line with the workspace.

        Only files whose mtime changed are re-embedded, but embedding is
        CPU-bound: a first sync over a few hundred files takes minutes. Callers
        that can be waited on should pass ``on_progress(done, total, rel)`` so
        that time is visible rather than looking like a hang.

        Serialized: two agents syncing the same store at once would duplicate
        every embedding and contend on one SQLite file.

        Returns ``{"added", "updated", "removed", "chunks"}`` file/chunk counts.
        """
        with self._sync_lock:
            indexed = self._indexed_mtimes()
            seen: set[str] = set()
            added = updated = chunks = 0

            stale: list[tuple[Path, str, float, bool]] = []
            for fp in self._iter_files():
                rel = self._rel(fp)
                seen.add(rel)
                try:
                    mtime = fp.stat().st_mtime
                except OSError:
                    continue
                prior = indexed.get(rel)
                if prior is None:
                    stale.append((fp, rel, mtime, False))
                elif abs(float(prior) - mtime) > 1e-6:
                    stale.append((fp, rel, mtime, True))

            total = len(stale)
            for i, (fp, rel, mtime, is_update) in enumerate(stale, 1):
                if on_progress:
                    on_progress(i, total, rel)
                if is_update:
                    self._delete_path(rel)
                    updated += 1
                else:
                    added += 1
                chunks += self._add_file(fp, rel, mtime)

            removed = 0
            for rel in indexed:
                if rel not in seen:
                    self._delete_path(rel)
                    removed += 1

            self._synced = True
            return {
                "added": added,
                "updated": updated,
                "removed": removed,
                "chunks": chunks,
            }

    def sync_once(self, on_progress=None) -> dict:
        """Sync at most once per process; a no-op on every later call.

        For the agent-facing ``rag_search`` tool. Every PHRAK agent tool is
        read-only, so the workspace cannot change during a run — re-syncing per
        tool call re-walks the tree and re-reads the whole index's metadata for
        nothing, and on a stale index it re-runs a multi-minute embed inside
        each tool call, in each parallel agent.
        """
        with self._sync_lock:
            if self._synced:
                return {"added": 0, "updated": 0, "removed": 0, "chunks": 0}
            return self.sync(on_progress=on_progress)

    def index_file(self, path: str | Path) -> int:
        """Add or refresh ONE file's chunks; returns how many were indexed.

        Makes a just-written artifact — e.g. an agent report saved under
        ``.phrack/reports`` — searchable by ``/ask`` straight away, without
        waiting for the next full :meth:`sync` over the workspace.
        """
        fp = Path(path).expanduser()
        if not fp.is_file():
            return 0
        try:
            mtime = fp.stat().st_mtime
        except OSError:
            return 0
        rel = self._rel(fp)
        self._delete_path(rel)  # drop chunks from any previous version
        return self._add_file(fp, rel, mtime)

    def reindex(self) -> dict:
        """Wipe and rebuild the whole index from scratch."""
        try:
            ids = self.store.get().get("ids", [])
            if ids:
                self.store.delete(ids=ids)
        except Exception:
            pass
        return self.sync()

    # ------------------------------------------------------------- retrieve
    def search(self, query: str, k: Optional[int] = None) -> list[tuple[str, str]]:
        """Return ``[(source_header, excerpt_text), ...]`` for the query."""
        k = k or self.rag.recall_k
        try:
            docs = self.store.similarity_search(query, k=k)
        except Exception:
            return []
        out: list[tuple[str, str]] = []
        for d in docs:
            m = d.metadata or {}
            header = f"{m.get('path', '?')}:{m.get('start', '?')}-{m.get('end', '?')}"
            out.append((header, d.page_content))
        return out

    def ask(
        self,
        llm: BaseChatModel,
        question: str,
        k: Optional[int] = None,
        sync: bool = True,
    ) -> str:
        """Answer ``question`` grounded in retrieved code, with citations.

        Syncs the index first. That sync is incremental (mtime-keyed, so only
        changed files re-embed) and it is not optional by default: an answer
        built from a stale index carries the same confident ``file:line``
        citations as a current one, which is the worst way to be wrong. Pass
        ``sync=False`` only when the caller has just synced.
        """
        stale_warning = ""
        if sync or self.count() == 0:
            try:
                self.sync()
            except Exception as e:
                # Answer from what's indexed rather than failing outright — but
                # say so, so a stale citation is never read as a current one.
                stale_warning = (
                    f"> ⚠ Could not refresh the code index ({e}). The answer "
                    "below may describe an older version of the code.\n\n"
                )
        hits = self.search(question, k=k)
        if not hits:
            return stale_warning + (
                "The code index is empty or found nothing relevant. Make sure "
                "the workspace points at your code, then try again "
                "(or reindex with `/ask --reindex`)."
            )
        blocks = []
        for header, content in hits:
            # content already begins with a "# path:start-end" header line
            blocks.append(
                content if content.startswith("# ") else f"# {header}\n{content}"
            )
        prompt = _ANSWER_PROMPT.format(question=question, context="\n\n".join(blocks))
        try:
            return stale_warning + message_text(llm.invoke(prompt))
        except Exception as e:
            return f"[ask failed: {e}]"
