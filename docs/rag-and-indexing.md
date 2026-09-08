<!-- PHRAK Agent — codebase Q&A and indexing -->

# Codebase Q&A (`/ask`) and indexing

> Part of the [PHRAK Agent documentation](../README.md#documentation).

`phrak ask "<question>"` retrieves relevant chunks from a local Chroma index over
the workspace and answers with `path:start-end` citations. The index covers
source + docs and **also indexes the workspace's own `.phrack/` reports and saved
skills** (so you can ask "what did the last threat model flag?"); only the vector
store itself (`.phrack/rag/`) is skipped. Retrieval is dense vector search over a
local embeddings backend (`default` ONNX or `ollama`); tune chunk size, `recall_k`,
extensions, and excluded dirs under `rag:` in config.

**The index is refreshed before every question**, so a citation reflects the code
as it is now. The sync is **incremental** — files are keyed by mtime, so only what
changed re-embeds. If the embeddings backend is unreachable, the answer is still
produced from whatever is indexed, prefixed with an explicit staleness warning.

## `phrak index` — do the embedding on your own schedule

Embedding is **local and CPU-bound** (a few hundred files takes minutes), so
`phrak index` lets you pay that cost deliberately rather than mid-assessment:

```bash
phrak index                  # build or refresh — no AI, no model, no network
phrak index --stats          # what's indexed and what's pending; changes nothing
phrak index --rebuild        # wipe and re-embed everything (slow)
phrak --json index           # machine-readable, for CI
```

```
[phrak] index :: 4359 chunk(s) from 742 file(s) :: .phrack/rag
[phrak] workspace :: 742 indexable file(s)
[phrak] up to date — nothing to do
```

Run it after `phrak clone` or a big refactor, and every later `/ask` and
`rag_search` is instant. The agents' `rag_search` refreshes the index at most
**once per process**, serialized across the DAG's parallel agents — but that one
refresh still happens inside a tool call, so on a large never-indexed workspace
it's a multi-minute pause mid-run. Indexing up front avoids it.

Reach for `--rebuild` only when the index itself is suspect (changed chunk size /
embeddings model, or a corrupted store); ordinary edits are handled incrementally.

**RAG retrieval is not proof of reachability** — a chunk surfacing for a query
means it's textually relevant, not that the code path is live.
