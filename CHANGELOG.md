<!-- PHRAK Agent changelog -->

# Changelog

All notable changes to PHRAK Agent are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file was seeded from the project's git history; the repository is not tagged,
so entries below group work by theme rather than by a released version boundary.

## [Unreleased]

_Nothing yet._

## [0.3.0] — 2026-09-08

The current state of the tool: a read-only, source-side whitebox assistant that
runs a DAG of specialist agents and assembles one report.

### Added

- **Agent swarm** — `code_review`, `threat_model`, `test_case`, and
  `generate_report`, coordinated by a DAG orchestrator with bounded parallel
  fan-out, failure isolation, and synthesis (confirmed vs. hypotheses).
- **`verify` agent (opt-in)** — runs a minimal PoC for each confirmed data-flow
  finding inside a locked-down, network-less container and promotes the finding's
  runtime status. Off by default (`enable_verify: false`).
- **Persistent findings & taint history** — fingerprint-keyed JSONL stores under
  `.phrack/`, cross-run dedup, separate `agent` / `runtime` / `human` status
  tracks, `⟲ re-surfaced` flags, and concurrency-safe writes.
- **Manual triage & entry** — `phrak findings` / `/findings`, `/triage`, `/note`,
  and `add-finding` / `add-testcase` for items you verify by hand (no model).
- **Test-case backlog** — the `test_case` agent authors a trackable plan; coverage
  reconciliation links tests to findings and backfills a verification test case
  per uncovered finding.
- **Consolidated report** (`phrak report`) — assembled by hand, quoting saved
  artifacts verbatim; only the executive summary is model-written.
- **Codebase Q&A** (`phrak ask`) and `phrak index` — incremental local Chroma
  index with `path:line` citations, over source, docs, and `.phrack/` artifacts.
- **`phrak clone`** — guarded shallow clone (HTTPS/SSH only, hooks disabled,
  size-capped, confined to `<workspace>/clones`).
- **`--version`** command and a `.gitignore`.
- Reliability layers for weak local models: verbalized-tool-call rescue
  (`middleware.py`) and deterministic findings/test-case extraction
  (`extract.py`).

### Changed

- **OpenGrep is now the sole static analyzer**, replacing the earlier CodeQL/Joern
  setup and the bespoke Python taint engine — taint mode provides the confirmed
  leads, pattern + secret scans the unconfirmed ones.
- Reworked RAG indexing to be incremental (mtime-keyed) and to refresh before
  every question, with an explicit staleness warning when embeddings are offline.
- Consolidated all per-workspace state under a single `.phrack/` directory (legacy
  top-level `config.yaml` + `data/` layouts still auto-detected).
- Documentation restructured: the README is now an overview linking to `docs/`,
  with `ARCHITECTURE.md` and this changelog added.

### Removed

- The legacy standalone test-plan flow (superseded by the tracked test-case
  backlog).
- Self-learning / agent-authored "learned skills" framing — the skill store now
  holds user-provided, reusable saved skills only.

### Security

- All default agents are read-only with no HTTP or script-execution tool; the only
  code executor (`verify`) is opt-in and container-sandboxed.
- No network without an explicit opt-in; provider is shown in the boot banner.
- API keys live only in `.phrack/credentials` (mode `0600`), redacted from
  `config --show`, and are never written to config or the index.

## [0.1.0] — 2026-08-04

- Initial commit: PHRAK Agent local AppSec agent swarm.
