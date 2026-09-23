<!-- PHRAK Agent changelog -->

# Changelog

All notable changes to PHRAK Agent are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file was seeded from the project's git history; the repository is not tagged,
so entries below group work by theme rather than by a released version boundary.

## [Unreleased]

### Added

- **Verify one finding on demand** — `phrak verify <FND-id>` (and `/verify` in
  chat) runs the sandboxed PoC agent against a single finding by id and records
  its runtime verdict. New `auto_verify` config flag (off by default) decouples
  "verify agent available" (`enable_verify`) from "let a full `run`
  auto-schedule PoCs" — so enabling verification never makes an assessment
  silently execute attacker code.
- **PoC store + replay** — every PoC the verify agent runs is saved to
  `.phrack/pocs/` with a `POC-…` id and index. Browse with `phrak poc` /
  `/poc`, inspect with `phrak poc POC-…`, and replay against a locally deployed
  target with `phrak poc-run POC-… <url>` / `/poc-run` (host exposed to the
  sandbox as `host.docker.internal`, target in `$PHRAK_TARGET`).
- **`http_request` tool** — the verify/test agent can send HTTP requests to a
  target, forced through the loopback + scope guard.
- **`scope` command** — `phrak scope` (and `/scope`) shows the workspace target
  scope policy and edits it without hand-writing YAML: `--init`, `--allow-host`,
  `--remove-host`, `--allow-port`, `--allow-path`, `--deny-path`, `--rate`,
  `--enable`/`--disable`.
- **Authorized remote targets** — new `allow_remote_targets` flag (off by
  default) lets the active tools (`http_request` / `/test` / `poc-run`) reach a
  non-loopback host **only** when it is explicitly listed in `scope.yaml`'s
  `allowed_hosts`. For authorized engagements (e.g. an in-scope bug-bounty
  target); there is no blanket "any host", and loopback-only remains the default.
- **Agentic test-case execution** — `phrak test <TC-id>` / `/test` drives a
  test case against the running app (via the `http_request` tool), records a PoC,
  and moves the test case's status/result — the live-traffic counterpart of
  `verify`. Works for linked and unlinked test cases; a linked case also promotes
  its finding on the runtime track.
- **Model benchmark** — `phrak benchmark` (and `/benchmark` in chat) runs one or
  more provider/model combinations against a labeled vulnerable target and prints
  a comparison table of recall, precision, and token cost. Interactive by default
  (prompts for provider, model, and API key); pass matched `--provider`/`--model`
  pairs to run non-interactively. Each model runs in an isolated throwaway
  workspace with the deterministic analyzers off, so the scores reflect the model
  itself and nothing lands in your real `.phrack/`.
- **OpenAI and xAI Grok providers** — `phrak config` now offers `openai` and
  `grok` alongside `ollama` and `anthropic`. Both run through the OpenAI client
  (Grok via its OpenAI-compatible `https://api.x.ai/v1` endpoint); keys are
  stored in `<workspace>/.phrack/credentials` as `OPENAI_API_KEY` / `XAI_API_KEY`.
  Adds an optional `langchain-openai` dependency.

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
