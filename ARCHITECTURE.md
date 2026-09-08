<!-- PHRAK Agent — architecture -->

# Architecture

How PHRAK is put together: the module map, the data flow of a run, and the
invariants a change must not break. For the user-facing docs see the
[README](README.md#documentation).

## The shape of it

PHRAK is a **read-only, source-side** whitebox assistant. It reads a codebase and
produces findings, a test plan, and a report; it never sends a packet to a running
target. Everything a run produces is written under a per-workspace `.phrack/`
directory (config, code index, findings, test cases, reports).

```
  bootstrap            orchestration              persistence
 ┌──────────┐    ┌───────────────────────┐    ┌──────────────────┐
 │ app.py   │──▶ │ orchestrator.py       │──▶ │ store.py         │
 │ config   │    │  plan/route → DAG →   │    │  findings/taint  │
 │ llm      │    │  parallel agent waves │    │  (JSONL, locked) │
 │ skills   │    │  → synthesis          │    │ testcase_cmds.py │
 │ rag      │    └───────────┬───────────┘    │  testcases       │
 │ registry │                │                └──────────────────┘
 └──────────┘        ┌───────▼────────┐
                     │ base_agent.py  │  tool-calling loop per agent
                     │  + tools/*     │  (read_file, opengrep, rag_search,
                     └───────┬────────┘   report_finding, report_test_case …)
                             │
                     ┌───────▼────────┐
                     │ analyzers/*    │  OpenGrep, dependency audit,
                     │ (normalized to │  sanitizer checks →
                     │  SecurityFinding) │  validate → ground → dedupe
                     └────────────────┘
```

## Data flow of a `phrak run`

1. **Bootstrap (`app.py`).** Resolve config (`config.py`), build the LLM factory
   (`llm.py`), the skills stores (`skill_library.py` curated, `skill_store.py`
   saved), the RAG index (`rag.py`), and the agent registry.
2. **Plan / route (`orchestrator.py`).** In `dag` mode the LLM returns a task
   graph; in `--single` mode one best-fit agent is chosen. See
   [orchestration](docs/orchestration.md).
3. **Execute waves.** Independent tasks run in parallel (bounded by
   `max_concurrency`), each in an isolated run-scoped context (`runtime.py`,
   context-vars) so parallel agents never clobber shared state.
4. **Each agent (`base_agent.py`).** A tool-calling loop over the tools in
   `tools/`, with curated + saved skills and a workspace file overview
   (`file_assist.py`). `middleware.py` rescues verbalized tool calls from weak
   local models; deterministic fallbacks (`extract.py`) capture findings when the
   model won't call the tools.
5. **Analyzers (`analyzers/`).** OpenGrep (taint + pattern + secrets), dependency
   audit, and sanitizer checks each normalize into the same `SecurityFinding`
   (`models/findings.py`) and run through `validate → ground → dedupe`.
6. **Persist (`store.py`, `testcase_cmds.py`).** Findings and taint paths upsert
   into `.phrack/findings/` and `.phrack/taint/` (fingerprint-keyed JSONL, thread
   + file locked, atomic rename); test cases into `.phrack/testcases/`.
7. **Synthesis + coverage (`orchestrator.py`, `coverage.py`).** Merge outputs into
   one report (confirmed vs. hypotheses + coverage/limitations), then link test
   cases to findings and backfill a verification test case per uncovered finding.
8. **Report (`report.py`, `generate_report`).** Assembled by hand, quoting saved
   artifacts verbatim; only the executive summary is model-written.

## Module map

```
appsec/
  cli.py            argparse entry point (`phrak`) + the chat REPL loop
  app.py            bootstrap: config -> llm, skills, rag, orchestrator, registry
  base_agent.py     agent loop + registry + run-to-completion + finding persistence
  orchestrator.py   planner/router + DAG execution (parallel fan-out) + synthesis
                    + salvage of findings/test cases from the consolidated report
  extract.py        deterministic findings/test-case extraction from a prose report
  coverage.py       link test cases to findings + backfill a test case per finding
  chat.py           conversational session (multi-turn, tool use, thread memory)
  repl.py           chat REPL helpers (readline autocomplete/history, grouped /help)
  llm.py            chat-model factory (ollama | anthropic) + model registry
  middleware.py     rescues "verbalized" tool calls from weaker local models
  runtime.py        process/run-scoped context (config, active agent, findings,
                    tool ledger — context-vars, so parallel agents stay isolated)
  config.py         config + setup wizard + .phrack path resolution + config --show
  credentials.py    provider API keys (.phrack/credentials -> env var at startup)
  rag.py            workspace code index (Chroma) powering /ask
  store.py          persistent finding/taint history (.phrack/findings, .phrack/taint)
  scope.py          declarative scope/target policy (.phrack/scope.yaml)
  clone.py          guarded shallow git clone
  session_cmds.py   session-command helpers: findings triage, manual entry, @file
  skill_store.py    saved-skills store (workspace + ~/.phrak global)
  skill_library.py  curated skills (appsec/skills/<agent>/*.md)
  file_assist.py    workspace overview + read-files-on-demand
  banner.py         startup banner + ANSI styling (NO_COLOR / non-TTY aware)
  ui.py             spinners, live activity log, markdown render, agent prompts
  report.py         deterministic consolidated-report assembly (generate_report)
  testcase_cmds.py  non-agentic test-case backlog commands (list/status/link/add)
  models/           structured findings + taint models + test-case model
  agents/           code_review, threat_model, test_case, generate_report, verify
  analyzers/        AnalyzerAdapter base + opengrep, dependencies, sanitizers
                    rules/taint/   bundled OpenGrep taint rules (python, javascript)
  tools/            common (sandbox/subprocess/loopback+SSRF guard), filesystem,
                    analysis, opengrep_tools, analyzer_tools, findings_tool,
                    rag_tool, testcase_tool, clone_tool, verify_tool, interaction,
                    skills_tool
cli.py              thin shim so `python cli.py …` still works
tests/              pytest bench (unit + marker-gated integration)
```

## Invariants (a PR must not break these)

- **Read-only agents.** `code_review`, `threat_model`, `test_case`, and
  `generate_report` have no HTTP client and no script-execution tool. `verify` is
  the sole executor, off by default, and only ever runs code in a locked-down
  container — never on the host. See [the verify agent](docs/verify-agent.md).
- **No network without an explicit opt-in.** The only outbound paths are
  `phrak clone` / the opt-in `git_clone` tool, an Ollama `base_url` you point
  elsewhere, and choosing the `anthropic` provider. Nothing leaves silently.
- **OpenGrep is the sole static analyzer** — no CodeQL/Joern, no Nuclei. See
  [static analysis](docs/static-analysis.md).
- **Findings are grounded and validated.** A data-flow finding can't be
  `confirmed` without a supporting taint path; `report_finding` downgrades
  ungrounded evidence rather than trusting a model claim. Human triage outranks
  runtime, which outranks the reporting agent.
- **Secrets never enter config or the index.** API keys live only in
  `.phrack/credentials` (mode `0600`), redacted from `config --show`, passed to
  the SDK via an environment variable.
- **The store survives concurrency and crashes.** Parallel agents serialize writes
  (thread + advisory file lock) and land them via atomic rename.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for style rules and the full contributor
checklist.
