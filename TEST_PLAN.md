# PHRAK Agent — Pre-Publish Test Plan

Run this end-to-end before pushing to GitHub. It covers the automated suite, a
manual smoke test of every CLI command, the `.phrack/` workspace layout, live
activity output, the Opengrep-based static analysis, the structured-findings
model, persistent finding/taint history + scope policy, DAG orchestration + the
structured threat model, the security test-case generator + SSRF hardening, the
no-AI CLI extensibility (skills / clone), the usability features, the
safety guardrails, and repo hygiene.

**PHRAK is local-only (Ollama) and uses Opengrep as its sole static analyzer.**
It does **not** use Nuclei, Semgrep, CodeQL, Joern, or a bespoke taint engine —
several checks confirm none of those remain.

Legend: ⬜ to do · ✅ pass · ❌ fail (note what broke)

---

## 0. Environment setup

```bash
cd PhrakAgent
python -m venv venv && source venv/bin/activate
pip install -e .                       # installs the `phrak` command
pip install -r requirements.txt
```

- ⬜ Fresh venv installs cleanly.
- ⬜ `phrak --help` and `python cli.py --help` both print usage.
- ⬜ `phrak --version` prints the version.
- ⬜ Ollama running with a tool-capable model: `ollama pull qwen2.5-coder:7b`.

---

## 1. Automated tests

```bash
pytest -m "not integration"     # fast unit gate (no network/LLM; CLIs mocked)
pip install flask && pytest     # full suite incl. local-target integration tests
```

- ⬜ `pytest -m "not integration"` — all green (**~216 tests**).
- ⬜ `pytest` (full) — green; integration tests pass or skip cleanly if Flask absent.
- ⬜ Tests never touch the real `.phrack/`, home dir, or network (all use `tmp_path`;
  the global skill dir is monkeypatched under `tmp_path`).

### Static checks (recommended)

```bash
pip install ruff && ruff check .
```

- ⬜ `ruff check .` clean (watch for unused imports after edits).

---

## 2. Providers (Ollama, Anthropic) and key storage

```bash
phrak config
```

- ⬜ The wizard offers `ollama` (default) and `anthropic`; embeddings offer
  `default` / `ollama` and are described as always-local.
- ⬜ Writing config reports `Wrote <workspace>/.phrack/config.yaml`.
- ⬜ Hand-editing config to `provider: openai` (or any unsupported one) fails fast:
  `Unknown LLM provider: … Supported providers are 'ollama' … and 'anthropic' …`
- ⬜ Launching with no config auto-runs the wizard.

Anthropic provider (skip if you have no key):

- ⬜ Choosing `anthropic` prints the "prompts are sent to Anthropic" notice,
  defaults the model to `claude-opus-5`, and prompts for the key without echoing it.
- ⬜ The key lands in `<workspace>/.phrack/credentials` with mode `600`
  (`stat -c '%a' .phrack/credentials`) — and **not** in `config.yaml`.
- ⬜ `phrak config --show` shows `provider: anthropic` and a real `max_tokens`
  value, with no key anywhere in the output.
- ⬜ Boot banner reads `model  anthropic:claude-opus-5`; a run completes.
- ⬜ With the key removed (`mv .phrack/credentials /tmp`) and no
  `ANTHROPIC_API_KEY` exported, startup warns
  `no ANTHROPIC_API_KEY found — the 'anthropic' provider will fail`.
- ⬜ Re-running `phrak config` and pressing Enter at the key prompt keeps the
  stored key (`keeping the key already in …`).
- ⬜ `phrak ask "…"` still works with `rag.embeddings.provider: default`
  (embeddings never hit Anthropic).

---

## 3. `.phrack/` workspace directory (like `.claude`)

- ⬜ After setup/first run, `<workspace>/.phrack/` contains `config.yaml`, `rag/`,
  `skills/`, `reports/` (and, after a review, `findings/` + `taint/`).
- ⬜ `phrak -w /other/project ...` creates/uses `/other/project/.phrack/`, not CWD's.
- ⬜ Nothing is written outside `.phrack/` on a fresh workspace.
- ⬜ A legacy checkout (top-level `config.yaml`) is still auto-detected.

---

## 4. CLI smoke test (scope with `-w`, e.g. `-w ./target`)

| Command | Expected | Status |
|---|---|---|
| `phrak agents` | Banner lists `code_review, test_case, threat_model` | ⬜ |
| `phrak ask "where is user input handled?" -w ./target` | Answer citing `file:line` | ⬜ |
| `phrak agent code_review "review for injection" -w ./target` | Findings w/ severity/location/fix + a **Structured Findings** section; `report saved :: .phrack/reports/report-<ts>-code_review.md` + `indexed N chunk(s)` | ⬜ |
| `phrak ask "what vulnerability did the last review find?" -w ./target` | Answers from the just-saved report, citing `.phrack/reports/report-*.md` | ⬜ |
| `phrak run "assess this app" -1 -w ./target` | One routed agent, report → `.phrack/reports/` | ⬜ |
| `phrak run "full assessment" -w ./target` | DAG plan (code_review + threat_model → test_case) → consolidated report incl. threat model, code-review findings, and a **security test-case list** | ⬜ |
| `phrak run "..." --json -w ./target` | Clean JSON (request/plan/report/report_path); no banner | ⬜ |
| `phrak chat -w ./target` | REPL; `/help`, `/agents`, `/ask`, `/quit` work | ⬜ |

- ⬜ Report appears at `.phrack/reports/report-<timestamp>.md` and reads well.
- ⬜ `keep_reports` pruning works.
- ⬜ Banner shows a `▸ skills  N learned` line.

---

## 5. Live activity / syscall output

- ⬜ Runs print `⚙ tool(args)` then `↳ tool: …` for each tool call.
- ⬜ Subprocess/network tools log the exec + a success/failure result line.
- ⬜ Piping to a file (or `--no-color`) keeps clean plain-text lines (no ANSI/spinner).

---

## 6. Opengrep static analysis + analyzers

```bash
phrak agent code_review "review ./target for vulnerabilities" -w ./target
```

- ⬜ `opengrep_scan` / `scan_secrets` produce leads; hits are treated as leads and
  **verified by reading the code** before being reported.
- ⬜ Scans exclude `venv`/`node_modules`/`.phrack` and honour the memory/jobs caps;
  an exit ≥ 2 is reported honestly (not a misleading "no output").
- ⬜ Missing `opengrep` binary degrades gracefully (install hint, run continues).
- ⬜ `dependency_audit` flags known-vulnerable versions per ecosystem (each optional).
- ⬜ `check_sanitizer` flags false-sanitizer assumptions (HTML-escape ≠ SQL-safe,
  urlparse ≠ SSRF-safe, prefix-before-canonicalize is bypassable).
- ⬜ `grep -rniE 'nuclei|semgrep|codeql|joern|taint_trace' appsec/ tests/` (excluding
  history docs) returns **nothing**.

---

## 7. Structured findings model

```bash
pytest tests/test_findings.py tests/test_findings_tool.py -q
```

- ⬜ Green: stable fingerprints, taint-path IDs, confidence bounds, enum validation,
  serialization round-trip, dedup, workspace grounding (path-escape / missing-file /
  out-of-range line), "data-flow finding can't be `confirmed` without a supporting
  taint path", status transitions, and **`effective_status()` precedence**
  (human > runtime > agent).
- ⬜ `report_finding` REJECTS structurally-invalid input and DOWNGRADES ungrounded
  evidence to `unconfirmed` (never silently upgrades).

---

## 8. Persistent history & scope (Phase 7)

```bash
pytest tests/test_store.py tests/test_scope.py -q
phrak agent code_review "review ./target" -w ./target   # populate the store
```

- ⬜ After a review, findings are persisted under `.phrack/findings/findings.jsonl`
  and taint paths under `.phrack/taint/taint.jsonl` (first/last seen, per-run log).
- ⬜ A human verdict is **preserved** across re-runs; a materially-changed re-observation
  flags the finding `⟲ re-surfaced`.
- ⬜ A `runtime` verdict records on its own track without overwriting the
  agent/human tracks, and an unknown actor is refused.
- ⬜ Scope policy: with `.phrack/scope.yaml` present, `http_request` respects
  `allowed_hosts`/`allowed_ports`/paths + `rate_limit_per_min`, and the loopback
  floor is still enforced first (a non-loopback host is refused regardless).

---

## 9. DAG orchestration + structured threat model (Phase 8)

```bash
pytest tests/test_dag.py tests/test_threat_model.py -q
phrak run "assess ./target end to end" -w ./target
phrak agent threat_model "threat model the app" -w ./target
```

- ⬜ `phrak run` (mode `dag`) plans a task graph; independent tasks run in parallel
  (bounded by `orchestrator.max_concurrency`) and dependents receive upstream output.
- ⬜ A failed task is **isolated**: its dependents are skipped, independent tasks still
  run, and the synthesis "Coverage & limitations" section names what failed/skipped.
- ⬜ The synthesis separates **Confirmed** from **Hypotheses** and preserves
  disagreement between agents.
- ⬜ `threat_model` produces the prose report **and** calls `record_threat_model`;
  the structured model (components/actors/assets/entry-points/flows/boundaries/
  threats/abuse-cases + candidate sources/sinks/controls) renders into the report and
  is saved to `.phrack/threat_model/model.json`, with code refs grounded.
- ⬜ Parallel agents don't clobber each other's findings (run-scoped collectors are
  context-isolated) and their terminal output is prefixed/quiet.

---

## 10. Security test-case generator + SSRF hardening

```bash
phrak agent test_case "derive security test cases for this app" -w ./target
```

- ⬜ `test_case` is **read-only**: it reads source (`list_dir`/`read_file`/
  `search_code`) and writes a report — no HTTP or script-execution tool, no
  traffic to any target.
- ⬜ Output contains a **Summary**, a numbered **Test Cases** list (each with an
  ID like `TC-001`, a target `file:line`/endpoint, steps, and an expected
  result), a **Prioritization** order, and a **Coverage / Traceability** map.
- ⬜ In a full `phrak run`, `test_case` runs AFTER `code_review` + `threat_model`
  and its cases trace back to their findings/threats; the consolidated report
  keeps the test-case list.
- ⬜ SSRF hardening: encoded loopback (`2130706433`, `0x7f000001`, `::ffff:127.0.0.1`)
  is treated as local; encoded **public** IPs and `169.254.169.254` are refused; an
  HTTP **redirect** off the loopback interface is blocked.

---

## 11. Usability & extensibility — no AI (Phase 9)

```bash
phrak clone https://github.com/OWASP/NodeGoat -w ./ws --index
phrak config --show
```

- ⬜ `clone`/`config --show` make **no LLM call** (work offline,
  instantly) — pure file/validation operations.
- ⬜ Saved skills dropped under `<workspace>/.phrack/skills/` and `~/.phrak/skills/`
  are both loaded; a workspace entry **overrides** a global one of the same name.
- ⬜ `clone` refuses non-HTTPS/SSH URLs, `file://`, local paths, and inline creds;
  clones **shallow** with hooks disabled and no submodules (unless `--recurse`);
  enforces the size cap and stays inside `<workspace>/clones`.
- ⬜ `phrak config --show` prints a **redacted** config (any key/token value shows
  `***redacted***`) and includes the `orchestrator`/`analyzers` blocks.
- ⬜ `git_clone` tool is **absent** from agents unless `enable_git_clone: true`.

### REPL session features

- ⬜ Grouped `/help` lists the available commands; `/agents --verbose` lists
  agents with their tools; typo hints ("did you mean") work.
- ⬜ Readline `↑/↓` filters your prompt history; plain text is a conversational
  turn (tool use + thread memory).
- ⬜ `--no-color` disables color across the UI.
- ⬜ None of the above change the security posture (guards from §12 still hold).

---

## 12. Safety guardrails

- ⬜ `read_file` refuses a path escaping the workspace (`../../etc/passwd`).
- ⬜ `http_request` refuses a non-loopback host and a redirect off loopback.
- ⬜ `run_script` refuses a destructive payload (`rm -rf /`, fork bomb, …).
- ⬜ No `shell=True` is ever built from model input (subprocess arg arrays only).

---

## 13. Packaging / clean-clone install

```bash
cd /tmp && git clone <your-fork-url> phrak-clone && cd phrak-clone
python -m venv venv && source venv/bin/activate
pip install -e .
pytest -m "not integration"
phrak config
```

- ⬜ Installs and tests pass with no reliance on your local `.phrack/` or `~/.phrak/`.
- ⬜ README install/usage steps match reality.

---

## 14. Repo hygiene — before `git push`

- ✅ `.gitignore` ignores `venv/`, caches, and the whole `.phrack/`.
- ✅ `LICENSE` present (MIT).
- ⬜ `git status` shows no `venv/`, `__pycache__/`, `.pytest_cache/`, `.phrack/`,
  or `data/` artifacts staged.
- ⬜ No secrets committed (`.phrack/config.yaml` is git-ignored; only env-var names /
  redacted values are ever stored).
- ⬜ README and TEST_PLAN render correctly on GitHub.
- ⬜ (Optional) add `license`/`authors` to `pyproject.toml`.

---

## Sign-off

- ⬜ §1 automated tests green (~216)
- ⬜ §2–§7 core checks pass (provider, layout, CLI, activity, Opengrep, findings)
- ⬜ §8 verification/history/scope checks pass
- ⬜ §9 DAG + structured threat model checks pass
- ⬜ §10 security test-case generator + SSRF hardening checks pass
- ⬜ §11 usability/extensibility checks pass
- ⬜ §12 guardrails hold
- ⬜ §13 clean-clone install works
- ⬜ §14 hygiene complete

Once all boxes are checked, tag a release and push. 🚀
