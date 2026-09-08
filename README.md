<!-- PHRAK Agent README -->

```
 ██████╗ ██╗  ██╗██████╗  █████╗ ██╗  ██╗
 ██╔══██╗██║  ██║██╔══██╗██╔══██╗██║ ██╔╝
 ██████╔╝███████║██████╔╝███████║█████╔╝
 ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██╔═██╗
 ██║     ██║  ██║██║  ██║██║  ██║██║  ██╗
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
```

# PHRAK Agent — a whitebox penetration testing assistant

**PHRAK works a whitebox engagement from the source side, end to end: recon of
the codebase, threat modeling, code review, findings triage, a manual test plan,
and the final report.** It reads the application; it never touches one.

That boundary is the whole design. PHRAK has **no HTTP client, no proxy, no
scanner, and no exploit runner** — it sends **zero packets to any target**. What
it produces is the artifact a whitebox tester needs: a prioritized set of
findings grounded in `file:line` evidence, and a test plan **you** execute
against a system you are authorised to test.

```
     source code                        PHRAK                        you
  ┌───────────────┐        ┌──────────────────────────────┐    ┌────────────┐
  │ repo / clone  │──read─▶│ recon · threat model · review │───▶│ triage     │
  │ dependencies  │        │ taint analysis · test plan    │    │ execute    │
  │ config        │        │ findings backlog · report     │    │ the tests  │
  └───────────────┘        └──────────────────────────────┘    └────────────┘
                                        ╳
                            never talks to the running app
```

| PHRAK does | PHRAK does not |
|------------|----------------|
| Read source, config, and dependency manifests | Send a single request to a live target |
| Trace taint from source to sink (OpenGrep) | Run an exploit against a deployed app |
| Model threats and attack paths against real components | Spider, fuzz, or scan a host |
| Keep a durable findings backlog you triage | Decide for you whether a bug is real |
| Author a manual test plan and track your progress | **Execute** those tests |
| Assemble the whole engagement into one report | Replace the human tester |

The one exception is opt-in and still never reaches your target: the
[`verify` agent](docs/verify-agent.md) can run a minimal proof-of-concept against
**the code, inside a locked-down container with no network**. It is off by
default.

Runs **fully offline on a local Ollama model** by default, or on **Claude via
the Anthropic API** if you opt in. **No Nuclei, no CodeQL/Joern** — OpenGrep is
the sole static analyzer. Everything a run produces stays on your machine in a
per-workspace `.phrack/` directory (like `.claude`).

## The workflow

A whitebox engagement, in the order you'd actually run it:

```bash
phrak clone https://github.com/org/app -w ./ws --index   # 1. bring the code in
phrak run "assess this app" -w ./ws                      # 2. model + review + tests
phrak findings -w ./ws                                   # 3. triage what came back
phrak testcases -w ./ws                                  # 4. work the test plan
phrak report -w ./ws                                     # 5. one deliverable
```

Steps 3 and 4 are yours, and **nothing in them involves a model**: you confirm
or dismiss findings, add ones you found yourself, and mark test cases off as you
execute them. Step 5 assembles everything into a single report. The mechanics of
steps 3–5 are in [Findings, triage, test cases & the report](docs/findings-and-testcases.md).

## Agents

| Agent | Role |
|-------|------|
| `code_review` | Finds vulnerabilities in source (OWASP/CWE) with `file:line` findings, exploitability reasoning, and fixes. Uses **OpenGrep taint mode** (source→sink traces) as confirmed leads, **OpenGrep pattern + secret scans** as unconfirmed leads, verifies each in source, and records structured findings. Has semantic `rag_search` for sibling instances of a pattern. |
| `threat_model` | STRIDE/PASTA threat model: components, trust boundaries, data flows, a per-threat table, and prioritized attack paths, tied to real components in the code. |
| `test_case` | Turns the source (+ `code_review` findings and `threat_model` threats fed forward) into a **prioritized list of concrete security test cases** — each with a target, steps, and expected result. Recorded in a trackable [backlog](docs/findings-and-testcases.md#test-cases). **PHRAK does not run the tests.** |
| `generate_report` | Assembles the engagement into one deliverable. Its body is **quoted verbatim** from the runs and stores; only the executive summary is model-written. See [the final report](docs/findings-and-testcases.md#the-final-report-generate_report). |
| `verify` *(opt-in)* | Runs a minimal PoC for each confirmed data-flow finding **inside a locked-down container** to demonstrate exploitability, then promotes the finding's runtime status. Off by default (`enable_verify: false`). |

The **orchestrator** plans a dependency graph of agent tasks, runs independent
ones in parallel, feeds each task's findings forward, and synthesizes one report
(confirmed vs. hypotheses, with coverage & limitations). `generate_report` is
deliberately **not** schedulable by the planner — it is invoked by hand, once the
work it reports on exists. See [How orchestration works](docs/orchestration.md).

## Install

```bash
python -m venv venv && source venv/bin/activate
pip install -e .                       # installs the `phrak` and `phrakagent` commands
# then install Ollama (https://ollama.com) and pull a model:
ollama pull qwen2.5-coder:7b
```

This installs two commands:

- **`phrakagent [DIR]`** — launch a chat session scoped to `DIR` (defaults to
  the current directory). `DIR` becomes the workspace: the root the file tools
  read, and where `.phrack/` is anchored. Trailing arguments pass through to the
  full CLI, e.g. `phrakagent /proj run "assess this app"`.
- **`phrak`** — the full CLI (`run` / `agent` / `ask` / `findings` / `config` /
  …), with `-w/--workspace` to point at a directory.

(Or, without installing: `pip install -r requirements.txt` and use
`python cli.py …`.)

Requires [Ollama](https://ollama.com) with a tool-capable model (default
`qwen2.5-coder:7b`) — unless you choose the Anthropic provider, which needs only
an API key. Optionally install [OpenGrep](https://opengrep.dev) for
static-analysis leads (PHRAK degrades gracefully without it; see
[static analysis](docs/static-analysis.md)).

## Configure — `phrak config`

```bash
phrak config
```

An interactive wizard (**no AI involved**) for your default workspace, model
provider, model settings, and embeddings backend. It writes
`<workspace>/.phrack/config.yaml`. Launching PHRAK with no config runs the
wizard automatically; re-run mid-session with `/config`. Inspect the resolved
config with `phrak config --show` (secret-looking values are redacted).

### Model provider — Ollama or Claude

| Provider | What it means |
|----------|---------------|
| `ollama` *(default)* | Fully local. Nothing leaves the machine. Asks for model, base URL, and temperature. |
| `anthropic` | Claude via the Anthropic API. Asks for the model (default `claude-opus-5`, or `claude-sonnet-5` / `claude-haiku-4-5`), a max-output-token cap, and your API key. **Prompts — including the code excerpts the agents read — are sent to Anthropic.** |

**The API key is stored in `<workspace>/.phrack/credentials`** (mode `0600`),
never in `config.yaml`. At startup PHRAK exports it as `ANTHROPIC_API_KEY`; a key
stored for the workspace takes precedence over one already in your shell. If the
provider is `anthropic` and no key is found, PHRAK says so at startup instead of
failing on the first model call. Re-run `phrak config` to rotate it (Enter keeps
the stored one), or edit/delete `.phrack/credentials` directly.

Per-agent overrides work across providers — e.g. a local model for `code_review`
and Claude for `threat_model`:

```yaml
agent_models:
  threat_model:
    provider: anthropic
    model: claude-opus-5
```

Embeddings for `/ask` are **always local** (Anthropic has no embeddings API);
with the `anthropic` provider, set `rag.embeddings.base_url` if your Ollama
server isn't at `http://localhost:11434`.

### The `.phrack/` directory

All per-workspace state lives in a single `.phrack/` dir at the workspace root:

```
<workspace>/.phrack/
├── config.yaml   # this workspace's configuration
├── credentials   # provider API keys (mode 0600) — only if you use one
├── rag/          # code-index vector store (Chroma)
├── skills/       # reusable skills you add from the CLI/REPL
├── findings/     # persistent finding history (cross-run dedup + triage)
├── testcases/    # the manual test-case backlog + your progress on it
├── taint/        # persistent taint-path history
├── reports/      # saved assessment reports
├── clones/       # repos brought in with `phrak clone`
├── scope.yaml    # optional declarative scope/target policy
└── history       # chat REPL history
```

`.phrack/` is git-ignored. Point at another project with `-w /path/to/project`
and it uses that project's own `.phrack/`. Anything added with `--global`
(skills) lives in `~/.phrack/` and applies to every workspace. (Legacy top-level
`config.yaml` + `data/` layouts are still auto-detected.)

### Config keys

The wizard writes everything you normally need, but `config.yaml` is plain YAML
you can edit. See [`config.example.yaml`](config.example.yaml) for the fully
commented file; the knobs worth knowing:

| Key | Default | What it controls |
|-----|---------|------------------|
| `llm.provider` / `llm.model` | `ollama` / `qwen2.5-coder:7b` | Where the model runs and which one |
| `llm.num_ctx` / `llm.max_tokens` | `16384` / `16000` | Ollama context window / Anthropic output cap |
| `rag.*` | see example | Index location, `recall_k`, `chunk_lines`/`chunk_overlap`, `max_file_kb`, embeddings backend |
| `orchestrator.mode` | `dag` | `dag` (graph + parallel fan-out) or `linear` |
| `orchestrator.max_concurrency` | `3` | Bounded parallel agents per wave |
| `orchestrator.continue_on_failure` | `true` | Isolate a failed task instead of aborting the run |
| `analyzers.opengrep` / `analyzers.dependency_audit` | `true` | Turn either deterministic analyzer off |
| `max_steps` / `max_rounds` | `40` / `4` | Per-round tool-call budget / completion nudges |
| `keep_reports` | `50` | Prune to the newest N reports (`0` = keep all) |
| `enable_git_clone` | `false` | Expose the guarded `git_clone` **tool** to `code_review` (see [Safety posture](#safety-posture)) |
| `enable_verify` | `false` | Register the opt-in `verify` agent (runs PoCs in a container) |
| `verify_runtime` / `verify_image` | `auto` / `python:3.12-slim` | Container runtime (`auto` → docker, then podman) and PoC image |
| `verify_network` | `none` | PoC container networking — `none`, or `bridge` if you deliberately need it |
| `verify_timeout_s` / `verify_memory_mb` / `verify_pids` | `30` / `512` / `128` | Per-PoC wall clock, memory, and process caps |
| `agent_models` | `{}` | Per-agent overrides of any `llm:` field, across providers |

The `verify_*` keys only matter when `enable_verify: true`; see
[the `verify` agent](docs/verify-agent.md).

## Quick start

```bash
phrak                              # conversational chat (like `claude`)
phrak -w /path/to/target           # chat about a specific codebase
phrak run "assess this app for security issues" -w ./target   # full swarm + report
phrak run --single "review server.py" -w ./target             # route to one agent
phrak clone https://github.com/org/webapp -w ./ws  # clone a repo into the workspace to analyze
phrak agent code_review "review for injection bugs" -w ./target
phrak ask "how are sessions authenticated?" -w ./target       # RAG over the code
phrak index -w ./target                # build/refresh the code index (no AI)
phrak index --stats -w ./target        # what's indexed, what's pending
phrak agents                           # list agents (and the model each uses)
phrak findings -w ./target             # every finding recorded so far
phrak findings --severity high --resurfaced -w ./target   # filter the backlog
phrak findings FND-284b4aac0d -w ./target                 # one finding in full
phrak add-finding -w ./target          # record one you verified yourself (no AI)
phrak testcases -w ./target            # the manual test plan, as a checklist
phrak add-testcase -w ./target         # write a test case by hand (no AI)
phrak report -w ./target               # assemble the whole engagement
phrak --json findings -w ./target      # the whole store as JSON, for CI
```

Global flags work on every subcommand: `-w/--workspace`, `-c/--config`,
`--quiet`, `--json`, `--no-color`, `--version`. (`phrak setup` aliases `config`,
`phrak interactive` aliases `chat`, and `-1` is short for `run --single`.)

## Chat mode

Running `phrak` with no subcommand drops you into a conversational REPL: plain
text is a normal turn (PHRAK reads code and answers, keeping thread context), and
everything else is a slash command. `Tab` autocompletes, `↑/↓` filters history by
prefix, and unknown commands get a "did you mean" hint.

Anywhere in a message, `@path/to/file` inlines that file from the workspace into
the turn. Each reference is echoed back before the model runs (`attached
@app.py (1,204 B)`), so a typo'd path or a refused traversal is visible
immediately; files outside the workspace are never inlined.

| Command | What it does |
|---------|--------------|
| `/ask <text> [--reindex]` | Answer a question grounded in the codebase (RAG) |
| `/index [--rebuild\|--stats]` | Build or refresh the code index — no AI |
| `/run <text>` | Full multi-agent assessment + saved report |
| `/route <text>` | Auto-route to the single best-fit agent |
| `/code_review`, `/threat_model`, `/test_case` `<text>` | Run one agent directly |
| `/agents [--verbose]` | List agents (with `--verbose`, their tools too) |
| `/generate_report` | Assemble the whole engagement into one report |
| `/findings [filters]` | List recorded findings (see [Triage](docs/findings-and-testcases.md#triage-findings)) |
| `/finding <id>` | One finding in full: evidence, taint paths, history, notes |
| `/finding-add` | Record a finding **you** verified — prompts, no AI |
| `/triage <id> <status> [note]` | Record your verdict on a finding |
| `/note <id> <text>` | Attach a reviewer note |
| `/testcases [filters]` | The test-case backlog as a checklist |
| `/testcase <id>` | One test case in full |
| `/testcase-add` | Write a test case by hand — prompts, no AI |
| `/testcase-status <id> <s>` | `new` / `in_progress` / `complete` (+ optional result) |
| `/testcase-link <id> <FND-…>` | Tie a test to the finding it verifies |
| `/testcase-note <id> <text>` | Record what happened when you ran it |
| `/clear` | Forget the conversation so far (fresh thread) |
| `/model [name]` | Show or switch the chat model for this session |
| `/cost` | Tokens used and estimated spend this session |
| `/verbose` | Toggle full tool output vs. one-line summaries |
| `/clone <url> [dest] [--index]` | Shallow-clone a repo to analyze |
| `/config [--show]` | Re-run the setup wizard (or print the redacted config) |
| `/help`, `/quit` | Grouped command list; exit |

Every `/run`, `/route`, and single-agent invocation saves and indexes its report
exactly like the equivalent CLI command.

## Bring in a codebase (`phrak clone`)

`phrak clone` (no AI) shallow-clones a remote repo into a sandboxed area under
the workspace and can index it in one step:

```bash
phrak clone https://github.com/org/webapp -w ./ws      # -> ./ws/clones/webapp
phrak clone git@github.com:org/webapp.git --index      # clone + build the RAG index
```

It clones `--depth 1 --single-branch` with **git hooks disabled** and submodules
skipped by default (`--recurse` to include them); **HTTPS/SSH URLs only** —
`file://`, local paths, and URLs carrying inline credentials are refused. The
clone is size-capped and confined to `<workspace>/clones`. Cloned code gets the
same read-only sandbox as any other workspace target.

## Documentation

The README is the overview; the deep dives live under [`docs/`](docs/):

| Doc | Covers |
|-----|--------|
| [Orchestration](docs/orchestration.md) | The task DAG, parallel waves + synthesis, robustness on weak local models, live activity output |
| [Findings, triage, test cases & the report](docs/findings-and-testcases.md) | Triaging findings, working the test-case backlog, the final report, the structured findings model, history & scope |
| [Static analysis](docs/static-analysis.md) | OpenGrep (taint / pattern / secrets), dependency audit, sanitizer checks |
| [The `verify` agent](docs/verify-agent.md) | The opt-in PoC runner and its container sandbox |
| [Codebase Q&A & indexing](docs/rag-and-indexing.md) | `phrak ask` (RAG) and `phrak index` |
| [Architecture](ARCHITECTURE.md) | Module map, data flow of a run, and the invariants a change must not break |
| [Changelog](CHANGELOG.md) | Notable changes by version |

## Safety posture

- **PHRAK never interacts with a running application.** There is no HTTP client,
  proxy, scanner, or exploit runner anywhere in the tool — it cannot send a
  request to a target because nothing in it can send one.
- `code_review`, `threat_model`, `test_case`, and `generate_report` (the agents
  that run by default) are all **read-only**, with no HTTP or script-execution
  tool. `test_case` produces a test *plan*, not an executor — running the cases is
  your own manual step, in an environment you're authorised to test.
- **`verify` is the one agent that executes code**, and it is **off by default**.
  When enabled, every PoC runs inside a container with no network, a read-only
  rootfs, no capabilities, as `nobody`, under memory / pid / wall-clock caps —
  never on the host. See [the `verify` agent](docs/verify-agent.md).
- **No agent reaches the network unless you opt in.** There are exactly two
  opt-ins, both off by default: `enable_git_clone` adds a guarded `git_clone`
  **tool** to `code_review` (HTTPS/SSH only, shallow, hooks disabled, size-capped,
  confined to `<workspace>/clones`); `enable_verify` + `verify_network: bridge`
  would give a PoC container network access (the default `none` is strongly
  recommended).
- **Local-first:** on the default `ollama` provider everything runs on your box.
  Every outbound path is explicit: `phrak clone` (and the opt-in `git_clone`),
  pointing the Ollama `base_url` at a remote endpoint, and **choosing the
  `anthropic` provider** (which sends prompts, with code excerpts, to the
  Anthropic API). The provider is shown in the boot banner.
- **API keys never enter the config or the index** — they live only in
  `.phrack/credentials` (mode `0600`), are redacted from `config --show`, and are
  passed to the SDK via an environment variable.
- File tools are sandboxed to the workspace; subprocess calls never use
  `shell=True` with model input. Agents always pause for `ask_user` /
  `request_permission`. **PHRAK never scans or attacks remote hosts, and does not
  use Nuclei.**

## Limitations (read these)

- **This is the source half of a whitebox engagement, not the whole engagement.**
  PHRAK never observes the running application, so anything that depends on
  deployment (reverse-proxy rules, WAF behaviour, runtime config, environment,
  infrastructure) is outside what it can see. A finding it reports as unreachable
  may be reachable in production, and vice versa.
- LLM output quality tracks the local model you choose; **LLM confidence is not a
  probability of exploitability.** RAG retrieval is **not** proof of reachability.
- **Taint coverage is Python and JS/TS only** (and not every bug class in either).
  Outside that, findings stay `unconfirmed` leads — absence of a taint path is
  absence of a *rule*, not evidence the code is safe.
- Test cases are **generated, not run.** A `verify` PoC that doesn't land means
  **not demonstrated**, not "not vulnerable."
- **Human review remains required.**

## Tests

```bash
pip install pytest
pytest                        # the whole bench
pytest tests/test_store.py    # one module
```

The bench is **offline by design** — no test reaches the network or a live model.
Providers are faked (`tests/conftest.py::FakeLLM`), external CLIs (OpenGrep,
`pip-audit`, the container runtime) are mocked, and every fixture writes into a
`tmp_path` workspace. An `integration` marker is registered in `pyproject.toml`
for tests that need a running Ollama or live target; none currently claims it, so
`pytest -m "not integration"` and a bare `pytest` run the same set.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) — dev setup, the `black` / `ruff` style
rules, the mandatory module-header docstring, and the architecture invariants a
PR must not break (read-only agents, no network without opt-in, OpenGrep as the
sole static analyzer). The module map and data flow are in
[`ARCHITECTURE.md`](ARCHITECTURE.md). False positives and missed findings belong
in a normal issue; vulnerabilities in PHRAK itself go to [`SECURITY.md`](SECURITY.md).
