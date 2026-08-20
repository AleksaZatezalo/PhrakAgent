<!-- PHRAK Agent — contributing guide -->

# Contributing to PHRAK Agent

Thanks for looking. PHRAK is a small, opinionated project: a **local-first,
read-only** AppSec agent swarm. Most of the guidance below exists to keep it that
way — the architecture invariants in [Non-negotiables](#non-negotiables) are the
part worth reading before you write code.

**Before you file anything:**

| You have | Go here |
|---|---|
| A vulnerability **in PHRAK itself** | [`SECURITY.md`](SECURITY.md) — report privately, **not** a public issue |
| A vulnerability **PHRAK found** in something else | [`FINDINGS.md`](FINDINGS.md) |
| A false positive / false negative | A normal issue — use the *Detection quality* template |
| A crash or wrong behaviour | A normal issue — use the *Bug report* template |

## Development setup

```bash
git clone https://github.com/AleksaZatezalo/PhrakAgent.git
cd PhrakAgent
python -m venv venv && source venv/bin/activate
pip install -e .                      # installs the `phrak` command
pip install pytest black ruff         # dev tooling (not in the install deps)
```

Requires Python **3.10+**. To exercise anything model-facing you also need
[Ollama](https://ollama.com) with a tool-capable model (`ollama pull
qwen2.5-coder:7b`), or an Anthropic API key via `phrak config`. Optionally
install [OpenGrep](https://opengrep.dev) for static-analysis leads — PHRAK
degrades gracefully without it, and the test suite mocks it.

## Tests

```bash
pytest -m "not integration"   # fast unit tests — no network, no LLM, CLIs mocked
pytest                        # full suite (integration tests need Flask)
```

The full suite must pass before you open a PR. See [`TEST_PLAN.md`](TEST_PLAN.md)
for the broader pre-publish checklist.

**New code needs tests.** The bar isn't coverage percentage — it's that a
reviewer can see the behaviour pinned down. Follow the existing bench: unit tests
are pure and offline (fakes for the LLM, mocked analyzer binaries, `tmp_path` for
workspaces), and anything needing a live target or model is gated behind
`@pytest.mark.integration`. A test that silently requires Ollama to be running is
a broken test.

## Style

**Formatting is mechanical — don't hand-format.**

```bash
black .          # line length 88 (Black's default); skips venv/ automatically
ruff check .     # line-length 90 per pyproject.toml
```

Black is the authority on layout; ruff catches the rest. Two consequences of
running default Black that are intentional here: inline comments sit two spaces
after code (no column alignment), and a trailing comma in a collection keeps it
expanded one-item-per-line.

### Module header

**Every `.py` file starts with this docstring, no exceptions:**

```python
"""
Description: One line saying what this module is for.
Author: Your Name
Date Created: MM-DD-YYYY
"""
```

`Author` is whoever created the file — leave it alone when you edit someone
else's, and don't add yourself to it. `Date Created` is the file's creation date
and never changes afterward. The header goes above `from __future__ import
annotations`, which must stay the first statement after it.

### Everything else

- Type-annotate public functions and dataclass fields. `from __future__ import
  annotations` is used throughout, so `str | None` is fine on 3.10.
- Docstrings explain **why**, not what — the code says what. If a design choice
  is non-obvious or a constraint is load-bearing, write it down; that's the
  cheapest documentation in the repo.
- Dataclasses over dicts for anything with a shape (see
  [`appsec/config.py`](appsec/config.py),
  [`appsec/models/findings.py`](appsec/models/findings.py)).
- **`appsec/models/` is pure stdlib.** Don't add a dependency there.
- New runtime dependencies need a reason in the PR description. The install
  surface is deliberately small.

## Non-negotiables

These are the properties PHRAK claims in its README and `SECURITY.md`. A PR that
breaks one won't be merged, however useful it is otherwise:

1. **Agents are read-only.** `code_review`, `threat_model`, and `test_case` read
   source and write reports. No HTTP tool, no script execution, no target
   traffic. `test_case` emits a *plan*; PHRAK never runs it.
2. **No network without explicit opt-in.** The only exception is the guarded
   `git_clone` tool (`enable_git_clone`, off by default) under the same rules as
   `phrak clone`: HTTPS/SSH only, shallow, hooks disabled, size-capped, confined
   to `<workspace>/clones`.
3. **PHRAK never scans or attacks remote hosts, and does not use Nuclei.**
4. **OpenGrep is the sole static analyzer.** No CodeQL or Joern
   integrations — those PRs get closed. New *analyzers* are welcome as
   `AnalyzerAdapter` implementations (see
   [`appsec/analyzers/base.py`](appsec/analyzers/base.py)) as long as they're
   deterministic and normalize into `SecurityFinding`.
5. **File tools stay sandboxed** to the workspace root, and `subprocess` is never
   called with `shell=True` on model-controlled input. Argument-list only.
6. **Secrets stay in `.phrack/credentials`** (mode `0600`), redacted from
   `config --show`, passed to SDKs via env var — never into a prompt, report, or
   the RAG index.
7. **The human is never auto-answered.** `ask_user` / `request_permission` always
   pause. There is no auto-grant mode and no flag to add one.
8. **Findings stay evidence-grounded.** Everything goes through validate → ground
   → dedup → record. A data-flow finding cannot be `confirmed` without a
   `complete` or `runtime_confirmed` taint path, and confidence is a static
   heuristic — never presented as a probability of exploitability.
9. **The agent set is settled**: `code_review`, `threat_model`, `test_case`. An
   exploit-development agent was deliberately removed and is not coming back —
   please don't propose re-adding one.

## Extending PHRAK

The seams designed for extension, easiest first:

- **A skill** — drop a markdown file in `appsec/skills/<agent>/`. Curated
  procedural guidance an agent can `load_skill` on demand. No code needed.
- **A tool** — add it under `appsec/tools/`, build it with the shared sandbox
  helpers in [`appsec/tools/common.py`](appsec/tools/common.py), and wire it into
  an agent's tool list. Respect invariants 1, 2, and 5.
- **An analyzer** — implement `is_available` / `supports` / `run` per
  [`appsec/analyzers/base.py`](appsec/analyzers/base.py) and normalize output to
  `SecurityFinding`. Analyzer output is *leads*: unverified by construction, with
  capped confidence, for an agent to confirm in source.
- **An agent** — build an `AgentSpec` in `appsec/agents/`, call
  `register_agent(...)`, import it in the package `__init__`. Read invariant 9
  first, and open an issue to discuss before writing it.

[`README.md`](README.md) has a project layout map at the bottom worth skimming.

## Pull requests

- **Branch off `main`**, one logical change per PR.
- **Keep mechanical churn in its own commit.** A reformat or a rename mixed into
  a logic change is unreviewable and poisons `git blame`. Formatting-only commits
  should say so in the subject.
- **Explain the why in the description.** What breaks without this, and what you
  considered instead.
- **Say what you tested.** Include the `pytest` result, and note if you ran
  against a real model or only the fakes.
- Update `README.md` when you change user-visible behaviour — flags, config keys,
  commands, or safety posture.
- Don't commit `.phrack/`, `venv/`, or anything containing real findings, client
  names, internal hostnames, or credentials. `.phrack/` is git-ignored for a
  reason.

Small, focused PRs get reviewed. Large refactors are best discussed in an issue
first — not because they're unwelcome, but because it's a shame to write one that
collides with an invariant above.

## License

By contributing, you agree your contributions are licensed under the project's
[MIT License](LICENSE).
