<!-- PHRAK Agent — the verify agent -->

# The `verify` agent (opt-in)

> Part of the [PHRAK Agent documentation](../README.md#documentation).

Every other agent is static and read-only. `verify` is the one that **executes
attacker input**, so it is off by default and has to be turned on deliberately:

```yaml
enable_verify: true          # .phrack/config.yaml
```

It only appears in the agent registry when that flag is set — otherwise the DAG
planner can't schedule it. It needs `docker` or `podman` on PATH; without one,
`run_poc` returns an install hint instead of falling back to the host.

**What it does.** It runs after `code_review`/`threat_model` and takes their
**confirmed data-flow findings** (SQLi, command injection, path traversal, unsafe
deserialization, SSRF against a controlled target), writes a short PoC for each,
and runs it in a container with `run_poc`. It may only confirm findings already
in the run's ledger; discovery is not its job. It records the verdict with
**`record_poc_result(finding_id, outcome, …)`**, which writes to the finding's
**runtime** status track:

| `outcome` | Effect on the finding |
|-----------|-----------------------|
| `confirmed` | Runtime track → `confirmed` (confidence raised) — a landed PoC is the strongest evidence there is |
| `false_positive` | Runtime track → `false_positive`; never re-marked confirmed |
| `inconclusive` | Status unchanged, a note is attached (needs a full app stack / out of scope) |

The runtime track folds into the finding's `effective_status` **above** the
agent's status but **below** a human triage decision (human > runtime > agent).

## The sandbox

Every PoC runs via `docker run --rm` (or podman) with:

| Flag | Effect |
|------|--------|
| `--network none` | No network at all (`verify_network`; `bridge` only if you set it) |
| `--read-only` + `--tmpfs /tmp` | Immutable rootfs; scratch space is 64 MB of tmpfs |
| `--user 65534:65534` | Runs as `nobody`, never root |
| `--cap-drop ALL`, `--security-opt no-new-privileges` | No capabilities, no privilege escalation |
| `--memory`, `--pids-limit` | Memory and process caps (`verify_memory_mb`, `verify_pids`) |
| `-v <workspace>:/workspace:ro` | Workspace mounted **read-only**, and only when the PoC asks for it |
| wall-clock kill | Hard timeout (`verify_timeout_s`, default 30s) |

**This is a real trade-off, not a solved problem.** You are running
model-authored attacker code. The sandbox is a strong boundary, not a proof —
container escapes exist. Leave `verify` off unless you want that trade, and run
it against code you're authorised to test. See the
[Safety posture](../README.md#safety-posture) for the full guarantee set.
