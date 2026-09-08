<!-- PHRAK Agent — findings, triage, test cases, and the report -->

# Findings, triage, test cases & the report

> Part of the [PHRAK Agent documentation](../README.md#documentation).

Steps 3–5 of the [workflow](../README.md#the-workflow) — triage what came back,
work the test plan, assemble the deliverable. Steps 3 and 4 involve **no model**.

## Triage findings

Agents write every finding into a durable, fingerprint-keyed store under
`.phrack/findings/` — so a finding keeps its identity across runs, and your
verdict on it survives the next scan. `/findings` and `phrak findings` are the
read/triage side of that store:

```bash
phrak findings                                  # the whole backlog, newest first
phrak findings --severity high --status new     # filter by severity / status
phrak findings --resurfaced                     # evidence changed since your verdict
phrak findings FND-284b4aac0d                   # full detail + status history + notes
phrak --json findings                           # machine-readable, for a CI gate
```

In chat, `/triage <id> <status> [note]` records a **human** verdict — one of
`new`, `confirmed`, `unconfirmed`, `false_positive`, `accepted_risk`, `fixed`.
Human triage is the authority of last resort: it can move a finding anywhere,
it's kept on a separate track from the agent's own status, and it is preserved
when a later run re-observes the same finding.

If a re-run turns up materially stronger evidence for something you'd dismissed
(confidence jumped, severity changed, or a supporting taint path newly appeared),
the record is flagged **⟲ re-surfaced**. `--resurfaced` lists exactly those, and
your next `/triage` clears the flag. An `<id>` can be the full finding id, its
fingerprint, or a unique prefix of either.

**Findings you found yourself.** `/finding-add` (or `phrak add-finding`) records
one you verified by hand — **no model is involved** — landing on the **human**
track as `confirmed`:

```bash
phrak add-finding --title "Auth bypass on /admin" --category "broken access control" \
  --severity critical --file app/views.py --line 88 --cwe CWE-862
```

The id is derived from the finding's own content (category + location + title),
so if an agent later reports the same issue the two converge onto **one** record
rather than duplicating — and your verdict is the one that sticks. If the path
doesn't resolve in the workspace you get a warning, not a downgrade.

## Test cases

The `test_case` agent authors a manual test plan; the backlog is where **you**
work it. Every test case is a tracked item with a generated `TC-…` id, a status,
an optional result, notes, and a link to the finding it verifies.

```bash
phrak testcases                        # the checklist
phrak testcases --status in_progress   # what you're mid-way through
phrak testcases --finding FND-9c41ba22e0   # tests covering one finding
phrak testcases --unlinked             # tests not tied to any finding
phrak testcases TC-4751bf44            # one test case in full
phrak --json testcases                 # for a tracker import
```

```
3 test case(s) — 1 complete, 1 in progress, 1 new:
☑ TC-4751bf44  [critical] complete     [fail]     SQLi via uid            verifies FND-c3deed9c78
◐ TC-a1b2c3d4  [high    ] in_progress             Auth bypass on /admin   verifies FND-9c41ba22e0
☐ TC-9f8e7d6c  [medium  ] new                     Rate limit on /login    verifies —
```

Working the list, in chat:

```
/testcase-status TC-4751bf44 complete fail     # 'fail' = the app was vulnerable
/testcase-note   TC-4751bf44 reproduced with a single quote in uid
/testcase-link   TC-9f8e7d6c FND-9c41ba22e0    # tie it to the finding it verifies
```

Statuses are `new`, `in_progress`, `complete`. Results are `pass`, `fail`,
`blocked`, `inconclusive` — **`fail` means the test found the app vulnerable**.
`/testcase-link` refuses an id that doesn't exist, so a typo surfaces immediately.
**Add your own** with `/testcase-add` (or `phrak add-testcase`), no model
involved:

```bash
phrak add-testcase --title "Rate limit on /login" --target "POST /login" \
  --steps "send 100 requests in 10s | observe throttling" \
  --expected "requests are rejected after N" --severity medium
```

**Re-running `test_case` never costs you progress** — a re-authored test keeps
its status, result, notes and link; only the instructions are refreshed
(identity is derived from title + target). **Every finding gets a test case:**
after a full `phrak run`, the orchestrator reconciles the backlog against the
findings store (`appsec/coverage.py`), links authored tests to the findings they
verify, and backfills a minimal verification test case for any finding —
confirmed or unconfirmed — that nothing else covers. The step is idempotent.

`test_case` is read-only and sends **no traffic to any target** — it hands you a
plan to run yourself, in your own authorised environment.

## The final report (`generate_report`)

`phrak report` (or `/generate_report`) assembles one deliverable:

| Section | Where it comes from |
|---------|---------------------|
| 1. Executive Summary | **Written by the model** — the only generated prose |
| 2. Threat Model | The latest `threat_model` report, quoted verbatim |
| 3. Code Review | The latest `code_review` report, quoted verbatim |
| 4. Findings | Rendered from `.phrack/findings/`, severity-ordered |
| 5. Test Cases | Rendered from `.phrack/testcases/`, with your progress |

```bash
phrak report                              # render to the terminal
phrak report "pre-release audit"          # add a scope note to the header
phrak report --out ./assessment.md        # write it to a file
```

**Only the executive summary is generated.** Everything else is quoted or
rendered from artifacts that already exist, because a model asked to "summarize
the code review" paraphrases — and a paraphrased finding drifts from the
`file:line` evidence the report rests on. A full `phrak run` leaves the material
this report needs: each specialist's own output is saved as its own
`report-<ts>-<agent>.md`. The report is honest about gaps — if `threat_model`
has never been run the section says so and names the command to fix it; if the
model is unreachable the summary is replaced by a factual stub while every
assembled section survives intact. `generate_report` is excluded from the
planner, so `phrak run` can never schedule it before the findings exist.

## Structured findings model

`appsec/models/findings.py` provides a typed `SecurityFinding` (with
`FindingEvidence` and `TaintPathReference`/`TaintNode`/`TaintStep`) representing
findings with evidence, CWE/OWASP tags, confidence, status, and validated taint
paths. It supports **stable fingerprints** (same vuln recognized across runs),
**validation** (confidence bounds, enums, workspace-grounded evidence, and the
rule that a data-flow finding can't be `confirmed` without a supporting taint
path), **separate status tracks** (`agent` / `runtime` / `human`, folded into one
`effective_status` with human precedence), and **serialization + Markdown render
+ dedup**. `report_finding` REJECTS structurally-invalid input and **downgrades**
ungrounded evidence to `unconfirmed` — it never silently upgrades a model claim.

### Sample structured finding (Markdown render)

```
### SQL injection in /user  `FND-ab12cd34ef`

Severity: High
Confidence: 0.91
Status: Confirmed
CWE: CWE-89
OWASP: A03:2021-Injection

Source:
- app/routes.py:44 — request.args['id']

Sink:
- app/db.py:91 — cursor.execute(q)

Taint path:
1. app/routes.py:44 — assignment
2. app/db.py:91 — call

Sanitizers:
- None observed

Evidence:
- app/routes.py:40-48 — untrusted query parameter
- app/db.py:84-96 — string-formatted SQL passed to execute()
```

## Findings history & scope

Findings and taint paths persist per workspace so PHRAK can answer "is this new
or known?" and keep triage decisions:

- **Persistent history** — every run upserts into `.phrack/findings/` and
  `.phrack/taint/` (JSONL), keyed by fingerprint, tracking first/last seen, a
  per-run log, status changes, and reviewer notes. A human verdict survives
  re-runs; a materially-changed re-observation is flagged `⟲ re-surfaced`.
- **Concurrency-safe** — the DAG runs agents in parallel and each persists at the
  end of its run, so every read-modify-write is serialized (a thread lock plus an
  advisory file lock covering two `phrak` processes on one workspace) and every
  write lands via atomic rename. No agent's findings can be dropped by another,
  and a crash mid-write can't truncate the store.
- **Triage tracks** — `runtime` and `human` verdicts are recorded separately from
  the reporting agent's claim. Browse and triage with `phrak findings` /
  `/findings`, or read `.phrack/findings/findings.jsonl` directly.
- **Scope policy** — an optional `<workspace>/.phrack/scope.yaml` makes "what am I
  allowed to touch" declarative (`allowed_hosts` / `allowed_ports` / path prefixes
  / `rate_limit_per_min`). It can only **narrow** what's already permitted — the
  loopback-only floor is always enforced first. See
  [`scope.example.yaml`](../scope.example.yaml).
- **Public log** — `.phrack/` never leaves your machine, so real findings worth
  publishing get curated by hand into [`FINDINGS.md`](../FINDINGS.md).
