<!-- PHRAK Agent — findings log -->

# Findings attributed to PHRAK

A running log of real security findings discovered with **PHRAK Agent**, in
third-party or first-party code, and what happened to each one after it left the
tool.

This file is the human-curated, public half of PHRAK's finding history. The
machine half lives per-workspace in `.phrack/findings/` (see
[`appsec/store.py`](appsec/store.py)) and is **never** committed — it contains
paths, snippets, and evidence from whatever repo you pointed PHRAK at. An entry
only lands here once it is safe to publish: the affected project has fixed it,
disclosed it, or agreed to disclosure, or the target is your own code.

> **Reporting a vulnerability *in PHRAK itself*** → see [`SECURITY.md`](SECURITY.md).
> This file is about vulnerabilities PHRAK *found*, not vulnerabilities it *has*.

## Ground rules

* **Nothing pre-disclosure.** No entry is added while a report is embargoed or
  unfixed and undisclosed. Coordinated disclosure first, log entry second.
* **Evidence or it doesn't count.** Every entry carries a `file:line` (or a
  taint source→sink) that a reader can check against the affected version.
* **PHRAK doesn't prove exploitability.** It is a static, read-only analyzer —
  it does not run exploits. `Confirmed` here means a human verified the code
  path (and, where noted, reproduced it manually); it is not a PHRAK verdict
  taken on faith. Confidence is a static heuristic, not a probability.
* **Credit the human.** PHRAK surfaced the lead; a person triaged, verified, and
  reported it. The `Reporter` column is who did that.
* **In-scope targets only.** Findings come from code you own, OSS you may lawfully
  analyze, or an engagement with authorization. See
  [`scope.example.yaml`](scope.example.yaml).

## Legend

Severity and status use PHRAK's own vocabularies, verbatim from
[`appsec/models/findings.py`](appsec/models/findings.py):

| Severity | `critical` · `high` · `medium` · `low` · `info` |
|---|---|
| **Status** | `new` · `confirmed` · `unconfirmed` · `false_positive` · `accepted_risk` · `fixed` |
| **Agent** | `code_review` · `threat_model` · `test_case` |

Status is the **effective** status — human triage outranks a runtime
observation, which outranks the reporting agent's claim
(`SecurityFinding.effective_status()`).

`ID` is the finding's stable PHRAK identifier (`FND-` + fingerprint prefix), so
the public entry and the local `.phrack/findings/` record refer to the same
thing across runs.

## Summary

| | Critical | High | Medium | Low | Info | Total |
|---|---|---|---|---|---|---|
| **Fixed** | 0 | 0 | 0 | 0 | 0 | 0 |
| **Confirmed (open)** | 0 | 0 | 0 | 0 | 0 | 0 |
| **Accepted risk** | 0 | 0 | 0 | 0 | 0 | 0 |
| **Total** | 0 | 0 | 0 | 0 | 0 | **0** |

CVEs / advisories assigned: **0**

## Findings

| ID | Target | Class (CWE) | Severity | Status | Agent | Advisory | Reported | Fixed |
|---|---|---|---|---|---|---|---|---|
| _no published findings yet_ | | | | | | | | |

<!--
Row template — copy, fill, keep newest at the top:

| [`FND-a1b2c3d4e5`](#fnd-a1b2c3d4e5) | acme/widget-api v2.3.1 | SQL injection (CWE-89) | `high` | `fixed` | `code_review` | [CVE-2026-1234](https://nvd.nist.gov/vuln/detail/CVE-2026-1234) | 2026-08-04 | 2026-08-19 |
-->

## Details

<!--
Detail template — one section per finding, newest first. Delete the fields that
don't apply; do not invent a taint path PHRAK didn't produce.

### FND-a1b2c3d4e5 — SQL injection in the report export endpoint

| | |
|---|---|
| **Target** | [acme/widget-api](https://github.com/acme/widget-api) @ `v2.3.1` (commit `deadbee`) |
| **Class** | SQL injection — CWE-89, OWASP A03:2021 |
| **Severity** | `high` |
| **Status** | `fixed` (agent=`confirmed`, human=`confirmed`) |
| **Confidence** | 0.85 (static heuristic) |
| **Found by** | `code_review` — leads from Opengrep, verified in source |
| **Reporter** | @your-handle |
| **Advisory** | CVE-2026-1234 / GHSA-xxxx-xxxx-xxxx |
| **Timeline** | reported 2026-08-04 → triaged 2026-08-06 → fixed in `v2.3.2` 2026-08-19 → disclosed 2026-09-02 |

**Evidence**

- `api/reports.py:142` — `request.args["order"]` reaches the query unescaped
- `api/db.py:88` — f-string interpolation into `execute()`

**Taint path** (`inter_procedural`, completeness `complete`)

1. source — `api/reports.py:142` — `request.args["order"]`
2. `api/reports.py:151` — call → `build_query(order)`
3. sink — `api/db.py:88` — `cursor.execute(sql)`

Sanitizers: none observed.

**Impact** — Any authenticated user can read arbitrary rows from other tenants.

**Fix** — Parameterized query + an allowlist for sortable columns
([`acme/widget-api#412`](https://github.com/acme/widget-api/pull/412)).

**What would disprove this** — If `build_query` were only ever reached with a
value already validated against the column allowlist.

---
-->

## Not findings

Leads PHRAK raised that triage killed. Kept deliberately: a tool's false
positives are as much a part of its track record as its hits, and this is where
detection gets tuned.

| ID | Target | Claimed | Why it isn't real |
|---|---|---|---|
| _none logged yet_ | | | |

## Adding an entry

1. Triage the finding locally: `/findings` in the PHRAK REPL, then record the
   human verdict so `.phrack/findings/` reflects reality.
2. Report it upstream. **Wait** for a fix or an agreed disclosure date.
3. Add the summary row and a `## Details` section here, then bump the
   **Summary** table.
4. Scrub before committing: no client names, no internal hostnames, no
   credentials, no snippets from code you can't publish.
