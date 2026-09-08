<!-- PHRAK Agent — static analysis -->

# Static analyzer: OpenGrep

> Part of the [PHRAK Agent documentation](../README.md#documentation).

`code_review` runs **OpenGrep** as its deterministic lead source, then verifies
every hit by reading the code:

- **`opengrep_taint_scan`** — OpenGrep in **taint mode** with PHRAK's bundled
  ruleset (`appsec/analyzers/rules/taint/`), tracing source→sink dataflow. These
  are the **confirmed leads**: a hit carries an actual path from untrusted input
  to a dangerous sink.
- **`opengrep_scan`** — fast pattern-based rules across many languages
  (`--config auto`). Returns `file:line [severity] rule -> message`. **Unconfirmed
  leads** to verify in source.
- **`scan_secrets`** — OpenGrep's secrets ruleset, for hardcoded credentials/keys.

**Bundled taint-rule coverage is deliberately narrow** — hand-written rules that
hold up, not breadth:

| Language | Rules |
|----------|-------|
| Python | SQL injection, command injection, path traversal, SSRF, unsafe deserialization |
| JavaScript / TypeScript | SQL injection, command injection, SSRF |

Anything outside that table gets no taint trace — pattern rules and the agent's
own source reading are the fallback, both producing `unconfirmed` findings. Since
a data-flow finding **cannot be marked `confirmed` without a supporting taint
path**, a SQLi in Ruby or Java surfaces as a lead and stays one. Point `--config`
at your own rules to extend this.

OpenGrep is PHRAK's **sole** static analyzer (the earlier CodeQL/Joern setup has
been removed). It's **optional and degrades gracefully**: if the binary isn't on
PATH it returns an install hint instead of failing the run.

```bash
# Linux/macOS — official installer puts `opengrep` on PATH:
curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
opengrep --version
```

PHRAK resolves the binary from `$PHRAK_OPENGREP_BIN` if set, otherwise `opengrep`
on PATH. Rules come from `--config`: `auto` (default), a registry id
(e.g. `p/owasp-top-ten`), or a **path to a local rules file/directory** for
fully-offline scans.

## Normalized output

Each analyzer is an **`AnalyzerAdapter`** (`appsec/analyzers/`) that normalizes
results into the same structured `SecurityFinding` an agent reports by hand, run
through one `validate → ground → dedupe` pipeline:

- **`analyzer_scan`** — OpenGrep hits recorded as workspace-grounded `unconfirmed`
  leads, deduped with anything you later confirm.
- **`dependency_audit`** — known-vulnerable dependency versions via `pip-audit` /
  `npm audit` / `govulncheck` / `cargo audit` (each optional), normalized into a
  `vulnerable-dependency` finding with advisory id, severity, CWE, and fix version.
- **`check_sanitizer`** — a context-sensitive effectiveness table so the reviewer
  doesn't dismiss a bug on a false-sanitizer assumption: HTML-escape ≠ SQL-safe,
  `urlparse` ≠ SSRF-safe, `shlex.quote` is fragile with `shell=True`, a prefix
  check *before* canonicalization is bypassable, and authentication ≠ authorization.
