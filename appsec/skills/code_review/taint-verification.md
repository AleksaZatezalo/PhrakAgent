---
name: taint-verification
when_to_use: Confirming or downgrading an analyzer/pattern lead by tracing the data flow in the real code.
---
# Taint Verification

A lead (from `opengrep_taint_scan`, `opengrep_scan`, `scan_secrets`, or your own
read) is a hypothesis. Confirm it by tracing the actual data flow before you call
it `confirmed` — and downgrade honestly when you can't.

Trace, in order:
1. **Source** — the untrusted entry point (request param/body/header, CLI arg,
   env, file, message field, DB row an attacker can influence). Name it with
   file:line.
2. **Propagation** — follow the value through assignments, function args, returns,
   and object fields with read_file/search_code. Note any transformation.
3. **Sink** — the dangerous operation (query exec, command, deserialize, file
   open, redirect/fetch, template render). Name it with file:line.
4. **Sanitizers/defenses on the path** — parameterisation, escaping, allowlists,
   type coercion, canonicalisation, authz. Use `check_sanitizer` before deciding
   a defense actually neutralises THIS sink (HTML-escape ≠ SQL-safe; a prefix
   check before canonicalisation is bypassable).

Verdict rules:
- **Confirmed** only when you have an unbroken source→sink path AND no effective
  sanitizer on it. A data-flow finding **cannot** be `confirmed` without a
  supporting taint path — cite each node.
- **Unconfirmed** when the source, path, or sink can't be fully located, the sink
  is outside taint-covered languages (Python/JS-TS), or an effective mitigation
  might apply — report it as a lead, not a fact.
- Never upgrade on confidence alone. If unsure, say why (the exact missing link).

Report: source→sink with file:line for each node, a concrete triggering input,
the reason no defense stops it (or which defense you couldn't rule out), and the
fix at the sink.
