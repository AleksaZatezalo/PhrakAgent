---
name: Detection quality (false positive / missed finding)
about: PHRAK reported something that isn't real, or missed something that is
title: ''
labels: detection
assignees: ''
---

<!--
This is the right place for both false positives and false negatives. SECURITY.md
explicitly routes them here: they're detection-quality bugs, not vulnerabilities
in PHRAK.

Keep in mind by design: analyzer output is *leads* with capped confidence, RAG
retrieval is not proof of reachability, and confidence is a static heuristic —
not a probability of exploitability. A low-confidence lead that turned out wrong
may be working as intended; a *confirmed* finding that's wrong is a real bug.
-->

## Which is it

- [ ] **False positive** — PHRAK reported a vulnerability that isn't there
- [ ] **False negative** — PHRAK missed a real vulnerability

## The finding

- Finding ID (`FND-…`), if you have one:
- Title / vulnerability class + CWE:
- Reported severity and confidence:
- Status shown (`new` / `confirmed` / `unconfirmed` / …):
- Which agent produced it (`code_review` / `threat_model` / `test_case`):
- Which tool fed it, if known (Opengrep, dependency audit, model reasoning):

## Minimal code that reproduces it

<!--
The most useful thing you can attach. A short, self-contained, publishable
snippet — not your real codebase. If the trigger is framework-specific, say
which framework and version.
-->

```python

```

## Why it's wrong

<!--
False positive: what makes the flagged path safe? A sanitizer PHRAK didn't
recognize, an unreachable branch, a validated input, a framework guarantee?

False negative: where is the real vulnerability, and what should the source →
sink path have been?
-->

## What PHRAK output

<!-- Paste the rendered finding, including its taint path / evidence section. -->

```

```

## Environment

- PHRAK version (`phrak --version`):
- Model provider and model: <!-- detection quality tracks the local model heavily -->
- Opengrep version, if it was involved:

<!--
Scrub before posting: publishable snippets only — no client code, no internal
paths or hostnames, no credentials.
-->
