---
name: Feature request
about: Suggest a capability, tool, analyzer, or skill
title: ''
labels: enhancement
assignees: ''
---

<!--
Worth a look first — CONTRIBUTING.md has a "Non-negotiables" section, and a few
things are settled rather than undecided:

  * agents are read-only, no target traffic, no HTTP tool
  * no network access without explicit opt-in
  * PHRAK never scans or attacks remote hosts, and does not use Nuclei
  * Opengrep is the sole static analyzer — no Semgrep / CodeQL / Joern
  * the agent set is code_review / threat_model / test_case; an exploit-development
    agent was deliberately removed and isn't coming back

New *analyzers* (as AnalyzerAdapter implementations), tools, and skills are all
welcome inside those bounds.
-->

## The problem

<!-- What are you trying to do that PHRAK makes hard or impossible today? -->

## What you'd like

## Which seam does this fit

- [ ] A **skill** — markdown guidance in `appsec/skills/<agent>/`
- [ ] A **tool** — new agent capability under `appsec/tools/`
- [ ] An **analyzer** — deterministic `AnalyzerAdapter` normalizing to `SecurityFinding`
- [ ] An **agent** — a new specialist
- [ ] Core / CLI / config
- [ ] Not sure

## Does it stay local and read-only?

<!--
If it needs network access, executes anything, or sends traffic to a target, say
so explicitly and explain how it stays opt-in and guarded. This is the most
common reason a request can't be taken as-is.
-->

## Alternatives you considered

<!-- Including "do it outside PHRAK" — sometimes that's the right answer. -->

## Are you offering to build it

- [ ] Yes, if the approach is agreed
- [ ] No, just proposing
