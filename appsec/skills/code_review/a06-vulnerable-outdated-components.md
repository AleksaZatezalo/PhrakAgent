---
name: a06-vulnerable-outdated-components
when_to_use: Reviewing dependencies for known-vulnerable / outdated components.
---
# A06: Vulnerable and Outdated Components

Using libraries/runtimes with known vulnerabilities.

Look for (use analyze_dependencies):
- Dependency manifests (requirements.txt, package.json, go.mod, pom.xml, …) and
  pinned versions.
- Old major versions of frameworks/libraries with known CVEs.
- Unmaintained / abandoned packages; transitive deps pulled without pinning.
- Unpinned or wildcard versions (`*`, `latest`) → non-reproducible, drift.
- End-of-life language/runtime versions.

Confirm: name the component + version and why it's risky (known CVE class or EOL).
You can't run a live CVE feed offline, so flag the version and recommend a scan
(pip-audit / npm audit / osv-scanner) rather than inventing CVE numbers.

Report: the component@version, the risk, and the fix (upgrade to a fixed release,
pin versions, add dependency scanning to CI, remove unused deps).
