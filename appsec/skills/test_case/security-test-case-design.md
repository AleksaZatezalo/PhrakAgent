---
name: security-test-case-design
when_to_use: Writing an individual security test case in the standard, reviewable shape.
---
# Security Test-Case Design

A good security test case is unambiguous, reproducible, and tied to a real issue.
Write EACH one in this shape:

- **ID** — `TC-001`, `TC-002`, … (stable, referenced elsewhere).
- **Title** — one line naming the weakness and where (e.g. "SQL injection via
  `/user?id`").
- **Linked to** — the code_review finding (CWE / file:line) or threat_model
  threat/attack-path this verifies. Every test traces back to something real.
- **Target** — the exact reachable surface: endpoint + method + parameter, or
  `file:line` / function for a code-level test.
- **Preconditions** — required state: auth level (anonymous / user / admin),
  seeded data, feature flags, the app running locally.
- **Steps** — numbered, concrete actions with a specific payload/input. Prefer a
  real value (`id=1 OR 1=1`, `../../etc/passwd`) over "malicious input".
- **Expected result** — what proves the issue PRESENT vs ABSENT. State both:
  "vulnerable if the query returns other users' rows; safe if it 400s / returns
  only id=1". A test with no observable oracle is not a test.
- **Severity** — Critical / High / Medium / Low, inherited from the linked
  finding/threat.

Rules:
- One weakness per test case. Split "SQLi and XSS on the same endpoint" into two.
- Make it runnable by a human with no extra context — no "test the auth" hand-waving.
- Only reference endpoints/params/functions you confirmed exist by reading the
  code. If you can't locate the sink, say so in Coverage rather than inventing one.
