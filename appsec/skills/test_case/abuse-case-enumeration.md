---
name: abuse-case-enumeration
when_to_use: Adding negative / abuse test cases beyond the confirmed findings.
---
# Abuse-Case Enumeration

Confirmed findings tell you what's already known-broken. Abuse cases probe what
*might* be, so the operator's manual pass covers more than the automated leads.

For each entry point you find in the code, ask "how would an attacker misuse
this?" and write a test for the answer:
- **Auth / session** — reuse an expired/other user's token, skip a step in a
  multi-stage flow, hit a protected route with no session, tamper a JWT `alg`.
- **Access control (IDOR)** — swap an id/owner reference to another user's
  resource; assert it is denied, not returned.
- **Input handling** — oversized input, unexpected type, null bytes, encoding
  tricks (double-URL-encode, unicode), missing/duplicate parameters.
- **Business logic** — negative quantities/amounts, race on a
  check-then-act, replay of a one-time action, out-of-order state transitions.
- **Resource abuse** — no rate limit on login/expensive endpoints; unbounded
  file upload / pagination.

Keep each abuse case a real, reachable scenario grounded in code you read — not a
generic "fuzz everything". Mark abuse cases (vs finding-verification cases) so
the operator knows which ones are exploratory.
