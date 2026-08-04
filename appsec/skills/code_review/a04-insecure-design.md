---
name: a04-insecure-design
when_to_use: Reviewing design-level flaws that no amount of clean code fixes.
---
# A04: Insecure Design

Missing or flawed security controls in the design itself (not an implementation bug).

Look for:
- Missing rate limiting / anti-automation on sensitive actions (login, OTP,
  password reset, payment) → credential stuffing, enumeration, brute force.
- Business-logic flaws: negative quantities, price/qty tampering, race conditions
  in "check then act" (TOCTOU), workflow steps that can be skipped.
- Trust placed in client-side controls or hidden fields.
- No segregation of tenants/roles by design; recoverable "security questions".
- Absence of a control the domain requires (e.g. no re-auth for fund transfer).

Confirm: describe the abuse case and show the design lacks the control (not just a
buggy check) — often the absence of code rather than wrong code.

Report: the abuse scenario, the missing control, and the design change (add the
control, threat-model the flow, enforce limits/invariants server-side).
