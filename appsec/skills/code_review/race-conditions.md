---
name: race-conditions
when_to_use: Reviewing concurrent access to shared state — check-then-act, TOCTOU, and non-atomic updates.
---
# Race Conditions & TOCTOU

Bugs that only appear when two operations interleave. Not in the OWASP top-level
categories, but common and high-impact (double-spend, auth bypass, privilege
escalation, file clobbering).

Look for:
- **Check-then-act** — a validation followed by a use, with a window between:
  balance/quota/limit checked, then debited in a separate step; "does this
  username exist?" then insert; permission checked, then acted on later.
- **Non-atomic updates** — read-modify-write on a shared counter/balance/status
  without a transaction, row lock, or atomic DB operation (`UPDATE … SET x = x-1`).
- **TOCTOU on the filesystem** — `os.path.exists`/`access` then `open`; stat then
  use; a symlink swapped in between (privileged file writes).
- **Idempotency / double-submit** — endpoints that mutate state (checkout, coupon
  redeem, transfer) with no dedup token or unique constraint.
- **Missing locks** around shared in-memory state in a threaded/async server.

Confirm: identify the shared resource, the two operations, and the window between
them; show there is no lock, transaction, `SELECT … FOR UPDATE`, unique
constraint, or atomic op protecting it (cite file:line for both operations).

Report: the interleaving that breaks the invariant, a concrete two-request
scenario that triggers it, the impact, and the fix (atomic DB op / transaction +
row lock / unique constraint / idempotency key / open-then-check with O_EXCL).
