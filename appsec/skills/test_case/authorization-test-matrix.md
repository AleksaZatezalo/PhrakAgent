---
name: authorization-test-matrix
when_to_use: Systematically testing access control by crossing every role against every protected resource/action.
---
# Authorization Test Matrix

Access-control bugs (IDOR, missing function-level checks, privilege escalation)
are found by *systematic* coverage, not spot checks. Build a matrix and write a
test for each meaningful cell.

1. **Enumerate the axes** from the code:
   - **Subjects** — every role/privilege level, plus **unauthenticated** and
     **another user of the same role** (for horizontal checks).
   - **Objects** — every protected resource/action: routes/handlers, record types
     with owner/tenant scoping, admin functions, state-changing operations.
2. **Fill expected outcomes** — for each (subject, object) cell, what *should*
   happen (allow / deny) per the intended policy.
3. **Test each cell that should DENY** — those are the vulnerabilities:
   - **Vertical escalation** — a lower role invoking a higher-privileged
     action/route.
   - **Horizontal escalation / IDOR** — user A requesting user B's object by
     swapping an id in the path/query/body; assert it's rejected, not returned.
   - **Unauthenticated access** — hit the endpoint with no session/token.
   - **Forced browsing** — a route not linked in that role's UI but still routed.

Oracle: a correct deny is an authorization error (401/403) or "not found" —
**not** a UI hiding the control and **not** the object's data. Getting B's record
back, or the action succeeding, is a `fail` (vulnerable).

Record each cell as a test case (title names subject→object, target is the exact
endpoint+parameter, steps carry the wrong-identity request, expected = denied),
and link it to the finding/threat it verifies. Note any cell you couldn't test
(role you can't obtain) so coverage stays honest.
