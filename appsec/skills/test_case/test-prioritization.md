---
name: test-prioritization
when_to_use: Ordering the test cases by risk and recording finding/threat traceability.
---
# Test Prioritization & Traceability

Order the test cases so the operator spends effort where it matters, and make it
obvious what each test verifies.

**Prioritize** by:
1. **Severity** of the linked finding/threat (Critical → Low).
2. **Confidence** — a Critical hypothesis that is cheap to check outranks a
   near-certain Low. Verifying/killing a scary unknown fast is high value.
3. **Reachability** — pre-auth / anonymous-reachable issues before ones needing
   admin or an unusual precondition.
4. **Blast radius** — RCE / auth bypass / full-DB read above single-record leaks.

Produce an explicit **execution order**: the TC ids in the order to run them,
highest risk first, so the reader has a ready-to-work checklist.

**Traceability** — give a small table mapping each test case back to what it
verifies:

| Test | Verifies (finding / threat) | Severity |
|------|-----------------------------|----------|
| TC-001 | code_review: SQLi `app.py:42` (CWE-89) | Critical |
| TC-002 | threat_model: T-03 auth bypass at boundary 2 | High |

Finally, note **gaps**: any finding or threat you could NOT write a test for
(e.g. sink not locatable, needs infra you can't assume) so coverage is honest.
