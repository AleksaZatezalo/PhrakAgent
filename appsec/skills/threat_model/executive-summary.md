---
name: executive-summary
when_to_use: Writing the top-level summary of the threat model for leadership.
---
# Executive Summary

Write 4-8 sentences a non-specialist decision-maker can act on. Produce this
LAST, after the analysis, but present it FIRST.

Include:
1. **What the system is** and the assessment scope (one sentence).
2. **Overall risk posture** — a qualitative rating (Critical / High / Medium /
   Low) with a one-line justification.
3. **The 3-5 most serious risks** in plain language, each tied to a business
   impact (data breach, downtime, fraud, compliance), not a CWE number.
4. **The single most important action** to take next.

Rules:
- No jargon, no STRIDE letters, no tool names. Impact and likelihood in business
  terms.
- Every claim must trace back to a specific threat in the Threat Details table.
- Quantify where possible ("3 Critical, 5 High findings across the auth and
  payment flows").
