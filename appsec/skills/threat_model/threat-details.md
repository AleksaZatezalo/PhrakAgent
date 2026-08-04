---
name: threat-details
when_to_use: Detailing every identified threat in a consistent, traceable table.
---
# Threat Details

The evidentiary core of the model: one row per threat, so each risk in the
Executive Summary and each step in an attack path is fully specified.

For EVERY threat, record:

| Field | Content |
|-------|---------|
| ID | T-01, T-02, … (stable, referenced elsewhere) |
| Element | The DFD element or flow affected (P1, F2, TB1, …) |
| STRIDE | Spoofing / Tampering / Repudiation / Info disclosure / DoS / Elevation |
| Threat | Concrete description — attacker, action, and what breaks |
| Attack vector | How it's reached (entry point + preconditions) |
| Likelihood | High / Med / Low + one-line rationale |
| Impact | High / Med / Low, in business terms |
| Existing mitigations | What the code already does (cite file:line) |
| Recommended mitigation | The specific fix / control to add |
| Evidence | file:line or observed behaviour backing the threat |

Rules:
- One threat per row; split compound threats.
- Tie every threat to a real element from the Data Flow / Architecture skills.
- Prefer precision over volume — a confirmed, evidenced threat beats a generic one.
- Threats that chain into an attack path must reference the path ID.
