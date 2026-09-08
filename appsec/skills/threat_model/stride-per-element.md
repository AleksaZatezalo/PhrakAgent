---
name: stride-per-element
when_to_use: Eliciting threats systematically by applying STRIDE to each DFD element by type.
---
# STRIDE per Element

Turn the DFD from the Data Flow / System Architecture skills into threats
systematically: each element type is susceptible to a specific subset of STRIDE,
so you elicit the right threats instead of guessing.

Applicability by element type:

| Element | S | T | R | I | D | E |
|---------|:-:|:-:|:-:|:-:|:-:|:-:|
| External entity (user, 3rd-party) | ✔ | | ✔ | | | |
| Process (service, handler, worker) | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| Data store (DB, cache, files, queue) | | ✔ | ✔ | ✔ | ✔ | |
| Data flow (network call, IPC, channel) | | ✔ | | ✔ | ✔ | |

Prompting questions per category:
- **Spoofing** — can the identity of this entity/process be forged? Is authn
  enforced at this boundary, or assumed?
- **Tampering** — can data in this store/flow be modified in transit or at rest?
  Integrity check? TLS? Signed?
- **Repudiation** — is there an audit trail tying this action to an actor, or can
  it be denied later?
- **Information disclosure** — what sensitive data does this element hold/carry,
  and who can read it they shouldn't?
- **Denial of service** — can this element be exhausted or crashed (unbounded
  input, no rate limit, expensive op)?
- **Elevation of privilege** — can an actor gain rights here they shouldn't
  (missing authz, trusting client-supplied role/tenant)?

Work each element × its applicable columns, favouring the ones that cross a
**trust boundary** (that's where the real threats live). Emit each threat you
find through the **Threat Details** skill (one row, tied to the element id and,
where relevant, an attack-path id), and skip cells with no plausible threat
rather than manufacturing filler.
