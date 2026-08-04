---
name: data-flow
when_to_use: Building the Data Flow Diagram (DFD) and marking trust boundaries.
---
# Data Flow

Produce a text-based DFD that later threats attach to. Use the DFD element types:

- **External entities** — users, third-party systems, admins (sources/sinks
  outside your control).
- **Processes** — code that transforms data (each numbered: P1, P2, …).
- **Data stores** — where data rests (D1, D2, …).
- **Data flows** — arrows between the above, each labelled with WHAT data moves
  and over what channel (e.g. "P1 → D1: user record over TLS").

Then overlay **trust boundaries** (TB1, TB2, … from the System Architecture
skill): draw them where a flow crosses a privilege or network change.

Format as a readable list/table, e.g.:

```
External: Browser (E1), Payment API (E2)
Processes: Web app (P1), Auth service (P2)
Stores:    User DB (D1), Session cache (D2)
Flows:
  F1  E1 → P1   login credentials        [crosses TB1: internet→app]
  F2  P1 → P2   auth request             [crosses TB2: app→service]
  F3  P2 → D1   read password hash
```

Every flow that crosses a trust boundary is a prime candidate for STRIDE analysis.
