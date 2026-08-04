---
name: pasta-threat-analysis
when_to_use: Running the PASTA risk-centric threat analysis over the system.
---
# PASTA Threat Analysis

PASTA (Process for Attack Simulation and Threat Analysis) is a 7-stage,
risk-centric method. Work the stages in order; each feeds the next.

1. **Define objectives** — business goals and the security/compliance
   requirements that matter (what must not happen).
2. **Define technical scope** — the components, boundaries, and dependencies
   (pull from the System Architecture + Data Flow skills).
3. **Application decomposition** — map entry points, assets, data flows, and
   trust levels; identify who can reach what.
4. **Threat analysis** — enumerate relevant threats and threat actors; map to
   STRIDE per element and to MITRE ATT&CK techniques where useful.
5. **Vulnerability analysis** — correlate threats with actual weaknesses in the
   code (fold in code_review findings if available; cite file:line).
6. **Attack modelling** — build attack trees / chains: how an actor combines
   weaknesses to reach an objective. Produce the top 3-5 end-to-end attack paths.
7. **Risk & impact analysis** — score each threat (likelihood × business impact),
   prioritise, and recommend countermeasures.

Output the per-threat results via the Threat Details skill, and the prioritised
attack paths + recommendations for the report. Keep everything tied to real
components and evidence, not generic checklists.
