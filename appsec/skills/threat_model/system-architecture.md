---
name: system-architecture
when_to_use: Describing the system's components, tech stack, and trust boundaries.
---
# System Architecture

Ground the model in what the code actually is. Use fingerprint_stack,
analyze_dependencies, search_code, and read_file first.

Document:
1. **Components / processes** — services, apps, workers, jobs. Name each and its
   responsibility.
2. **Technology stack** — languages, frameworks, servers, datastores, queues,
   third-party/SaaS dependencies (with versions where known).
3. **Entry points** — HTTP routes, CLIs, message consumers, webhooks, scheduled
   tasks. These are the attack surface.
4. **Data stores** — databases, caches, file/object storage, secrets stores; note
   what sensitive data each holds.
5. **External dependencies** — APIs and services the system trusts.
6. **Trust boundaries** — where data crosses a privilege/network/ownership change
   (internet↔app, app↔db, service↔service, tenant↔tenant). Number them (TB1,
   TB2, …); the Data Flow and Threat Details skills reference these numbers.

Base every statement on code you read; mark anything inferred as an assumption.
