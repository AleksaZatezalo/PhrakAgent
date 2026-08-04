---
name: a01-broken-access-control
when_to_use: Reviewing authorization — who can access which resources/actions.
---
# A01: Broken Access Control

Users acting outside their intended permissions.

Look for:
- Endpoints/handlers with NO authorization check, or checks only in the UI.
- IDOR: object IDs taken from the request (path/query/body) used to fetch/modify
  records without an ownership check (`get(id)` where id is user-controlled).
- Missing function-level checks (admin routes reachable by normal users).
- Trusting client-supplied role/tenant fields; JWT/`role` claims not verified.
- Path traversal to escape a per-user directory (`../`).
- CORS `Access-Control-Allow-Origin: *` with credentials.

Confirm: trace the request parameter to the data access and show there is no
`user == resource.owner` (or role/tenant) check on the path an attacker controls.

Report: the exact route + missing check, an IDOR/priv-esc trigger, and the fix
(enforce server-side authz per request; deny by default).
