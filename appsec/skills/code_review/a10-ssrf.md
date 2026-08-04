---
name: a10-ssrf
when_to_use: Reviewing server-side requests built from user-controlled URLs/hosts.
---
# A10: Server-Side Request Forgery (SSRF)

The server is tricked into making requests to an attacker-chosen destination.

Look for:
- User-controlled URL/host/port passed to an HTTP client or fetch:
  `requests.get(user_url)`, `urllib.request.urlopen(...)`, `curl`, image/PDF/
  webhook/SSO-metadata fetchers, URL previews, file imports "by URL".
- No allowlist of permitted hosts/schemes; `file://`, `gopher://`, `dict://`
  schemes accepted.
- No blocking of internal ranges (127.0.0.0/8, 169.254.169.254 cloud metadata,
  10/8, 192.168/16, ::1) — classic path to cloud credentials.
- Redirect following that bypasses a naive host check.

Confirm: trace the user-supplied URL to the outbound request and show no
allowlist / internal-range block between them.

Report: the sink (file:line), an SSRF trigger (e.g. hitting the metadata
endpoint), the impact (internal service access, credential theft), and the fix
(strict scheme+host allowlist, resolve+block private IPs, disable unneeeded
redirects, no raw user URLs).
