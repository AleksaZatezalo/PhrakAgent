---
name: a05-security-misconfiguration
when_to_use: Reviewing framework/server/app configuration and defaults.
---
# A05: Security Misconfiguration

Insecure defaults, verbose errors, or unnecessary exposure.

Look for:
- Debug mode enabled in production (`app.run(debug=True)`, `DEBUG=True`) —
  exposes a console/stack traces.
- Default/weak credentials; admin interfaces exposed.
- Verbose error handling that leaks stack traces, SQL, or paths to users.
- Missing security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options).
- Directory listing enabled; sensitive files served (`.git`, `.env`, backups).
- Overly permissive CORS; unnecessary features/ports/services enabled.
- Cloud/storage buckets or DB bound to 0.0.0.0 without auth.

Confirm: point to the config/flag (file:line) and the exposure it causes.

Report: the misconfiguration, what it exposes, and the hardened setting (disable
debug, add headers, restrict binding, remove defaults).
