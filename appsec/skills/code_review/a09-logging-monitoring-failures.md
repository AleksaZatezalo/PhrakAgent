---
name: a09-logging-monitoring-failures
when_to_use: Reviewing security logging, auditing, and sensitive-data leakage in logs.
---
# A09: Security Logging and Monitoring Failures

Attacks go undetected — or logs themselves become a liability.

Look for:
- Security-relevant events NOT logged: logins (success/failure), access-control
  denials, input validation failures, high-value actions.
- No audit trail for admin/privileged actions.
- **Sensitive data written to logs**: passwords, tokens, session IDs, PII, card
  data, full request bodies (this is itself a disclosure vuln).
- Logs that an attacker can tamper with or that lack integrity/retention.
- Log injection: unsanitised user input written to logs (forged entries, CRLF).
- Errors swallowed silently (`except: pass`) hiding attack signals.

Confirm: show either the missing log on a security event, or the sensitive value
being logged (file:line).

Report: what is not observable (or what leaks), the detection/forensics or
disclosure impact, and the fix (log security events without secrets, sanitise,
protect and retain logs, alert on anomalies).
