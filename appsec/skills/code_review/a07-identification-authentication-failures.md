---
name: a07-identification-authentication-failures
when_to_use: Reviewing authentication, session, and credential handling.
---
# A07: Identification and Authentication Failures

Weaknesses in confirming and maintaining user identity.

Look for:
- Passwords: no strength policy, weak hashing (see A02), no lockout/rate limit.
- Credential stuffing / brute force possible (no throttling on login).
- Session tokens: predictable, not rotated on login, no expiry/idle timeout, not
  invalidated on logout.
- Session cookies missing `HttpOnly` / `Secure` / `SameSite`.
- JWT flaws: `alg: none` accepted, signature not verified, secret hardcoded/weak,
  no expiry.
- Password reset tokens that are guessable, long-lived, or reusable.
- Missing/optional MFA on sensitive accounts; user enumeration via differing
  responses.

Confirm: show the auth/session code path and the missing/weak control (file:line).

Report: the weakness, how an attacker abuses it (takeover, fixation, forgery),
and the fix (strong hashing, secure cookie flags, verified+expiring tokens, MFA,
throttling).
