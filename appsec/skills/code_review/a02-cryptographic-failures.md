---
name: a02-cryptographic-failures
when_to_use: Reviewing protection of data in transit and at rest.
---
# A02: Cryptographic Failures

Sensitive data exposed through weak or missing cryptography.

Look for:
- Secrets/keys/passwords hardcoded in source or config (scan_secrets helps).
- Weak hashing for passwords (MD5, SHA1, unsalted) instead of bcrypt/scrypt/argon2.
- Weak/broken ciphers or modes (DES, RC4, ECB), static IVs, homemade crypto.
- Sensitive data stored in plaintext (PII, tokens, card data).
- TLS disabled / cert verification turned off (`verify=False`, `rejectUnauthorized:false`).
- Predictable randomness for tokens/keys (`random` instead of `secrets`/CSPRNG).

Confirm: identify the sensitive value and show the weak primitive protecting it
(cite file:line).

Report: what data is at risk, the weak mechanism, and the fix (strong algorithm,
proper KDF, TLS enforced, secrets from a vault/env).
