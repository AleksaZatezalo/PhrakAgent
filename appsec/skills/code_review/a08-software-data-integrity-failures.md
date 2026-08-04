---
name: a08-software-data-integrity-failures
when_to_use: Reviewing integrity of code, updates, and serialized data.
---
# A08: Software and Data Integrity Failures

Code/data trusted without verifying its integrity.

Look for:
- **Insecure deserialization** of untrusted data: `pickle.loads`, `yaml.load`
  (unsafe loader), `marshal`, PHP `unserialize`, Java `ObjectInputStream`,
  Node `node-serialize` — an attacker-controlled blob → object/gadget → RCE.
- Auto-update / plugin mechanisms that fetch and execute code without signature
  verification.
- CI/CD pulling unpinned actions/images, or build steps executing untrusted input.
- Client-side state (cookies, hidden fields) deserialized/trusted server-side
  without integrity checks (unsigned).
- Downloading and `exec`/`eval`-ing remote content.

Confirm: trace untrusted bytes to the deserialization/execution sink and show no
integrity check (signature/HMAC/allowlist) precedes it.

Report: the source→sink, the RCE/tampering impact, and the fix (safe loaders,
signed data, pinned+verified artifacts, avoid native deserialization of untrusted
input).
