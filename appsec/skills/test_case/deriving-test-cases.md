---
name: deriving-test-cases
when_to_use: Turning code-review findings and threat-model threats into concrete test cases.
---
# Deriving Test Cases from Findings & Threats

The upstream code_review findings and threat_model threats are your primary
input. Convert each into at least one verification test case.

From a **code_review finding** (has file:line, CWE, severity):
1. Identify the source (attacker-controlled input) and the sink from the finding.
2. Read the code around both with read_file/search_code to find the exact
   reachable entry point (endpoint + parameter, CLI arg, message field).
3. Write a POSITIVE test: an input that should trigger the weakness, with the
   observable oracle that confirms it (error, reflected payload, extra rows, a
   file read, a delay).
4. Write a NEGATIVE/boundary test where useful: a benign input that must be
   handled safely, so a fix can be regression-tested.

From a **threat_model threat / attack path** (STRIDE, trust boundary):
1. Take the attacker goal and the boundary it crosses.
2. Turn each step of the attack path into a test that checks whether that step is
   actually possible (e.g. "can an anonymous user reach the admin route?").
3. For Spoofing/Elevation threats, test with the WRONG identity/role and assert
   access is denied.

Coverage checklist — make sure the set spans the categories that apply to this
app: authn/session, authz/access control, injection (SQL/OS/template/NoSQL),
path traversal / file access, SSRF, deserialization, secrets/crypto, missing
rate-limiting, and insecure defaults. If the upstream agents missed a category
that the code clearly exposes, add tests for it (see abuse-case-enumeration).
