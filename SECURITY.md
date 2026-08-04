<!-- PHRAK Agent — security policy -->

# Security Policy

Two different things live under this heading, so to be explicit up front:

* **A vulnerability *in* PHRAK Agent** — report it here, details below.
* **A vulnerability PHRAK *found* in something else** — that's the log in
  [`FINDINGS.md`](FINDINGS.md), not this file.

## Reporting a vulnerability in PHRAK Agent

Use **[GitHub private vulnerability reporting](https://github.com/AleksaZatezalo/PhrakAgent/security/advisories/new)**
(Security → Advisories → *Report a vulnerability*). That keeps the report
private until there's a fix and gives us a place to request a CVE.

If that's unavailable, email **zabumaphu@gmail.com** with `PHRAK SECURITY` in
the subject.

Please **don't** open a public issue for anything exploitable.

Include what you'd want to receive: affected version or commit, the
`file:line` involved, what an attacker controls, and the smallest reproducer you
have. A patch is welcome but not expected.

**What to expect:** an acknowledgement within a few days and a status update as
triage progresses. This is a small project maintained in spare time — there's no
SLA and no bounty, but real reports get real attention and credit in the
advisory (or anonymity, your call).

## Supported versions

| Version | Supported |
|---|---|
| `0.2.x` (`main`) | ✅ |
| `< 0.2` | ❌ — upgrade |

Only the latest release on `main` gets fixes. There are no maintenance branches.

## Scope

PHRAK is a local, offline-first analysis tool: no server, no multi-tenancy, no
network listener. Its interesting trust boundary is that it **reads untrusted
code and feeds it to a model** — so the surfaces that matter are:

**In scope**

* **Escaping the workspace sandbox** — path traversal or symlink tricks in the
  file tools ([`appsec/tools/filesystem.py`](appsec/tools/filesystem.py),
  `validate_against_workspace` in
  [`appsec/models/findings.py`](appsec/models/findings.py)) that read or write
  outside the configured workspace.
* **Command execution beyond the intended analyzers** — anything reaching
  `subprocess` through the sandbox helpers in
  [`appsec/tools/common.py`](appsec/tools/common.py), or argument injection into
  Opengrep / `pip-audit` / `git`.
* **Bypassing the SSRF / loopback guard** — reaching internal or non-permitted
  hosts from a tool.
* **Bypassing the clone guard** — [`appsec/clone.py`](appsec/clone.py) fetching
  something it should refuse, or writing outside the target directory.
* **Prompt injection with real consequence** — malicious content in an analyzed
  repo that causes PHRAK to take an action it otherwise wouldn't (invoke a tool
  outside scope, exfiltrate file contents, write outside the workspace). Not
  merely making the model say something wrong.
* **Credential leakage** — API keys from
  [`appsec/credentials.py`](appsec/credentials.py) or `.phrack/credentials`
  landing in logs, reports, or an outbound request that shouldn't carry them.
* **Scope-policy bypass** — [`appsec/scope.py`](appsec/scope.py) permitting a
  target the policy excludes.

**Out of scope**

* **Wrong analysis results.** Missed vulnerabilities (false negatives) and bogus
  ones (false positives) are detection-quality bugs, not security
  vulnerabilities — open a normal issue. Interesting ones end up in the *Not
  findings* table in [`FINDINGS.md`](FINDINGS.md).
* **Model output that is merely incorrect, offensive, or hallucinated.** PHRAK's
  findings are leads for a human to verify; the README says so.
* Issues requiring a maliciously modified local config, a hostile
  `~/.phrak`, or an attacker who already has code execution as your user.
* Vulnerabilities in dependencies (Ollama, Chroma, Opengrep, the Anthropic SDK)
  with no PHRAK-specific amplification — report those upstream. If PHRAK's usage
  makes an upstream issue exploitable when it otherwise wouldn't be, that *is*
  in scope.
* Resource exhaustion from pointing PHRAK at a deliberately enormous repo.
* Anything on a host you don't own or aren't authorized to test. PHRAK is an
  offensive-security tool; using it does not grant you authorization.

## Using PHRAK safely

* Analyzed code is **untrusted input**. Treat a workspace the way you'd treat any
  hostile repo — PHRAK reads it, but you're the one who eventually runs it.
* `.phrack/` holds findings, evidence snippets, and credentials. It's
  git-ignored for a reason; don't commit it and don't paste it into a ticket
  unfiltered.
* Set a scope policy (`.phrack/scope.yaml`, see
  [`scope.example.yaml`](scope.example.yaml)) before pointing PHRAK at anything
  you don't own.
* The default Ollama provider keeps everything local. Choosing the Anthropic
  provider sends code from the analyzed workspace to a third-party API — make
  that decision deliberately.
