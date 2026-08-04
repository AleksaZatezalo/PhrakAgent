"""Context-sensitive sanitizer effectiveness table.

A sanitizer is only a sanitizer *against a specific sink class, in a specific
context*. Encoding that here lets the reviewing agent avoid the most common
**false-sanitizer** mistakes — treating a control as protective when it isn't:

* HTML-escaping (`html.escape`) makes output safe for an HTML context — it does
  **not** make a value SQL-, shell-, path-, or URL-safe.
* `shlex.quote` is fragile with `shell=True`; the robust fix is an argument array
  (`shell=False`), where a shell never parses the value at all.
* Authentication (proving identity) is **not** authorization (access control): an
  authenticated user can still reach another user's object (IDOR/BOLA).
* Parsing a URL (`urlparse`) does **not** make a request SSRF-safe — DNS
  rebinding, redirects, and encoded/alternate IPs bypass a naive parse.
* A prefix check *before* canonicalization is bypassable (`../`, symlinks); you
  must canonicalize (`realpath`) **then** check the prefix.

:func:`assess` answers "does <sanitizer> mitigate <vuln class> here?" and, crucially,
flags a **false assumption** when the answer is "no but people think yes".
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ---- canonical vuln classes ------------------------------------------------
_CATEGORY_ALIASES = {
    "sql_injection": ["sql", "sqli", "sql-injection", "sql injection"],
    "command_injection": [
        "command", "command-injection", "command injection", "cmd", "os-command",
        "rce", "os command injection",
    ],
    "xss": ["xss", "cross-site-scripting", "cross site scripting", "html-injection"],
    "path_traversal": [
        "path", "path-traversal", "path traversal", "traversal", "lfi",
        "directory-traversal", "file-read", "file inclusion",
    ],
    "ssrf": ["ssrf", "server-side-request-forgery", "server side request forgery"],
    "open_redirect": ["open-redirect", "open redirect", "redirect"],
    "ldap_injection": ["ldap", "ldap-injection", "ldap injection"],
    "deserialization": ["deserialization", "deserialisation", "insecure-deserialization"],
    "xxe": ["xxe", "xml-external-entity"],
    "authz": [
        "authz", "authorization", "authorisation", "access-control",
        "broken-access-control", "idor", "bola", "access control",
    ],
    "authn": ["authn", "authentication", "login"],
}

# ---- canonical sanitizers/controls -----------------------------------------
_SANITIZER_ALIASES = {
    "html_escape": [
        "html.escape", "html_escape", "markupsafe.escape", "markupsafe",
        "cgi.escape", "escape_html", "htmlspecialchars", "htmlescape",
    ],
    "parameterized_query": [
        "parameterized", "parameterised", "parameterized-query", "prepared",
        "prepared-statement", "bound-parameters", "bind", "placeholder",
        "query-parameters", "execute-params",
    ],
    "int_cast": ["int", "int()", "int-cast", "integer", "integer-cast", "to_int"],
    "shlex_quote": ["shlex.quote", "shlex_quote", "shlex", "quote", "pipes.quote"],
    "arg_array": ["arg-array", "argument-array", "arg_list", "list-args", "no-shell"],
    "url_parse": [
        "urlparse", "urlsplit", "url-parse", "url.parse", "parse-url", "urllib.parse",
    ],
    "allowlist_host": [
        "allowlist", "allowlist-host", "whitelist", "resolve-and-check-ip",
        "ip-allowlist", "dns-pin",
    ],
    "prefix_check": [
        "prefix-check", "startswith", "starts-with", "prefix", "basedir-check",
    ],
    "canonicalize": [
        "canonicalize", "realpath", "os.path.realpath", "abspath", "normpath",
        "resolve",
    ],
    "authentication": ["authentication", "login-required", "authn", "is-authenticated"],
    "authorization": [
        "authorization", "authorisation", "authz", "ownership-check",
        "role-check", "permission-check", "access-control-check",
    ],
}


@dataclass
class _Entry:
    mitigates: set = field(default_factory=set)
    ineffective: set = field(default_factory=set)
    note: str = ""


# Non-context-sensitive controls. Context-sensitive ones are handled in assess().
_TABLE: dict[str, _Entry] = {
    "html_escape": _Entry(
        {"xss"},
        {"sql_injection", "command_injection", "path_traversal", "ssrf", "ldap_injection"},
        "HTML output-encoding is safe only in an HTML context; it does not make a "
        "value SQL-, shell-, path-, or URL-safe.",
    ),
    "parameterized_query": _Entry(
        {"sql_injection"},
        {"command_injection", "xss", "path_traversal", "ssrf"},
        "Binding data out-of-band from the SQL text is the canonical SQLi fix; it "
        "is irrelevant to non-SQL sinks.",
    ),
    "int_cast": _Entry(
        {"sql_injection", "command_injection", "path_traversal", "open_redirect",
         "ldap_injection"},
        set(),
        "Coercing to int destroys any injection payload when the value must be numeric.",
    ),
    "arg_array": _Entry(
        {"command_injection"},
        {"sql_injection", "xss", "path_traversal", "ssrf"},
        "Passing an argument array with shell=False means no shell parses the value.",
    ),
    "allowlist_host": _Entry(
        {"ssrf"},
        set(),
        "Resolving the host and checking the resolved IP against an allowlist "
        "mitigates SSRF — still guard DNS rebinding and redirects.",
    ),
    "authentication": _Entry(
        {"authn"},
        {"authz"},
        "Proving identity (login) is NOT authorization: an authenticated user can "
        "still access another user's object (IDOR/BOLA).",
    ),
    "authorization": _Entry(
        {"authz"},
        set(),
        "An ownership/role/permission check enforces access control.",
    ),
    "canonicalize": _Entry(
        {"path_traversal"},
        {"sql_injection", "command_injection", "xss", "ssrf"},
        "Canonicalizing (realpath) then checking the result is under the base dir "
        "defeats ../ and symlink traversal.",
    ),
}


@dataclass
class SanitizerAssessment:
    sanitizer: str
    category: str
    effective: bool | None            # True / False / None (unknown)
    false_assumption: bool            # True: commonly believed protective but isn't (here)
    reason: str

    def render(self) -> str:
        verdict = {True: "EFFECTIVE", False: "NOT EFFECTIVE", None: "UNKNOWN"}[
            self.effective
        ]
        flag = "  ⚠ FALSE-SANITIZER ASSUMPTION" if self.false_assumption else ""
        return (f"{self.sanitizer} vs {self.category}: {verdict}{flag}\n"
                f"  {self.reason}")


def _canon(value: str, aliases: dict[str, list[str]]) -> str:
    v = (value or "").strip().lower()
    # tolerate "html.escape()" / "shlex.quote(x)" and space/underscore/hyphen mixes
    base = v.split("(")[0].strip()
    variants = {v, base, base.replace(" ", "-"), base.replace(" ", "_"),
                base.replace("_", "-"), base.replace("-", " ")}
    if v in aliases:
        return v
    for canon, names in aliases.items():
        pool = {canon, *names}
        if variants & pool:
            return canon
    return v


def canonical_category(name: str) -> str:
    return _canon(name, _CATEGORY_ALIASES)


def canonical_sanitizer(name: str) -> str:
    return _canon(name, _SANITIZER_ALIASES)


def assess(
    sanitizer: str,
    category: str,
    *,
    shell: bool = False,
    canonicalized: bool = False,
) -> SanitizerAssessment:
    """Does ``sanitizer`` actually mitigate ``category`` in this context?

    ``shell`` — is the command built for a shell (``shell=True``)? Relevant to
    ``shlex.quote``. ``canonicalized`` — was the path canonicalized *before* the
    prefix/base check? Relevant to a ``startswith`` base-dir check.
    """
    s = canonical_sanitizer(sanitizer)
    c = canonical_category(category)

    # ---- context-sensitive controls ----
    if s == "shlex_quote":
        if c == "command_injection":
            if shell:
                return SanitizerAssessment(
                    s, c, False, True,
                    "shlex.quote with shell=True is fragile — quoting is easy to "
                    "misapply and shell parsing still occurs. Use an argument array "
                    "(shell=False) so no shell interprets the value.",
                )
            return SanitizerAssessment(
                s, c, True, False,
                "With shell=False (argument array) no shell parses the value, so "
                "command injection is prevented regardless of quoting.",
            )
        return SanitizerAssessment(
            s, c, False, False,
            "shell quoting is unrelated to this sink class.",
        )

    if s == "url_parse":
        if c == "ssrf":
            return SanitizerAssessment(
                s, c, False, True,
                "Parsing a URL does not validate its destination. DNS rebinding, "
                "HTTP redirects, and encoded/alternate IPs (e.g. 0x7f.1, [::1], "
                "decimal) bypass a naive parse. Resolve the host and allowlist the "
                "resolved IP instead.",
            )
        return SanitizerAssessment(
            s, c, False, False, "URL parsing is unrelated to this sink class.")

    if s == "prefix_check":
        if c == "path_traversal":
            if canonicalized:
                return SanitizerAssessment(
                    s, c, True, False,
                    "Checking the prefix AFTER canonicalization (realpath) is a "
                    "sound base-dir containment check.",
                )
            return SanitizerAssessment(
                s, c, False, True,
                "A prefix/startswith check BEFORE canonicalization is bypassable "
                "with ../ sequences and symlinks. Canonicalize (realpath) first, "
                "then check the result is under the base directory.",
            )
        return SanitizerAssessment(
            s, c, False, False, "A path prefix check is unrelated to this sink class.")

    # ---- table-driven controls ----
    entry = _TABLE.get(s)
    if entry is None:
        return SanitizerAssessment(
            s, c, None, False,
            "Unknown control — cannot assert effectiveness; verify by reading the "
            "code and the sink's escaping requirements.",
        )
    if c in entry.mitigates:
        return SanitizerAssessment(s, c, True, False, entry.note)
    if c in entry.ineffective:
        return SanitizerAssessment(
            s, c, False, True,
            f"{entry.note} It does not mitigate {c}.",
        )
    return SanitizerAssessment(
        s, c, None, False,
        f"No effectiveness recorded for {s} against {c}; {entry.note}",
    )
