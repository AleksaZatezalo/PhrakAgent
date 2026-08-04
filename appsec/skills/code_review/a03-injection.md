---
name: a03-injection
when_to_use: Reviewing untrusted input flowing into an interpreter/sink.
---
# A03: Injection

Untrusted input changes the meaning of a command/query.

Look for (source → sink, no sanitisation):
- **SQL**: string-concatenated / f-string queries instead of parameterised
  (`"... WHERE id = '" + uid`). Sinks: `execute`, `cursor.execute`, raw ORM SQL.
- **OS command**: `os.system`, `os.popen`, `subprocess(..., shell=True)`,
  backticks with user input.
- **Template (SSTI)**: user input rendered by Jinja2/Twig/etc. (`render_template_string`).
- **NoSQL / LDAP / XPath**: user input in query objects/filters.
- **Code eval**: `eval`, `exec`, `pickle.loads` on user data.

Confirm: trace a request parameter (source) to the sink and show no escaping /
parameterisation between them.

Report: source→sink with file:line, a concrete payload that triggers it, and the
fix (parameterised queries, `shell=False` + arg list, autoescaping, allowlists).
