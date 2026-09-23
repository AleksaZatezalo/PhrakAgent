"""
Description: ``http_request`` — send ONE HTTP request to a locally-running target.

PHRAK is a whitebox assistant that only ever drives a locally-deployed instance
of the target: the request is forced through :func:`guard_local`, so it must
resolve to loopback and pass the workspace scope policy (allowed hosts / ports /
paths + rate limit). That is the same floor the rest of PHRAK's active tools sit
on — an agent cannot use this to reach the public internet or an arbitrary host.
Author: Aleksa Zatezalo
Date Created: 09-22-2026
"""

from __future__ import annotations

import urllib.error
import urllib.request

from langchain_core.tools import tool

from ..runtime import record_tool_run
from .common import guard_local

# Cap the response we hand back to the model — a PoC only needs to see enough to
# judge whether the issue reproduced, not a multi-MB page.
_MAX_BODY = 8_000


def _parse_headers(raw: str) -> dict[str, str]:
    """Parse ``"Key: Value"`` lines (newline- or ``;``-separated) into a dict."""
    out: dict[str, str] = {}
    for line in (raw or "").replace(";", "\n").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip()
            if k:
                out[k] = v.strip()
    return out


@tool
def http_request(
    url: str,
    method: str = "GET",
    headers: str = "",
    body: str = "",
    timeout: int = 10,
) -> str:
    """Send a single HTTP request to a LOCALLY-RUNNING target and return the
    response (status line, headers, and truncated body).

    `url` must resolve to loopback (localhost / 127.0.0.1 / ::1) and stay within
    the workspace scope policy — PHRAK only drives a locally-deployed instance of
    the target, never a remote host. `method` is GET/POST/PUT/… ; `headers` is
    "Key: Value" lines (newline- or ';'-separated); `body` is the raw request
    body for methods that take one. Use this to demonstrate a web finding against
    the running app (e.g. an injected `id` param that leaks rows). Prefer safe,
    non-destructive requests — you are hitting a real running service."""
    url, err = guard_local(url)
    if err:
        return err

    method = (method or "GET").upper()
    data = body.encode() if body else None
    req = urllib.request.Request(
        url, data=data, method=method, headers=_parse_headers(headers)
    )
    record_tool_run("http_request", f"{method} {url}")
    try:
        with urllib.request.urlopen(req, timeout=max(1, int(timeout))) as resp:
            status = resp.status
            resp_headers = dict(resp.getheaders())
            payload = resp.read(_MAX_BODY + 1)
    except urllib.error.HTTPError as e:  # 4xx/5xx are results, not failures
        status = e.code
        resp_headers = dict(e.headers or {})
        payload = e.read(_MAX_BODY + 1) if hasattr(e, "read") else b""
    except Exception as e:
        return f"[REQUEST FAILED] {method} {url}: {e}"

    truncated = len(payload) > _MAX_BODY
    text = payload[:_MAX_BODY].decode("utf-8", errors="replace")
    hdrs = "\n".join(f"{k}: {v}" for k, v in resp_headers.items())
    out = [f"HTTP {status}  ({method} {url})", "", hdrs, "", text]
    if truncated:
        out.append("\n[... body truncated]")
    return "\n".join(out)


def http_tools() -> list:
    return [http_request]
