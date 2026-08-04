"""Declarative scope / target policy (Phase 7).

The per-call loopback guard (:func:`appsec.tools.common.is_local`) answers "is
this host local?" but nothing more. A scope policy makes "what am I allowed to
touch" **declarative and auditable**: allowed hosts / ports / path prefixes and a
request rate limit, loaded from ``<workspace>/.phrack/scope.yaml``.

Crucially, scope can only ever *narrow* what is already permitted — the loopback
floor is enforced separately and independently in ``guard_local`` and is never
weakened here. An absent or malformed scope file means "no extra restrictions"
(loopback-only still applies).
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml

SCOPE_FILENAME = "scope.yaml"


@dataclass
class ScopePolicy:
    """An allow-list narrowing what network tools may reach, within loopback."""

    enabled: bool = False
    allowed_hosts: list[str] = field(default_factory=list)   # empty = any loopback
    allowed_ports: list[int] = field(default_factory=list)   # empty = any port
    allowed_paths: list[str] = field(default_factory=list)   # path prefixes; empty=any
    denied_paths: list[str] = field(default_factory=list)
    rate_limit_per_min: int = 0                              # 0 = unlimited

    @classmethod
    def from_dict(cls, raw: dict) -> "ScopePolicy":
        raw = raw or {}
        def _ints(v):
            out = []
            for x in v or []:
                try:
                    out.append(int(x))
                except (TypeError, ValueError):
                    continue
            return out
        return cls(
            enabled=bool(raw.get("enabled", True)),  # a present file is on by default
            allowed_hosts=[str(h).lower() for h in raw.get("allowed_hosts") or []],
            allowed_ports=_ints(raw.get("allowed_ports")),
            allowed_paths=[str(p) for p in raw.get("allowed_paths") or []],
            denied_paths=[str(p) for p in raw.get("denied_paths") or []],
            rate_limit_per_min=int(raw.get("rate_limit_per_min", 0) or 0),
        )

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "allowed_hosts": self.allowed_hosts,
            "allowed_ports": self.allowed_ports,
            "allowed_paths": self.allowed_paths,
            "denied_paths": self.denied_paths,
            "rate_limit_per_min": self.rate_limit_per_min,
        }

    # ------------------------------------------------------------- checks
    def check_host_port(self, url: str) -> str | None:
        """Host/port narrowing only — safe for a base URL (no path component)."""
        if not self.enabled:
            return None
        u = urlparse(url)
        host = (u.hostname or "").lower()
        if self.allowed_hosts and host not in self.allowed_hosts:
            return (f"[OUT OF SCOPE] host '{host}' is not in the scope policy's "
                    f"allowed_hosts ({', '.join(self.allowed_hosts)}). "
                    f"Edit {SCOPE_FILENAME} to widen scope.")
        if self.allowed_ports:
            port = u.port or (443 if u.scheme == "https" else 80)
            if port not in self.allowed_ports:
                return (f"[OUT OF SCOPE] port {port} is not in the scope policy's "
                        f"allowed_ports ({self.allowed_ports}).")
        return None

    def check_url(self, url: str) -> str | None:
        """Return an error string if ``url`` is out of scope, else None.

        Does NOT re-check loopback — that is ``guard_local``'s job and always runs
        first. This only applies the *additional* narrowing this policy declares.
        """
        hp = self.check_host_port(url)
        if hp:
            return hp
        if not self.enabled:
            return None
        u = urlparse(url)
        path = u.path or "/"
        for d in self.denied_paths:
            if path.startswith(d):
                return f"[OUT OF SCOPE] path '{path}' matches a denied prefix '{d}'."
        if self.allowed_paths and not any(path.startswith(p) for p in self.allowed_paths):
            return (f"[OUT OF SCOPE] path '{path}' is not under any allowed prefix "
                    f"({', '.join(self.allowed_paths)}).")
        return None


# --------------------------------------------------------------- loading
def scope_path(config) -> Path:
    return config.phrack_dir / SCOPE_FILENAME


def load_policy(config) -> ScopePolicy:
    """Load the workspace scope policy; a missing/invalid file -> disabled policy."""
    p = scope_path(config)
    if not p.exists():
        return ScopePolicy(enabled=False)
    try:
        raw = yaml.safe_load(p.read_text()) or {}
    except yaml.YAMLError:
        return ScopePolicy(enabled=False)
    if not isinstance(raw, dict):
        return ScopePolicy(enabled=False)
    return ScopePolicy.from_dict(raw)


# --------------------------------------------------------------- rate limiting
# Process-wide request timestamps for the scope rate limiter. Runs are sequential
# so a single window is sufficient; kept module-level to persist across tool calls.
_REQUEST_TIMES: deque[float] = deque()


def check_rate_limit(policy: ScopePolicy, now: float | None = None) -> str | None:
    """Enforce ``rate_limit_per_min`` over a rolling 60s window; None if allowed.

    Records the request time when it is allowed (so callers must only call this
    once per intended request, at send time)."""
    if not policy.enabled or policy.rate_limit_per_min <= 0:
        return None
    now = time.monotonic() if now is None else now
    while _REQUEST_TIMES and now - _REQUEST_TIMES[0] > 60.0:
        _REQUEST_TIMES.popleft()
    if len(_REQUEST_TIMES) >= policy.rate_limit_per_min:
        return (f"[RATE LIMITED] scope policy allows {policy.rate_limit_per_min} "
                "request(s)/min to the target; slow down and retry shortly.")
    _REQUEST_TIMES.append(now)
    return None


def reset_rate_limit() -> None:
    """Clear the rate-limit window (tests / new session)."""
    _REQUEST_TIMES.clear()


def enforce(url: str, config=None) -> str | None:
    """Full scope check for a URL: policy allow-list + rate limit. None if OK.

    Loopback is enforced separately by ``guard_local`` and is not repeated here.
    """
    if config is None:
        from .runtime import require_config

        config = require_config()
    policy = load_policy(config)
    err = policy.check_url(url)
    if err:
        return err
    return check_rate_limit(policy)
