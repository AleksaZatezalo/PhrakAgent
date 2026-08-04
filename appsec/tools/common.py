"""Shared helpers for PHRAK tools.

Centralises the three things every tool needs so they aren't re-implemented (and
subtly diverging) across modules:

* **Workspace sandboxing** — resolve a path under the configured workspace and
  reject anything that escapes it.
* **Subprocess execution** — run an external CLI with a timeout and uniform
  error handling (missing binary / timeout / crash).
* **Loopback guard** — normalise a URL and refuse any non-loopback host, so
  network tools can only ever touch a locally-running target.
"""

from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from ..runtime import require_config

# Output caps (bytes/chars) — named by purpose rather than repeated magic numbers.
FILE_READ_MAX = 60_000      # a single file read
ANALYSIS_MAX = 40_000       # static-analysis / search output
CLI_OUTPUT_MAX = 6_000      # dynamic-tool (scanner) output

# Bare hostnames accepted without DNS resolution. Everything else that is not an
# IP literal is resolved and every returned address must be loopback.
LOOPBACK_NAMES = {"localhost", "", "0.0.0.0"}
# Kept for back-compat with callers/tests that referenced the old name.
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", ""}


# --------------------------------------------------------------- workspace
def workspace() -> Path:
    """The resolved workspace root the file tools operate under."""
    return Path(require_config().paths.workspace).resolve()


def excluded_dirs() -> list[str]:
    """Directory names search/analysis tools should never descend into.

    Reuses the RAG ``exclude_dirs`` list (so search, opengrep and indexing agree)
    and always adds PHRAK's own state dir + the git dir — otherwise a code search
    matches PHRAK's own skill files under ``.phrack/skills/`` instead of the
    target's code, and drowns real hits in ``node_modules``/``venv`` noise.
    """
    try:
        dirs = list(require_config().rag.exclude_dirs)
    except Exception:  # pragma: no cover - config not loaded
        dirs = ["venv", ".venv", "node_modules", "__pycache__", "site-packages"]
    for extra in (".phrack", ".git"):
        if extra not in dirs:
            dirs.append(extra)
    return list(dict.fromkeys(dirs))


def resolve_in_workspace(path: str) -> Path:
    """Resolve ``path`` under the workspace root.

    Raises ``ValueError`` if the resolved path escapes the workspace, so tools
    can't be tricked into reading outside the target project.
    """
    root = workspace()
    p = (
        (root / path).resolve()
        if not Path(path).is_absolute()
        else Path(path).resolve()
    )
    if root not in p.parents and p != root:
        raise ValueError(f"Path '{path}' is outside the workspace {root}")
    return p


# --------------------------------------------------------------- subprocess
@dataclass
class CliResult:
    """Outcome of running an external CLI.

    ``error`` is set only when the command could not run at all (binary missing,
    timeout, crash); otherwise inspect ``returncode`` / ``stdout`` / ``stderr``.
    """

    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    error: str | None = None

    @property
    def output(self) -> str:
        """stdout if present, else stderr — trimmed."""
        return (self.stdout or self.stderr or "").strip()


def run_cli(
    cmd: list[str],
    timeout: int,
    require_bin: bool = True,
    cwd: str | Path | None = None,
    optional: bool = False,
) -> CliResult:
    """Run ``cmd`` with a timeout, never raising — errors come back on the result.

    Emits a live activity line to stdout when the external process starts and
    when it finishes, so the operator can see each syscall as it happens.
    ``cwd`` runs the process in that directory (dependency auditors like
    ``npm audit`` / ``cargo audit`` operate on the project dir they run in).

    ``optional=True`` marks this as a *probe* the caller will fall back from if the
    binary is absent (e.g. ``rg`` before ``grep``): a missing binary is then logged
    as a dim note instead of a red failure, so an expected fallback doesn't read as
    an error.
    """
    from ..ui import log_syscall, log_syscall_note, log_syscall_result

    def _missing() -> CliResult:
        msg = f"{binary}: not installed / not on PATH"
        if optional:
            log_syscall_note(f"{binary} not found, trying fallback")
        else:
            log_syscall_result(msg, ok=False)
        return CliResult(error=f"{binary} is not installed / not on PATH.")

    binary = cmd[0]
    if require_bin and not shutil.which(binary):
        return _missing()
    log_syscall(" ".join(cmd))
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )
    except subprocess.TimeoutExpired:
        log_syscall_result(f"{binary}: timed out after {timeout}s", ok=False)
        return CliResult(error=f"{binary} timed out after {timeout}s.")
    except FileNotFoundError:
        return _missing()
    except Exception as e:  # pragma: no cover - defensive
        log_syscall_result(f"{binary}: {e}", ok=False)
        return CliResult(error=f"failed to run {binary}: {e}")
    log_syscall_result(f"{binary}: exit {proc.returncode}", ok=proc.returncode == 0)
    return CliResult(
        stdout=proc.stdout or "", stderr=proc.stderr or "", returncode=proc.returncode
    )


# --------------------------------------------------------------- loopback guard
def normalize_url(url: str) -> str:
    """Prefix a bare host with ``http://`` so urlparse can read the hostname."""
    return url if url.startswith(("http://", "https://")) else "http://" + url


def _parse_ip(host: str) -> ipaddress._BaseAddress | None:
    """Parse ``host`` as an IP, tolerating the encodings used to bypass SSRF
    filters: dotted, IPv6, and integer/hex/octal IPv4 (e.g. 2130706433,
    0x7f000001, 0177.0.0.1). Returns None if it isn't an IP literal."""
    host = host.strip().strip("[]")
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    # integer / hex / octal IPv4 forms
    for base in (10, 16, 8):
        try:
            if base == 16 and not host.lower().startswith("0x"):
                continue
            if base == 8 and not (host.startswith("0") and host.isdigit()):
                continue
            val = int(host, base)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except (ValueError, ipaddress.AddressValueError):
            continue
    return None


def _ip_is_loopback(ip: ipaddress._BaseAddress) -> bool:
    """Loopback check that also unwraps IPv4-mapped IPv6 (::ffff:127.0.0.1)."""
    if ip.is_loopback:
        return True
    mapped = getattr(ip, "ipv4_mapped", None)
    return bool(mapped and mapped.is_loopback)


def host_is_loopback(host: str) -> bool:
    """True only if ``host`` unambiguously resolves to a loopback address.

    Defeats SSRF-filter bypasses: encoded IPv4 (decimal/hex/octal), IPv4-mapped
    IPv6, and DNS-rebinding (a hostname whose A/AAAA records include a public
    address). For a non-literal hostname, EVERY resolved address must be loopback
    — resolution failure fails closed (not local)."""
    host = (host or "").lower()
    ip = _parse_ip(host)
    if ip is not None:
        return _ip_is_loopback(ip)
    if host in LOOPBACK_NAMES:
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    addrs = {info[4][0] for info in infos}
    if not addrs:
        return False
    return all(_ip_is_loopback(ipaddress.ip_address(a.split("%")[0])) for a in addrs)


def is_local(url: str) -> bool:
    """True if ``url``'s host resolves to loopback (see :func:`host_is_loopback`)."""
    return host_is_loopback(urlparse(url).hostname or "")


def guard_local(url: str, binary: str | None = None) -> tuple[str, str | None]:
    """Normalise ``url`` and enforce loopback (and optionally that ``binary`` exists).

    Returns ``(normalized_url, error)``. When ``error`` is not None the caller
    should return it to the agent unchanged. The loopback floor is checked first
    and unconditionally; the declarative scope policy can only *further* narrow it
    (allowed hosts/ports/paths + rate limit).
    """
    url = normalize_url(url)
    if not is_local(url):
        return url, (
            f"[REFUSED] '{url}' is not a loopback address. PHRAK only targets a "
            "locally-running instance (localhost / 127.0.0.1 / ::1)."
        )
    if binary and not shutil.which(binary):
        return url, (
            f"{binary} is not installed / not on PATH. Install it to enable "
            "this tool."
        )
    scope_err = _enforce_scope(url)
    if scope_err:
        return url, scope_err
    return url, None


def _enforce_scope(url: str, host_port_only: bool = False) -> str | None:
    """Apply the workspace scope policy to ``url`` (None if OK / no policy).

    Best-effort: if scope can't be evaluated (no config), it simply doesn't
    narrow anything — the loopback floor already applied by the caller stands.
    """
    try:
        from ..scope import check_rate_limit, load_policy
        from ..runtime import require_config

        policy = load_policy(require_config())
        err = (policy.check_host_port(url) if host_port_only
               else policy.check_url(url))
        if err:
            return err
        return None if host_port_only else check_rate_limit(policy)
    except Exception:
        return None
