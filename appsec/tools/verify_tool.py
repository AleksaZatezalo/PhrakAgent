"""
Description: Sandboxed one-shot PoC runner for the opt-in `verify` agent.

The verify agent's job: take a *confirmed* data-flow finding and try to
demonstrate exploitability by running a minimal PoC. Doing this on the host is
insane — the PoC is by definition attacker-controlled code. This tool executes
the PoC inside a throwaway container with:

  * ``--network none``      (default; ``bridge`` only when config says so)
  * ``--read-only`` root + ``--tmpfs /tmp:rw,size=64m`` for scratch
  * ``--user 65534:65534``  (nobody)
  * ``--cap-drop ALL``, ``--security-opt no-new-privileges``
  * memory / pids / cpu limits from :class:`Config`
  * ``--rm`` so nothing persists
  * absolute-timeout wall clock kill

The workspace is optionally mounted **read-only** at ``/workspace`` so a PoC
can import the target's code path — never RW. Nothing the PoC does can affect
the host, the workspace, or any other run.

The tool is only registered on the ``verify`` agent, and only when
``enable_verify: true`` in the workspace config. Absent Docker / Podman it
reports the deficiency instead of executing.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from langchain_core.tools import tool

from ..runtime import require_config

# Only these two script kinds are supported. Everything else needs a build
# step, which defeats the point of a short one-shot PoC.
_KINDS = {"python": ["python3", "/poc/poc.py"], "sh": ["sh", "/poc/poc.sh"]}


@dataclass
class VerifyResult:
    ok: bool
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool
    error: str = ""

    def render(self) -> str:
        parts = [
            f"exit_code={self.exit_code}",
            f"ok={self.ok}",
        ]
        if self.error:
            parts.append(f"error={self.error}")
        if self.truncated:
            parts.append("(output truncated)")
        out = self.stdout.strip()
        err = self.stderr.strip()
        block = "\n".join(parts)
        if out:
            block += "\n\nSTDOUT:\n" + out[-4000:]
        if err:
            block += "\n\nSTDERR:\n" + err[-2000:]
        return block


def _runtime_binary(cfg) -> tuple[str, str]:
    """Return (binary_path, name) or ('', '') if none present."""
    pref = (cfg.verify_runtime or "auto").lower()
    if pref in ("docker", "auto"):
        p = shutil.which("docker")
        if p:
            return p, "docker"
    if pref in ("podman", "auto"):
        p = shutil.which("podman")
        if p:
            return p, "podman"
    return "", ""


def run_poc_sandboxed(
    script: str,
    kind: str = "python",
    mount_workspace: bool = False,
) -> VerifyResult:
    """Execute ``script`` inside a locked-down container.

    Never raises for policy failures — returns a VerifyResult with .error set so
    the agent sees a normal tool return rather than a stack trace.
    """
    cfg = require_config()
    if not getattr(cfg, "enable_verify", False):
        return VerifyResult(
            False,
            -1,
            "",
            "",
            False,
            "verify sandbox is disabled (set enable_verify: true in config)",
        )
    if kind not in _KINDS:
        return VerifyResult(
            False,
            -1,
            "",
            "",
            False,
            f"unsupported kind {kind!r}; use python or sh",
        )
    if not isinstance(script, str) or not script.strip():
        return VerifyResult(False, -1, "", "", False, "empty PoC script")
    if len(script) > 32_000:
        return VerifyResult(False, -1, "", "", False, "PoC script too large (>32KB)")

    binary, runtime_name = _runtime_binary(cfg)
    if not binary:
        return VerifyResult(
            False,
            -1,
            "",
            "",
            False,
            "no container runtime found (install docker or podman, "
            "or set verify_runtime)",
        )

    filename = "poc.py" if kind == "python" else "poc.sh"
    with tempfile.TemporaryDirectory(prefix="phrak-poc-") as td:
        poc_dir = Path(td)
        # The sandbox runs as uid 65534 (nobody), so the PoC dir & script have
        # to be readable by "other". TemporaryDirectory defaults to 0700.
        poc_dir.chmod(0o755)
        script_file = poc_dir / filename
        script_file.write_text(script)
        script_file.chmod(0o755)

        cmd = [
            binary,
            "run",
            "--rm",
            "--network",
            str(cfg.verify_network or "none"),
            "--read-only",
            "--tmpfs",
            "/tmp:rw,size=64m,mode=1777",
            "--user",
            "65534:65534",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            f"{int(cfg.verify_memory_mb)}m",
            "--pids-limit",
            str(int(cfg.verify_pids)),
            "--workdir",
            "/poc",
            "-v",
            f"{poc_dir}:/poc:ro",
        ]
        if mount_workspace:
            ws = Path(cfg.paths.workspace).expanduser().resolve()
            cmd += ["-v", f"{ws}:/workspace:ro", "-e", "PHRAK_WORKSPACE=/workspace"]
        cmd.append(cfg.verify_image or "python:3.12-slim")
        cmd += _KINDS[kind]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(1, int(cfg.verify_timeout_s or 30)),
            )
        except subprocess.TimeoutExpired as e:
            return VerifyResult(
                False,
                124,
                e.stdout or "",
                e.stderr or "",
                True,
                f"PoC exceeded wall-clock timeout ({cfg.verify_timeout_s}s)",
            )
        except FileNotFoundError as e:
            return VerifyResult(False, -1, "", "", False, f"runtime missing: {e}")
        except Exception as e:  # pragma: no cover - defensive
            return VerifyResult(False, -1, "", "", False, f"sandbox error: {e}")

    out, err = proc.stdout, proc.stderr
    truncated = len(out) > 8000 or len(err) > 4000
    return VerifyResult(
        ok=(proc.returncode == 0),
        exit_code=proc.returncode,
        stdout=out,
        stderr=err,
        truncated=truncated,
    )


@tool
def run_poc(script: str, kind: str = "python", mount_workspace: bool = False) -> str:
    """Run a short PoC script inside a locked-down container to verify a finding.

    `script` is the full source code of a one-shot proof-of-concept. `kind` is
    either 'python' or 'sh'. `mount_workspace=True` mounts the target code at
    /workspace (read-only) so the PoC can import a vulnerable module. The
    sandbox has NO network by default (config `verify_network`), no
    capabilities, tmpfs /tmp, and a hard wall-clock timeout — everything the
    PoC does is thrown away. Use this to demonstrate that a data-flow finding
    is actually exploitable (e.g. SQLi returns row leak, path traversal reads
    /etc/passwd from the mounted workspace, deserialization runs your code).
    Return value contains exit code, stdout, and stderr. A non-zero exit or
    empty stdout usually means the PoC did not land."""
    result = run_poc_sandboxed(script, kind=kind, mount_workspace=mount_workspace)
    return result.render()


def verify_tools(config) -> list:
    """Only exposed when enable_verify is set. Off-by-default posture."""
    return [run_poc] if getattr(config, "enable_verify", False) else []
