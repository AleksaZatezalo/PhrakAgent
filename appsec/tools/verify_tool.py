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

import re
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


def _reachable_from_sandbox(target: str) -> str:
    """Rewrite a host-local URL so it resolves from inside the container.

    A PoC run against a locally deployed target says ``http://localhost:8000`` —
    but inside the sandbox ``localhost`` is the container itself. With
    ``--add-host host.docker.internal:host-gateway`` the host is reachable under
    that name, so point loopback URLs at it.
    """
    return re.sub(
        r"(^https?://)(localhost|127\.0\.0\.1)(?=[:/]|$)",
        r"\1host.docker.internal",
        target.strip(),
    )


def run_poc_sandboxed(
    script: str,
    kind: str = "python",
    mount_workspace: bool = False,
    network: str | None = None,
    target: str = "",
) -> VerifyResult:
    """Execute ``script`` inside a locked-down container.

    ``target`` (a URL) runs the PoC against a locally deployed service: the host
    is exposed as ``host.docker.internal`` and the target is handed to the PoC in
    ``$PHRAK_TARGET``. A live target needs egress, so the network defaults to
    ``bridge`` in that case (``network`` overrides either way). Every other guard
    — read-only root, dropped caps, nobody user, mem/pid caps, wall-clock kill —
    still applies; nothing here makes the PoC safe to run destructively.

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

        # A live target needs egress; default to bridge for it, else honour the
        # configured network (none by default). An explicit `network` wins.
        net = network or (("bridge" if target else None) or cfg.verify_network or "none")
        cmd = [
            binary,
            "run",
            "--rm",
            "--network",
            str(net),
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
        if target:
            # Expose the host so a locally deployed target is reachable, and hand
            # the (rewritten) URL to the PoC via $PHRAK_TARGET.
            cmd += ["--add-host", "host.docker.internal:host-gateway"]
            cmd += ["-e", f"PHRAK_TARGET={_reachable_from_sandbox(target)}"]
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


# How a PoC outcome maps onto the finding's runtime status track. "inconclusive"
# deliberately changes no status — it records a note and leaves the static
# verdict standing (the bug may still be real; the PoC just couldn't show it).
_OUTCOME_STATUS = {"confirmed": "confirmed", "false_positive": "false_positive"}


@tool
def record_poc_result(
    finding_id: str,
    outcome: str,
    note: str = "",
    poc: str = "",
) -> str:
    """Record a sandboxed PoC's verdict against an existing finding, promoting (or
    refuting) it on the RUNTIME status track.

    Call this once per finding you attempted, AFTER run_poc, using the finding id
    (``FND-...``) from the code_review context. ``outcome`` is one of:
      * ``confirmed``       — the PoC demonstrated the vulnerability (row leak,
                              canary side-effect, marker string, /etc/passwd read).
      * ``false_positive``  — the PoC did not land after a retry; the finding is
                              not runtime-reproducible as written.
      * ``inconclusive``    — needs a full app stack / out of scope for a one-shot
                              PoC; leaves the static verdict standing.
    ``note`` explains what the PoC showed (or why it didn't); ``poc`` is the script
    you ran, kept on the finding's history. The runtime track has precedence over
    the reporting agent's status but not over a human triage decision."""
    outcome = (outcome or "").strip().lower()
    if outcome not in ("confirmed", "false_positive", "inconclusive"):
        return (
            f"REJECTED: outcome {outcome!r} is not one of confirmed / "
            "false_positive / inconclusive."
        )
    from ..store import FindingStore

    cfg = require_config()
    store = FindingStore(cfg)
    # Resolve the finding first so the persisted PoC is named by its canonical id
    # and a bad id fails fast (rather than after saving an orphan script).
    rec0 = store.get(finding_id)
    if rec0 is None:
        return (
            f"NOT RECORDED — no finding matching {finding_id!r}. "
            "Use the finding id shown in your context."
        )

    from ..poc_store import PocStore

    poc_rec = PocStore(cfg).save(rec0.id, poc, outcome=outcome, note=note)
    tail = _poc_tail(poc)
    where = f"(poc {poc_rec.id})" if poc_rec else ""
    detail = " ".join(p for p in (note.strip(), tail, where) if p).strip()

    if outcome == "inconclusive":
        rec, msg = store.add_note(
            rec0.id, f"runtime PoC inconclusive: {detail or 'no detail given'}"
        )
        return f"RECORDED inconclusive on {rec.id} (status unchanged; noted). {where}".strip()

    status = _OUTCOME_STATUS[outcome]
    # A landed PoC is the strongest evidence there is, so it raises confidence; a
    # non-landing one leaves confidence to the static analysis that reported it.
    conf = 0.95 if outcome == "confirmed" else None
    rec, msg = store.set_status(
        rec0.id,
        status,
        actor="runtime",
        note=f"sandboxed PoC: {detail or outcome}",
        confidence=conf,
    )
    return f"RECORDED runtime verdict — {msg}. {where}".strip()


def _poc_tail(poc: str) -> str:
    """A short, single-line tag of the PoC script for the history note."""
    poc = (poc or "").strip()
    if not poc:
        return ""
    first = poc.splitlines()[0][:80]
    return f"(poc: {first}…)" if len(poc) > 80 else f"(poc: {first})"


# Verification outcome (agent vocabulary) -> (test-case status, test-case result).
# See models.testcases: statuses new|in_progress|complete, results pass|fail|
# blocked|inconclusive. "fail" = the security control failed (issue present).
_TEST_OUTCOME = {
    "confirmed": ("complete", "fail"),
    "false_positive": ("complete", "pass"),
    "inconclusive": ("in_progress", "inconclusive"),
}
# Friendly aliases the model might use.
_OUTCOME_ALIASES = {
    "vulnerable": "confirmed",
    "pass": "false_positive",  # app "passed" the security test -> not vulnerable
    "not_vulnerable": "false_positive",
    "safe": "false_positive",
    "fail": "confirmed",  # security control "failed" -> vulnerable
}


@tool
def record_test_result(
    test_case_id: str,
    outcome: str,
    note: str = "",
    poc: str = "",
) -> str:
    """Record the result of running a TEST CASE against the app, saving its PoC.

    Use this from `/test` once you've exercised the test case with http_request
    (and, where useful, run_poc). Works whether or not the test case is linked to
    a finding: it always saves the ``poc`` to the PoC store and moves the test
    case's status/result, and if the case IS linked to a finding it also promotes
    that finding on the runtime track (like record_poc_result).

    ``outcome`` is one of ``confirmed`` (issue reproduced), ``false_positive``
    (not reproducible), or ``inconclusive`` (needs setup you don't have).
    ``note`` explains what you observed; ``poc`` is the script you ran."""
    outcome = _OUTCOME_ALIASES.get(
        (outcome or "").strip().lower(), (outcome or "").strip().lower()
    )
    if outcome not in _TEST_OUTCOME:
        return (
            f"REJECTED: outcome {outcome!r} is not one of confirmed / "
            "false_positive / inconclusive."
        )
    from ..poc_store import PocStore
    from ..store import FindingStore, TestCaseStore

    cfg = require_config()
    tc = TestCaseStore(cfg).get(test_case_id)
    if tc is None:
        return (
            f"NOT RECORDED — no test case matching {test_case_id!r}. "
            "Use the test case id shown in your context."
        )

    # Save the PoC keyed by the linked finding when there is one, else the test
    # case id — so an unlinked case still produces a browsable POC-… entry.
    poc_rec = PocStore(cfg).save(
        tc.finding_id or tc.id, poc, outcome=outcome, note=note
    )
    where = f"(poc {poc_rec.id})" if poc_rec else ""
    detail = " ".join(p for p in (note.strip(), _poc_tail(poc), where) if p).strip()

    status, result = _TEST_OUTCOME[outcome]
    _, tc_msg = TestCaseStore(cfg).set_status(tc.id, status, result=result)
    if detail:
        TestCaseStore(cfg).add_note(tc.id, f"/test run: {detail}")

    # Linked to a finding? Promote it on the runtime track too.
    finding_msg = ""
    if tc.finding_id and outcome in _OUTCOME_STATUS:
        conf = 0.95 if outcome == "confirmed" else None
        rec, fmsg = FindingStore(cfg).set_status(
            tc.finding_id,
            _OUTCOME_STATUS[outcome],
            actor="runtime",
            note=f"/test PoC: {detail or outcome}",
            confidence=conf,
        )
        if rec is not None:
            finding_msg = f" · finding {rec.id} -> {_OUTCOME_STATUS[outcome]}"

    return f"RECORDED — {tc_msg}{finding_msg}. {where}".strip()


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
    if not getattr(config, "enable_verify", False):
        return []
    return [run_poc, record_poc_result, record_test_result]
