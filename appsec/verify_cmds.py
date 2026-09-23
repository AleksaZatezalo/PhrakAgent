"""
Description: `verify` command helpers — run the sandboxed PoC agent against ONE
    finding by id, shared by `phrak verify <id>` (CLI) and `/verify <id>` (chat).
Author: Aleksa Zatezalo
Date Created: 09-22-2026
"""

from __future__ import annotations


def build_verify_task(app, ident: str) -> tuple[str, str]:
    """Resolve ``ident`` to a finding and build the verify agent's task.

    Returns ``(task, error)`` with exactly one populated: the task string to hand
    ``orchestrator.run_agent("verify", ...)``, or a user-facing error explaining
    why verification can't run (agent off, no such finding, no id given).
    """
    cfg = app.config
    if not getattr(cfg, "enable_verify", False):
        return "", (
            "the verify agent is OFF. Set `enable_verify: true` in "
            f"{cfg.phrack_dir / 'config.yaml'} (needs docker or podman on PATH), "
            "then restart PHRAK."
        )
    if "verify" not in app.registry.names():
        return "", (
            "verify agent is not registered — set `enable_verify: true` and "
            "restart PHRAK so it loads."
        )

    ident = (ident or "").strip()
    if not ident:
        return "", "usage: verify <FND-id>   (see `phrak findings` for ids)"

    from .store import FindingStore, render_finding_detail

    rec = FindingStore(cfg).get(ident)
    if rec is None:
        return "", f"no finding matching '{ident}'. Run `phrak findings` to list them."

    task = (
        f"Verify ONLY the finding below ({rec.id}) and record its runtime verdict "
        "with record_poc_result, using this exact finding id. Do NOT verify, "
        "discover, or invent any other finding. If it is not a data-flow bug a "
        "one-shot PoC can demonstrate, record it inconclusive and explain why.\n\n"
        f"Target finding:\n{render_finding_detail(rec)}"
    )
    return task, ""


def build_test_task(app, ident: str) -> tuple[str, str]:
    """Resolve a TEST CASE id and build a task to execute it against the running
    app, then record a PoC — the agentic counterpart of ``build_verify_task``.

    The test case must be linked to a finding (that's the thing being proven);
    returns ``(task, error)`` with exactly one populated.
    """
    cfg = app.config
    if not getattr(cfg, "enable_verify", False):
        return "", (
            "the verify agent is OFF. Set `enable_verify: true` in "
            f"{cfg.phrack_dir / 'config.yaml'} (needs docker or podman on PATH), "
            "then restart PHRAK."
        )
    if "verify" not in app.registry.names():
        return "", (
            "verify agent is not registered — set `enable_verify: true` and "
            "restart PHRAK so it loads."
        )

    ident = (ident or "").strip()
    if not ident:
        return "", "usage: test <TC-id>   (see `phrak testcases` for ids)"

    from .store import FindingStore, TestCaseStore, render_finding_detail

    tc = TestCaseStore(cfg).get(ident)
    if tc is None:
        return "", f"no test case matching '{ident}'. Run `phrak testcases` to list them."
    if not tc.finding_id:
        return "", (
            f"test case {tc.id} is not linked to a finding. Link it first with "
            f"`/testcase-link {tc.id} <FND-id>`, then run test again."
        )
    finding = FindingStore(cfg).get(tc.finding_id)
    finding_block = (
        render_finding_detail(finding)
        if finding is not None
        else f"(finding {tc.finding_id} not found in the store)"
    )

    task = (
        f"Agentically EXECUTE the test case below against the locally-deployed "
        f"target and prove or disprove the finding it verifies ({tc.finding_id}). "
        "Use http_request to send the requests the test case describes to the "
        "running app (loopback only), read the responses, and judge them against "
        "the test case's expected result. Then write a minimal, SAFE, "
        "non-destructive PoC (python or sh) that reproduces the check and, if the "
        "sandbox is available, confirm it with run_poc. Record the verdict with "
        f"record_poc_result using the finding id {tc.finding_id} — confirmed if "
        "the issue reproduced, false_positive if it did not, inconclusive if it "
        "needs setup you don't have. Do NOT perform destructive actions.\n\n"
        f"Test case:\n{tc.to_markdown()}\n\n"
        f"Finding under test:\n{finding_block}"
    )
    return task, ""
