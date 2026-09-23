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
