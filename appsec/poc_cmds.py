"""
Description: `/poc` command helpers — list PoCs, show one, and re-run a saved PoC
    against a locally deployed target. Shared by the CLI (`phrak poc` /
    `phrak poc-run`) and chat (`/poc`, `/poc-run`).
Author: Aleksa Zatezalo
Date Created: 09-22-2026
"""

from __future__ import annotations


def list_pocs(app) -> str:
    from .poc_store import PocStore, render_list

    return render_list(PocStore(app.config).list())


def poc_detail(app, ident: str) -> str:
    from .poc_store import PocStore, render_detail

    ident = (ident or "").strip()
    if not ident:
        return "usage: /poc [POC-id]   (bare /poc lists them)"
    store = PocStore(app.config)
    rec = store.get(ident)
    if rec is None:
        return f"no PoC matching '{ident}'. Run `/poc` to list them."
    return render_detail(rec, store.read_script(rec))


def run_poc(app, ident: str, target: str = "") -> str:
    """Run a saved PoC against a locally deployed target, inside the sandbox.

    Returns rendered stdout/stderr, or a user-facing error (agent off, no PoC,
    no target). The PoC executes exactly as stored — it's your responsibility to
    have written a **safe, non-destructive** check; the sandbox limits blast
    radius but cannot make a destructive payload safe.
    """
    cfg = app.config
    if not getattr(cfg, "enable_verify", False):
        return (
            "the verify sandbox is OFF. Set `enable_verify: true` in "
            f"{cfg.phrack_dir / 'config.yaml'} (needs docker or podman), then "
            "restart PHRAK."
        )
    ident = (ident or "").strip()
    if not ident:
        return "usage: /poc-run <POC-id> [target-url]"

    from .poc_store import PocStore
    from .tools.verify_tool import run_poc_sandboxed

    store = PocStore(cfg)
    rec = store.get(ident)
    if rec is None:
        return f"no PoC matching '{ident}'. Run `/poc` to list them."

    target = (target or "").strip() or getattr(cfg, "verify_target", "")
    if not target:
        return (
            "no target given. Pass a URL of your locally deployed target, e.g. "
            f"`/poc-run {rec.id} http://localhost:8000`, or set `verify_target` "
            "in config."
        )

    # Same target policy as every other active tool: loopback by default, a
    # remote host only if explicitly authorized (allow_remote_targets + scope
    # allowlist). This gates the *intended* target before the container runs.
    from .tools.common import guard_local

    target, err = guard_local(target)
    if err:
        return err

    script = store.read_script(rec)
    if not script:
        return f"PoC {rec.id}'s script file is missing on disk."

    result = run_poc_sandboxed(script, kind=rec.kind, target=target)
    store.set_target(rec, target)
    header = (
        f"ran PoC {rec.id} (finding {rec.finding_id or '—'}) against {target}\n"
        f"{'-' * 60}\n"
    )
    return header + result.render()
