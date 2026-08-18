"""
Description: Verify agent sandbox — policy gating + real container execution.

Container-runtime tests are skipped if docker/podman isn't on PATH. The policy
gate tests run unconditionally.
"""

from __future__ import annotations

import shutil

import pytest

from appsec import runtime
from appsec.agents import register_verify_if_enabled
from appsec.base_agent import REGISTRY
from appsec.config import Config
from appsec.tools.verify_tool import run_poc_sandboxed, verify_tools


@pytest.fixture()
def cfg():
    c = Config()
    runtime.init_runtime(c)
    yield c
    runtime.RUNTIME.config = None


def test_verify_disabled_by_default(cfg):
    """Off-by-default posture — no tools exposed, no agent registered."""
    assert cfg.enable_verify is False
    assert verify_tools(cfg) == []
    assert "verify" not in REGISTRY.names()


def test_run_poc_refuses_when_disabled(cfg):
    """Even if called directly, the tool refuses to launch a container."""
    r = run_poc_sandboxed("print('x')", kind="python")
    assert r.ok is False
    assert "disabled" in r.error.lower()


def test_run_poc_rejects_unknown_kind(cfg):
    cfg.enable_verify = True
    r = run_poc_sandboxed("print('x')", kind="perl")
    assert r.ok is False
    assert "unsupported" in r.error.lower()


def test_run_poc_rejects_empty_script(cfg):
    cfg.enable_verify = True
    r = run_poc_sandboxed("   ", kind="python")
    assert r.ok is False
    assert "empty" in r.error.lower()


def test_run_poc_rejects_oversize_script(cfg):
    cfg.enable_verify = True
    r = run_poc_sandboxed("x" * 40_000, kind="python")
    assert r.ok is False
    assert "too large" in r.error.lower()


def test_verify_agent_registers_when_enabled(cfg):
    """The verify agent lives in the registry only after enable_verify=True."""
    assert "verify" not in REGISTRY.names()
    cfg.enable_verify = True
    register_verify_if_enabled(cfg)
    assert "verify" in REGISTRY.names()
    # Cleanup so other tests don't see it.
    REGISTRY._specs.pop("verify", None)


def test_verify_tools_hides_when_off(cfg):
    cfg.enable_verify = False
    assert verify_tools(cfg) == []
    cfg.enable_verify = True
    tools = verify_tools(cfg)
    assert tools and tools[0].name == "run_poc"


# ------------------------------- real container tests (opt-in via docker/podman)


HAVE_RUNTIME = shutil.which("docker") is not None or shutil.which("podman") is not None


def _daemon_reachable() -> bool:
    """docker/podman binary present is not enough — daemon must respond."""
    import subprocess
    for b in ("docker", "podman"):
        p = shutil.which(b)
        if not p:
            continue
        try:
            r = subprocess.run(
                [p, "info"], capture_output=True, timeout=5, text=True
            )
            if r.returncode == 0:
                return True
        except Exception:
            continue
    return False


pytestmark_runtime = pytest.mark.skipif(
    not (HAVE_RUNTIME and _daemon_reachable()),
    reason="no reachable docker/podman daemon",
)


@pytestmark_runtime
def test_run_poc_hello_world(cfg):
    """A trivial print PoC actually runs and captures stdout."""
    cfg.enable_verify = True
    cfg.verify_timeout_s = 60  # image pull margin on cold cache
    r = run_poc_sandboxed("print('phrak-ok')", kind="python")
    if r.error and ("pull" in r.error.lower() or "manifest" in r.error.lower()):
        pytest.skip(f"image unavailable: {r.error}")
    assert r.ok, r.render()
    assert "phrak-ok" in r.stdout


@pytestmark_runtime
def test_run_poc_has_no_network_by_default(cfg):
    """--network none default — outbound curl must fail."""
    cfg.enable_verify = True
    cfg.verify_timeout_s = 60
    script = (
        "import socket, sys\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 80), timeout=3)\n"
        "    print('NETWORK_AVAILABLE'); sys.exit(0)\n"
        "except OSError as e:\n"
        "    print(f'NETWORK_BLOCKED:{e}'); sys.exit(1)\n"
    )
    r = run_poc_sandboxed(script, kind="python")
    if r.error and "pull" in r.error.lower():
        pytest.skip(f"image unavailable: {r.error}")
    assert "NETWORK_BLOCKED" in r.stdout
    assert "NETWORK_AVAILABLE" not in r.stdout


@pytestmark_runtime
def test_run_poc_workspace_is_read_only(cfg, tmp_path):
    """--read-only + workspace mount means the PoC can't modify the target."""
    cfg.enable_verify = True
    cfg.verify_timeout_s = 60
    cfg.paths.workspace = str(tmp_path)
    (tmp_path / "target.txt").write_text("original")
    script = (
        "import sys\n"
        "try:\n"
        "    open('/workspace/target.txt', 'w').write('OWNED')\n"
        "    print('WROTE'); sys.exit(0)\n"
        "except OSError as e:\n"
        "    print(f'BLOCKED:{e}'); sys.exit(1)\n"
    )
    r = run_poc_sandboxed(script, kind="python", mount_workspace=True)
    if r.error and "pull" in r.error.lower():
        pytest.skip(f"image unavailable: {r.error}")
    assert "BLOCKED" in r.stdout
    assert (tmp_path / "target.txt").read_text() == "original"


@pytestmark_runtime
def test_run_poc_wall_clock_timeout(cfg):
    """Timeout kills a hung PoC."""
    cfg.enable_verify = True
    cfg.verify_timeout_s = 2
    r = run_poc_sandboxed("import time; time.sleep(30)", kind="python")
    if r.error and "pull" in r.error.lower():
        pytest.skip(f"image unavailable: {r.error}")
    assert r.ok is False
    assert r.exit_code in (124, 137, -9)
