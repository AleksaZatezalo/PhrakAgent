"""
Description: Built-in agents. Importing this package registers them into the registry.
Author: Aleksa Zatezalo
Date Created: 07-31-2026
"""

from . import (  # noqa: F401  (registration side-effect)
    code_review,
    test_case,
    threat_model,
)

# The verify agent is registered ONLY when enable_verify is set in the
# workspace config — otherwise the orchestrator's DAG planner would happily
# schedule it in a default "assess this app" request, which is exactly the
# opt-in barrier we're trying to preserve.
try:
    from ..runtime import require_config

    if getattr(require_config(), "enable_verify", False):
        from . import verify  # noqa: F401
except Exception:
    # Runtime not initialised yet (unit tests / imports before init_runtime).
    # register_verify_if_enabled() below is the explicit hook.
    pass


def register_verify_if_enabled(config) -> None:
    """Explicit hook: register the verify agent iff config.enable_verify.

    Called from :func:`appsec.runtime.init_runtime` so the agent shows up in
    the registry after config is loaded, without paying the cost when it's off.
    """
    if getattr(config, "enable_verify", False):
        from . import verify  # noqa: F401


__all__ = [
    "code_review",
    "test_case",
    "threat_model",
    "register_verify_if_enabled",
]
