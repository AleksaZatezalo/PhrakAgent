"""Built-in agents. Importing this package registers them into the registry.

PHRAK focuses on: Code Review, Threat Modeling, and Test-Case generation.

To add a new agent, drop a module here that builds an AgentSpec and calls
``register_agent(...)``, then import it below.
"""

from . import (  # noqa: F401  (registration side-effect)
    code_review,
    test_case,
    threat_model,
)

__all__ = ["code_review", "test_case", "threat_model"]
