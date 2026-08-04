"""
Description: Agent registry behaviour.
Author: Aleksa Zatezalo
Date Created: 07-29-2026
"""

from __future__ import annotations

import pytest

from appsec.base_agent import AgentRegistry, AgentSpec


def _spec(name="a", desc="does a thing"):
    return AgentSpec(name=name, description=desc, system_prompt="p")


def test_register_and_get():
    reg = AgentRegistry()
    spec = _spec()
    reg.register(spec)
    assert reg.get("a") is spec
    assert reg.names() == ["a"]


def test_duplicate_register_raises():
    reg = AgentRegistry()
    reg.register(_spec())
    with pytest.raises(ValueError):
        reg.register(_spec())


def test_override_allows_replacement():
    reg = AgentRegistry()
    reg.register(_spec(desc="old"))
    reg.register(_spec(desc="new"), override=True)
    assert reg.get("a").description == "new"


def test_get_unknown_raises_keyerror():
    reg = AgentRegistry()
    with pytest.raises(KeyError):
        reg.get("missing")


def test_catalog_lists_all_sorted():
    reg = AgentRegistry()
    reg.register(_spec("zeta", "z"))
    reg.register(_spec("alpha", "a"))
    catalog = reg.catalog()
    assert catalog.index("alpha") < catalog.index("zeta")
    assert "- alpha: a" in catalog
