"""Config loading, serialization, and per-agent overrides."""

from __future__ import annotations

import pytest

from appsec.config import Config


def test_defaults():
    cfg = Config()
    assert cfg.llm.provider == "ollama"
    assert cfg.max_rounds == 4


def test_from_dict_reads_overrides():
    cfg = Config.from_dict(
        {
            "max_steps": 7,
            "agent_models": {"threat_model": {"model": "x-mini"}},
        }
    )
    assert cfg.max_steps == 7
    assert cfg.agent_models["threat_model"]["model"] == "x-mini"


def test_from_dict_ignores_legacy_autonomous_key():
    cfg = Config.from_dict({"autonomous": True})  # removed field: must not crash
    assert not hasattr(cfg, "autonomous")


def test_to_dict_round_trip_preserves_settings():
    cfg = Config()
    cfg.max_steps = 11
    again = Config.from_dict(cfg.to_dict())
    assert again.max_steps == 11
    assert again.llm.model == cfg.llm.model


def test_llm_for_applies_override():
    cfg = Config.from_dict({"agent_models": {"code_review": {"temperature": 0.9}}})
    base = cfg.llm_for("threat_model")       # no override -> base config
    overridden = cfg.llm_for("code_review")
    assert base.temperature == cfg.llm.temperature
    assert overridden.temperature == 0.9
    assert overridden.model == cfg.llm.model  # untouched fields preserved


def test_load_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        Config.load(str(tmp_path / "nope.yaml"))
