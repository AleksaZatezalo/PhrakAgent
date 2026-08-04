"""Provider API keys: stored under .phrack, exported as env vars, never leaked."""

from __future__ import annotations

import os
import stat

import pytest

from appsec import credentials
from appsec.config import Config, LLMConfig, PathsConfig
from appsec.llm import _accepts_temperature, build_chat_model


@pytest.fixture
def anthropic_config(config) -> Config:
    """The temp-dir config, switched to the Claude provider."""
    config.llm = LLMConfig(provider="anthropic", model="claude-opus-5", base_url="")
    return config


@pytest.fixture(autouse=True)
def clean_env():
    """Keep a real ANTHROPIC_API_KEY out of (and each test's key out of) the env."""
    saved = os.environ.pop("ANTHROPIC_API_KEY", None)
    yield
    os.environ.pop("ANTHROPIC_API_KEY", None)
    if saved is not None:
        os.environ["ANTHROPIC_API_KEY"] = saved


# ------------------------------------------------------------------- storage
def test_key_lands_in_phrack_credentials(workspace):
    path = credentials.set_key(workspace, "anthropic", "sk-ant-test")

    assert path == workspace / ".phrack" / "credentials"
    assert path.exists()
    assert credentials.get_key(workspace, "anthropic") == "sk-ant-test"


def test_credentials_file_is_owner_only(workspace):
    path = credentials.set_key(workspace, "anthropic", "sk-ant-test")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_missing_file_reads_as_empty(workspace):
    assert credentials.read_all(workspace) == {}
    assert credentials.get_key(workspace, "anthropic") == ""


def test_set_key_overwrites_and_can_clear(workspace):
    credentials.set_key(workspace, "anthropic", "first")
    credentials.set_key(workspace, "anthropic", "second")
    assert credentials.get_key(workspace, "anthropic") == "second"

    credentials.set_key(workspace, "anthropic", "")
    assert credentials.get_key(workspace, "anthropic") == ""


def test_unknown_provider_rejected(workspace):
    with pytest.raises(ValueError):
        credentials.set_key(workspace, "ollama", "no-key-needed")


# ----------------------------------------------------------------- env export
def test_load_into_env_exports_global(anthropic_config, workspace):
    credentials.set_key(workspace, "anthropic", "sk-ant-env")

    exported = credentials.load_into_env(anthropic_config)

    assert exported == ["ANTHROPIC_API_KEY"]
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-ant-env"


def test_stored_key_wins_over_ambient_env(anthropic_config, workspace):
    os.environ["ANTHROPIC_API_KEY"] = "stale-shell-key"
    credentials.set_key(workspace, "anthropic", "workspace-key")

    credentials.load_into_env(anthropic_config)

    assert os.environ["ANTHROPIC_API_KEY"] == "workspace-key"


def test_hint_only_when_key_missing(anthropic_config, workspace):
    assert "ANTHROPIC_API_KEY" in credentials.missing_key_hint(anthropic_config)

    credentials.set_key(workspace, "anthropic", "sk-ant-x")
    credentials.load_into_env(anthropic_config)
    assert credentials.missing_key_hint(anthropic_config) == ""


def test_no_hint_for_local_provider(config):
    assert credentials.missing_key_hint(config) == ""


# ------------------------------------------------------------------- leakage
def test_key_never_enters_config_yaml(anthropic_config, workspace, tmp_path):
    credentials.set_key(workspace, "anthropic", "sk-ant-secret")
    dest = tmp_path / "config.yaml"

    anthropic_config.save(str(dest))

    assert "sk-ant-secret" not in dest.read_text()
    assert "sk-ant-secret" not in anthropic_config.show()


def test_credentials_file_is_not_rag_indexable(anthropic_config, workspace):
    """``.phrack`` *is* indexed for /ask — the key file must not be."""
    credentials.set_key(workspace, "anthropic", "sk-ant-secret")
    from appsec.rag import CodeIndex

    indexed = list(CodeIndex(anthropic_config)._iter_files())

    assert anthropic_config.credentials_file() not in indexed


# --------------------------------------------------------------- model wiring
def test_anthropic_model_built_from_env_key(anthropic_config, workspace):
    credentials.set_key(workspace, "anthropic", "sk-ant-build")
    credentials.load_into_env(anthropic_config)

    model = build_chat_model(anthropic_config.llm)

    assert model.model == "claude-opus-5"
    assert model.max_tokens == anthropic_config.llm.max_tokens
    assert model.anthropic_api_key.get_secret_value() == "sk-ant-build"


def test_temperature_dropped_for_models_that_reject_it():
    """Opus 5 / Sonnet 5 / … 400 on `temperature`; older Claude models take it."""
    assert not _accepts_temperature("claude-opus-5")
    assert not _accepts_temperature("claude-sonnet-5")
    assert _accepts_temperature("claude-haiku-4-5")
    assert _accepts_temperature("claude-sonnet-4-6")


def test_sampling_free_model_sends_no_temperature(anthropic_config, workspace):
    credentials.set_key(workspace, "anthropic", "sk-ant-build")
    credentials.load_into_env(anthropic_config)

    payload = build_chat_model(anthropic_config.llm)._get_request_payload(
        [("user", "hi")]
    )

    assert "temperature" not in payload


def test_unknown_provider_raises():
    with pytest.raises(ValueError, match="Unknown LLM provider"):
        build_chat_model(LLMConfig(provider="openai"))


# ----------------------------------------------------------- embeddings URL
def test_embeddings_fall_back_to_local_ollama_under_anthropic(anthropic_config):
    """Embeddings stay local, so they must not inherit the Claude endpoint."""
    assert anthropic_config.ollama_base_url() == "http://localhost:11434"


def test_explicit_embeddings_url_wins(anthropic_config):
    anthropic_config.rag.embeddings.base_url = "http://ollama.internal:11434"
    assert anthropic_config.ollama_base_url() == "http://ollama.internal:11434"


def test_ollama_provider_uses_its_own_base_url():
    cfg = Config(
        llm=LLMConfig(provider="ollama", base_url="http://box:1234"),
        paths=PathsConfig(workspace="."),
    )
    assert cfg.ollama_base_url() == "http://box:1234"


# ------------------------------------------------- cross-provider agent models
def test_agent_override_switching_provider_drops_ollama_url(config):
    """A Claude override on an Ollama base must not inherit the Ollama URL."""
    config.agent_models = {"threat_model": {"provider": "anthropic"}}

    sub = config.llm_for("threat_model")

    assert sub.provider == "anthropic"
    assert sub.base_url == ""
    assert sub.model == "claude-opus-5"
    assert config.llm_for("code_review").provider == "ollama"   # base untouched


def test_agent_override_same_provider_still_inherits(config):
    config.llm.base_url = "http://box:1234"
    config.agent_models = {"code_review": {"model": "other-model"}}

    sub = config.llm_for("code_review")

    assert sub.base_url == "http://box:1234"
    assert sub.model == "other-model"


def test_agent_override_fields_win_over_provider_defaults(config):
    config.agent_models = {
        "threat_model": {"provider": "anthropic", "model": "claude-haiku-4-5"}
    }

    assert config.llm_for("threat_model").model == "claude-haiku-4-5"
