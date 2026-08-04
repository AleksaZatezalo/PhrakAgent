"""Application bootstrap — build the fully wired system from config.

One call, :func:`build_app`, returns everything the CLI needs: the LLM, the
learned-skills store, the codebase index, orchestrator, and registry, with the
built-in agents loaded.
"""

from __future__ import annotations

from dataclasses import dataclass

from langchain_core.language_models.chat_models import BaseChatModel

from .base_agent import REGISTRY, AgentRegistry
from .config import Config
from .credentials import load_into_env
from .llm import ModelRegistry
from .orchestrator import Orchestrator
from .rag import CodeIndex
from .runtime import init_runtime
from .skill_store import SkillStore


@dataclass
class App:
    config: Config
    llm: BaseChatModel
    models: ModelRegistry
    skills: SkillStore
    rag: CodeIndex
    orchestrator: Orchestrator
    registry: AgentRegistry


def build_app(config: Config) -> App:
    config.ensure_dirs()
    # Export the workspace's stored provider keys (.phrack/credentials) as
    # process-wide env vars before any client is constructed — the provider SDKs
    # read ANTHROPIC_API_KEY & co. from the environment.
    load_into_env(config)
    models = ModelRegistry(config)
    llm = models.base()
    skills = SkillStore(config)
    rag = CodeIndex(config)  # backing store built lazily on first /ask
    init_runtime(config)

    # register built-in agents (import side-effect)
    from . import agents  # noqa: F401

    orchestrator = Orchestrator(llm, skills, config, REGISTRY, models=models)
    return App(
        config=config,
        llm=llm,
        models=models,
        skills=skills,
        rag=rag,
        orchestrator=orchestrator,
        registry=REGISTRY,
    )
