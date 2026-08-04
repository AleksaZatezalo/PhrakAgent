"""Configuration loading and the interactive setup wizard.

The whole system is driven by a single YAML file that lives — along with all
generated data (code index, learned skills, reports, history) — inside a
``.phrack/`` directory at the workspace root, mirroring how ``.claude`` works.
Nothing is written outside it, so a workspace is self-describing and trivial to
.gitignore.

PHRAK defaults to running fully local against an Ollama server. Claude via the
Anthropic API is an opt-in alternative provider: the model and endpoint are
configured here, while the API key is kept out of this file entirely — see
``credentials.py``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

# All PHRAK state for a workspace lives under a single ``.phrack/`` directory at
# the workspace root (like ``.claude``): config, code index, learned skills,
# and reports.
PHRACK_DIRNAME = ".phrack"
CONFIG_FILENAME = "config.yaml"
# Provider API keys live beside the config, in their own 0600 file. No indexed
# extension, so the RAG walker never embeds it (see credentials.py).
CREDENTIALS_FILENAME = "credentials"

# Default (workspace-relative) config location: ``.phrack/config.yaml``.
DEFAULT_CONFIG_PATH = f"{PHRACK_DIRNAME}/{CONFIG_FILENAME}"

# Where an Ollama server lives when nothing says otherwise.
OLLAMA_DEFAULT_URL = "http://localhost:11434"

# Providers PHRAK can drive. "ollama" keeps everything on the box; "anthropic"
# sends prompts (and the code excerpts in them) to the Anthropic API.
PROVIDERS = ("ollama", "anthropic")

# Suggested Claude models, most capable first. The wizard offers the first as
# the default; any model ID the API accepts can be typed in instead.
ANTHROPIC_MODELS = (
    "claude-opus-5",       # most capable; the default
    "claude-sonnet-5",     # faster/cheaper, near-Opus on coding
    "claude-haiku-4-5",    # cheapest, for simple passes
)


def _build(cls, raw):
    """Construct a config dataclass from ``raw``, dropping unknown keys.

    Keeps old/newer config files loading after a field is added or removed
    (tolerant defaults, matching the project convention).
    """
    allowed = {f.name for f in fields(cls)}
    kw = {k: v for k, v in (raw or {}).items() if k in allowed}
    return cls(**kw)


def phrack_dir_for(workspace: str | Path = ".") -> Path:
    """Absolute path to the ``.phrack`` directory for a given workspace root."""
    return Path(workspace).expanduser().resolve() / PHRACK_DIRNAME


def default_config_path(workspace: str | Path = ".") -> Path:
    """Where a workspace's config lives: ``<workspace>/.phrack/config.yaml``."""
    return phrack_dir_for(workspace) / CONFIG_FILENAME


def credentials_path(workspace: str | Path = ".") -> Path:
    """Where a workspace's provider API keys live: ``.phrack/credentials``."""
    return phrack_dir_for(workspace) / CREDENTIALS_FILENAME


@dataclass
class LLMConfig:
    provider: str = "ollama"            # ollama (local) | anthropic (Claude API)
    model: str = "qwen2.5-coder:7b"
    base_url: str = OLLAMA_DEFAULT_URL  # Ollama server URL; "" -> provider default
    temperature: float = 0.1            # dropped for Claude models that reject it
    num_ctx: int = 16384                # ollama context window
    max_tokens: int = 16000             # anthropic per-response output cap


def provider_defaults(provider: str) -> LLMConfig:
    """A sane starting LLMConfig for ``provider``.

    Used when a per-agent override switches provider, where inheriting the base
    provider's model and endpoint would be wrong.
    """
    if provider.lower() == "anthropic":
        return LLMConfig(
            provider="anthropic",
            model=ANTHROPIC_MODELS[0],
            base_url="",            # the SDK's own endpoint
        )
    return LLMConfig(provider=provider)


@dataclass
class EmbeddingsConfig:
    provider: str = "default"           # default (local onnx) | ollama
    model: str = "nomic-embed-text"     # used by ollama provider
    base_url: str = ""                  # ollama URL for embeddings; "" -> derive
                                        # (needed when the LLM isn't Ollama)


@dataclass
class RagConfig:
    """Codebase retrieval index — powers `/ask` over the working directory."""

    persist_dir: str = f"{PHRACK_DIRNAME}/rag"  # relative -> resolved vs workspace
    collection: str = "phrak_code"
    recall_k: int = 6                  # chunks retrieved per question
    chunk_lines: int = 60              # lines per indexed chunk
    chunk_overlap: int = 10            # overlapping lines between chunks
    max_file_kb: int = 256            # skip files larger than this
    include_ext: list[str] = field(default_factory=lambda: [
        ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".rb",
        ".php", ".c", ".h", ".cpp", ".hpp", ".cs", ".sh", ".sql", ".yaml",
        ".yml", ".toml", ".ini", ".cfg", ".md", ".rst", ".txt",
    ])
    # Note: ``.phrack`` is intentionally NOT excluded — /ask indexes the
    # workspace's reports/learned-skills/config living there. The vector store
    # sub-dir (``.phrack/rag``) is skipped by path in CodeIndex._iter_files.
    exclude_dirs: list[str] = field(default_factory=lambda: [
        "venv", ".venv", "node_modules", "__pycache__", "data", "dist",
        "build", ".git", ".pytest_cache", "site-packages",
    ])
    embeddings: EmbeddingsConfig = field(default_factory=EmbeddingsConfig)


@dataclass
class PathsConfig:
    skills_dir: str = f"{PHRACK_DIRNAME}/skills"    # relative -> vs workspace
    reports_dir: str = f"{PHRACK_DIRNAME}/reports"  # relative -> vs workspace
    workspace: str = "."               # root the read-only file tools operate under
                                       # (and where .phrack/ is anchored)
    clones_dir: str = "clones"         # where `phrak clone` shallow-clones repos


@dataclass
class OrchestratorConfig:
    """How the multi-agent orchestrator plans and executes work (Phase 8)."""

    mode: str = "dag"                  # "dag" (dependency graph) | "linear"
    max_concurrency: int = 3           # bounded parallel fan-out
    continue_on_failure: bool = True   # isolate a failed task; keep the rest going


@dataclass
class AnalyzersConfig:
    """Which deterministic analyzers are enabled (Phase 8)."""

    opengrep: bool = True
    dependency_audit: bool = True


@dataclass
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    rag: RagConfig = field(default_factory=RagConfig)
    paths: PathsConfig = field(default_factory=PathsConfig)
    max_steps: int = 40                 # per-round tool-call recursion budget
    max_rounds: int = 4                 # times an agent may be nudged to finish
                                        # the report before giving up (run-to-done)
    keep_reports: int = 50              # keep newest N reports; older auto-deleted.
                                        # 0 = keep everything
    enable_git_clone: bool = False      # expose the guarded git_clone tool to agents
    orchestrator: OrchestratorConfig = field(default_factory=OrchestratorConfig)
    analyzers: AnalyzersConfig = field(default_factory=AnalyzersConfig)
    # Per-agent LLM overrides, e.g. {"threat_model": {"model": "glm-4.7-flash"}}.
    # Any subset of LLMConfig fields (provider/model/temperature/base_url/...).
    agent_models: dict[str, dict] = field(default_factory=dict)

    # ------------------------------------------------------------------ load
    @classmethod
    def load(cls, path: str = DEFAULT_CONFIG_PATH) -> "Config":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(
                f"No config found at '{path}'. Run:  python cli.py setup"
            )
        raw = yaml.safe_load(p.read_text()) or {}
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Config":
        # Drop unknown keys (e.g. a legacy ``api_key_env`` from an older config)
        # so pre-existing config.yaml files keep loading after a field removal.
        llm_fields = {f.name for f in fields(LLMConfig)}
        llm_raw = {k: v for k, v in (raw.get("llm") or {}).items() if k in llm_fields}
        llm = LLMConfig(**llm_raw)
        rag_raw = dict(raw.get("rag") or {})
        emb = EmbeddingsConfig(**(rag_raw.pop("embeddings", {}) or {}))
        rag = RagConfig(embeddings=emb, **rag_raw)
        paths = _build(PathsConfig, raw.get("paths"))
        return cls(
            llm=llm,
            rag=rag,
            paths=paths,
            orchestrator=_build(OrchestratorConfig, raw.get("orchestrator")),
            analyzers=_build(AnalyzersConfig, raw.get("analyzers")),
            max_steps=raw.get("max_steps", 40),
            max_rounds=raw.get("max_rounds", 4),
            keep_reports=raw.get("keep_reports", 50),
            enable_git_clone=bool(raw.get("enable_git_clone", False)),
            agent_models=dict(raw.get("agent_models") or {}),
        )

    def ollama_base_url(self) -> str:
        """Where an Ollama server lives for this workspace.

        Embeddings are always local, so they need an Ollama URL even when the
        chat model isn't Ollama. ``llm.base_url`` only points at Ollama when
        it's the LLM provider — with ``anthropic`` it is the Anthropic endpoint
        (usually unset). Prefer an explicit ``rag.embeddings.base_url``, then the
        LLM's URL when it is in fact Ollama's, then the standard port.
        """
        if self.rag.embeddings.base_url:
            return self.rag.embeddings.base_url
        if self.llm.provider.lower() == "ollama" and self.llm.base_url:
            return self.llm.base_url
        return OLLAMA_DEFAULT_URL

    def llm_for(self, agent_name: str) -> LLMConfig:
        """Base LLM config with any per-agent overrides applied.

        An override that switches *provider* starts from that provider's own
        defaults rather than the base config: an Ollama ``base_url`` is
        meaningless to Claude (and vice versa), so inheriting it would point the
        agent at the wrong endpoint. Fields the override does name still win.
        """
        override = self.agent_models.get(agent_name) or {}
        if not override:
            return self.llm
        base = self.llm
        if str(override.get("provider", base.provider)).lower() != base.provider.lower():
            base = provider_defaults(str(override["provider"]))
        merged = dict(base.__dict__)
        for k, v in override.items():
            if k in merged:
                merged[k] = v
        return LLMConfig(**merged)

    # ------------------------------------------------------- resolved paths
    # Stored path fields are workspace-relative by default (e.g. ".phrack/rag").
    # These helpers turn them into absolute paths anchored at the workspace root,
    # so every consumer writes into the workspace's own ``.phrack/`` — not the
    # process CWD. An absolute stored path is honoured as-is (used by tests).
    def _ws_root(self) -> Path:
        return Path(self.paths.workspace).expanduser().resolve()

    @property
    def phrack_dir(self) -> Path:
        """The ``.phrack`` directory at the workspace root."""
        return self._ws_root() / PHRACK_DIRNAME

    def _resolve(self, path: str) -> Path:
        p = Path(path).expanduser()
        return p if p.is_absolute() else (self._ws_root() / p)

    def rag_dir(self) -> Path:
        return self._resolve(self.rag.persist_dir)

    def skills_dir(self) -> Path:
        return self._resolve(self.paths.skills_dir)

    def reports_dir(self) -> Path:
        return self._resolve(self.paths.reports_dir)

    def clones_dir(self) -> Path:
        return self._resolve(self.paths.clones_dir)

    def history_file(self) -> Path:
        return self.phrack_dir / "history"

    def credentials_file(self) -> Path:
        """The workspace's provider-API-key file (see ``credentials.py``)."""
        return self.phrack_dir / CREDENTIALS_FILENAME

    def to_dict(self) -> dict[str, Any]:
        return {
            "llm": self.llm.__dict__,
            "rag": {
                **{k: v for k, v in self.rag.__dict__.items() if k != "embeddings"},
                "embeddings": self.rag.embeddings.__dict__,
            },
            "paths": self.paths.__dict__,
            "orchestrator": self.orchestrator.__dict__,
            "analyzers": self.analyzers.__dict__,
            "max_steps": self.max_steps,
            "max_rounds": self.max_rounds,
            "keep_reports": self.keep_reports,
            "enable_git_clone": self.enable_git_clone,
            "agent_models": self.agent_models,
        }

    # ------------------------------------------------------------- show (redacted)
    _SECRET_HINTS = ("key", "token", "secret", "password", "passwd", "cookie")

    def show(self) -> str:
        """A human-readable YAML dump with any secret-looking values redacted.

        No API key is ever stored in this file — provider keys live in
        ``.phrack/credentials`` — but the redaction walk is defence-in-depth so
        `phrak config --show` is always safe to paste into a bug report."""
        redacted = _redact(self.to_dict(), self._SECRET_HINTS)
        return yaml.safe_dump(redacted, sort_keys=False)

    def save(self, path: str = DEFAULT_CONFIG_PATH) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)   # create .phrack/ if needed
        p.write_text(yaml.safe_dump(self.to_dict(), sort_keys=False))

    def ensure_dirs(self) -> None:
        for d in (
            self.phrack_dir,
            self.rag_dir(),
            self.skills_dir(),
            self.reports_dir(),
        ):
            Path(d).mkdir(parents=True, exist_ok=True)


def _redact(obj, hints):
    """Recursively redact dict values whose key looks secret.

    Only string values are candidates: a secret is always a string, while a
    number under a secret-looking key is a setting (``max_tokens`` matches the
    "token" hint but is a limit, not a credential) and redacting it would make
    `config --show` misleading.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if (
                isinstance(k, str)
                and isinstance(v, str)
                and v
                and any(h in k.lower() for h in hints)
            ):
                out[k] = "***redacted***"
            else:
                out[k] = _redact(v, hints)
        return out
    if isinstance(obj, list):
        return [_redact(v, hints) for v in obj]
    return obj


# ---------------------------------------------------------------- setup wizard
def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    ans = input(f"{prompt}{suffix}: ").strip()
    return ans or default


def _ask_secret(prompt: str) -> str:
    """Read a secret without echoing it. Falls back to plain input if the
    terminal can't suppress echo (piped stdin, some CI shells)."""
    import getpass

    try:
        return getpass.getpass(f"{prompt}: ").strip()
    except (EOFError, getpass.GetPassWarning, OSError):
        return input(f"{prompt} (visible): ").strip()


def _setup_ollama() -> LLMConfig:
    print("\nOllama keeps everything on this machine. Make sure the server is")
    print("running and your model is pulled (e.g. `ollama pull qwen2.5-coder:7b`).\n")
    llm = LLMConfig(provider="ollama")
    llm.model = _ask("Model", "qwen2.5-coder:7b")
    llm.base_url = _ask("Ollama base URL", OLLAMA_DEFAULT_URL)
    llm.temperature = float(_ask("Temperature", "0.1"))
    return llm


def _setup_anthropic(workspace: str) -> LLMConfig:
    """Configure the Claude provider and store its API key under ``.phrack``."""
    from .credentials import PROVIDER_ENV_VARS, get_key, set_key

    print("\nClaude runs in Anthropic's cloud: prompts — including the code")
    print("excerpts the agents read — are sent to the Anthropic API.\n")
    print("Suggested models:")
    for i, name in enumerate(ANTHROPIC_MODELS, 1):
        print(f"  {i}) {name}")
    choice = _ask("Model", ANTHROPIC_MODELS[0])
    model = (
        ANTHROPIC_MODELS[int(choice) - 1]
        if choice.isdigit() and 1 <= int(choice) <= len(ANTHROPIC_MODELS)
        else choice
    )
    # base_url stays empty: the SDK's own endpoint. temperature is left at the
    # dataclass default and only sent for models that still accept it (see llm.py).
    llm = provider_defaults("anthropic")
    llm.model = model
    llm.max_tokens = int(_ask("Max output tokens per response", str(llm.max_tokens)))

    var = PROVIDER_ENV_VARS["anthropic"]
    existing = get_key(workspace, "anthropic")
    prompt = f"{var}" + (" (Enter to keep the stored key)" if existing else "")
    key = _ask_secret(prompt)
    if key:
        dest = set_key(workspace, "anthropic", key)
        print(f"  key stored in {dest} (mode 0600)")
    elif existing:
        print(f"  keeping the key already in {credentials_path(workspace)}")
    else:
        print(f"  no key given — set one later with `phrak config`, or export {var}.")
    return llm


def run_setup(path: str | None = None) -> Config:
    """Interactive wizard that writes ``<workspace>/.phrack/config.yaml``.

    ``path`` pins an explicit destination (e.g. from ``-c``); when omitted the
    config is written into the chosen workspace's ``.phrack`` directory. An
    Anthropic API key, if one is given, goes to ``.phrack/credentials`` instead —
    never into the YAML.
    """
    print("\n=== PHRAK Agent — setup ===\n")

    # The workspace is asked first: it decides where .phrack — and therefore the
    # credentials file the provider step may write — lives.
    default_ws = os.getcwd()
    if path:
        pp = Path(path).expanduser().resolve()
        if pp.parent.name == PHRACK_DIRNAME:
            default_ws = str(pp.parent.parent)
    workspace = _ask("Default workspace (root for file tools + .phrack)", default_ws)

    print("\nModel provider:")
    print("  1) ollama     — fully local, nothing leaves this machine (default)")
    print("  2) anthropic  — Claude API; needs a key, sends prompts to Anthropic")
    choice = _ask("Provider", "1")
    provider = {"1": "ollama", "2": "anthropic"}.get(choice, choice.lower())
    if provider not in PROVIDERS:
        print(f"  unknown provider {provider!r} — falling back to ollama.")
        provider = "ollama"

    llm = _setup_anthropic(workspace) if provider == "anthropic" else _setup_ollama()

    print("\nEmbeddings for the codebase index (/ask retrieval) — always local:")
    print("  1) default  (local, no extra model needed)")
    print("  2) ollama   (needs an embedding model pulled, e.g. nomic-embed-text)")
    emb_choice = _ask("Embeddings", "1")
    emb_provider = {"1": "default", "2": "ollama"}.get(emb_choice, emb_choice)
    emb = EmbeddingsConfig(provider=emb_provider)
    if emb_provider == "ollama":
        emb.model = _ask("Embedding model", "nomic-embed-text")
        if provider != "ollama":
            # llm.base_url isn't an Ollama URL here, so ask where Ollama is.
            emb.base_url = _ask("Ollama base URL (embeddings)", OLLAMA_DEFAULT_URL)

    cfg = Config(
        llm=llm,
        rag=RagConfig(embeddings=emb),
        paths=PathsConfig(workspace=workspace),
    )
    save_path = path or str(default_config_path(workspace))
    cfg.ensure_dirs()
    cfg.save(save_path)
    print(f"\nWrote {save_path}. You can edit it any time.")
    return cfg
