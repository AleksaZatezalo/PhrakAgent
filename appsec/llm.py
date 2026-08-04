"""Chat-model factory.

PHRAK defaults to a local Ollama server; ``anthropic`` (Claude) is the opt-in
cloud alternative. Both client classes are lazy-imported so importing this
module stays cheap and a missing optional dependency only bites the provider
that needs it.

The Anthropic client takes no key here: ``credentials.load_into_env`` has
already exported ``ANTHROPIC_API_KEY`` into the process environment from
``.phrack/credentials``, and the SDK reads it from there.
"""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel

from .config import Config, LLMConfig

# Claude models that removed the sampling parameters: sending `temperature`
# to any of these is a 400, so it is dropped rather than passed through.
# Everything else (Sonnet 4.6, Haiku 4.5, …) still accepts it.
_NO_SAMPLING_PARAMS = (
    "claude-opus-5",
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-sonnet-5",
    "claude-fable-5",
    "claude-mythos-5",
)


def _accepts_temperature(model: str) -> bool:
    return not model.lower().startswith(_NO_SAMPLING_PARAMS)


def prompt_char_budget(cfg: LLMConfig) -> int:
    """Roughly how much prose this model can be handed in one prompt, in chars.

    The orchestrator uses this to size the material it passes between agents and
    into synthesis. A fixed cap can't serve both providers: one small enough for
    a 16k-token local window silently drops most of a Claude-sized report, and
    one sized for Claude overflows Ollama. English runs ~3.5 chars/token; half
    the window is budgeted so the system prompt and the answer still fit.
    """
    if cfg.provider.lower() == "anthropic":
        return 240_000        # ~70k tokens — well inside every current Claude window
    return max(4_000, int(cfg.num_ctx * 3.5 * 0.5))


def message_text(resp) -> str:
    """Flatten an LLM response (or its ``.content``) into plain text.

    Ollama hands back a plain string, but Anthropic returns a *list of content
    blocks* — ``{"type": "text", ...}``, ``{"type": "thinking", ...}``,
    ``tool_use``, … Everything downstream (markdown rendering, JSON extraction,
    saved reports) wants one string, and ``str(<list of dicts>)`` would leak
    Python reprs into the user's output, so join the text blocks and drop the
    rest.
    """
    content = getattr(resp, "content", resp)
    if isinstance(content, str):
        return content
    if content is None:
        return ""
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                # untyped blocks carrying text count; thinking/tool_use don't
                if block.get("type", "text") == "text":
                    text = block.get("text")
                    if isinstance(text, str):
                        parts.append(text)
            else:  # SDK block objects
                text = getattr(block, "text", None)
                if isinstance(text, str) and getattr(block, "type", "text") == "text":
                    parts.append(text)
        return "\n".join(p for p in parts if p)
    return str(content)


def _warn_if_ollama_unready(cfg: LLMConfig) -> None:
    """Best-effort heads-up when the local server or model isn't there.

    Otherwise the first failure lands deep inside an agent turn as a bare
    connection error, after the run has already spent time planning. Never
    fatal: a slow or unreachable check just stays quiet and lets the run try.
    """
    import json
    import urllib.request

    from .banner import GREY, RESET

    try:
        with urllib.request.urlopen(
            f"{cfg.base_url.rstrip('/')}/api/tags", timeout=2
        ) as resp:
            names = {m.get("name", "") for m in json.load(resp).get("models", [])}
    except Exception:
        print(f"  {GREY}… no Ollama server at {cfg.base_url} — start it with "
              f"`ollama serve`{RESET}")
        return
    # Ollama resolves a bare name to its ":latest" tag; match how it does.
    wanted = cfg.model if ":" in cfg.model else f"{cfg.model}:latest"
    if names and wanted not in names:
        print(f"  {GREY}… model '{cfg.model}' is not pulled — run "
              f"`ollama pull {cfg.model}`{RESET}")


def build_chat_model(cfg: LLMConfig) -> BaseChatModel:
    provider = cfg.provider.lower()

    if provider == "ollama":
        from langchain_ollama import ChatOllama

        _warn_if_ollama_unready(cfg)
        return ChatOllama(
            model=cfg.model,
            base_url=cfg.base_url,
            temperature=cfg.temperature,
            num_ctx=cfg.num_ctx,
        )

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        kwargs = {
            "model": cfg.model,
            # An explicit cap: the SDK's model-derived default (128k on Opus 5)
            # trips its own "too large for a non-streaming request" guard.
            "max_tokens": cfg.max_tokens,
        }
        if cfg.base_url:                 # else the SDK's own endpoint
            kwargs["base_url"] = cfg.base_url
        if _accepts_temperature(cfg.model):
            kwargs["temperature"] = cfg.temperature
        try:
            return ChatAnthropic(**kwargs)
        except Exception as e:
            # Almost always a missing key. The SDK resolves credentials from
            # more than one place (env var, auth token, an `ant auth login`
            # profile), so don't pre-check for one of them — let it try, then
            # say what to do when it can't.
            raise RuntimeError(
                f"Could not build the Anthropic client for '{cfg.model}': {e}\n"
                "Store a key with:  python cli.py setup\n"
                "or export ANTHROPIC_API_KEY in the shell."
            ) from e

    raise ValueError(
        f"Unknown LLM provider: {cfg.provider!r}. Supported providers are "
        f"'ollama' (local) and 'anthropic' (Claude API)."
    )


class ModelRegistry:
    """Builds and caches chat models, keyed by their effective config.

    Lets each agent use a different model/provider (``config.agent_models``)
    while sharing one instance across agents that resolve to the same config.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self._cache: dict[tuple, BaseChatModel] = {}

    @staticmethod
    def _key(cfg: LLMConfig) -> tuple:
        return (
            cfg.provider,
            cfg.model,
            cfg.base_url,
            round(cfg.temperature, 4),
            cfg.num_ctx,
            cfg.max_tokens,
        )

    def get(self, cfg: LLMConfig) -> BaseChatModel:
        key = self._key(cfg)
        if key not in self._cache:
            self._cache[key] = build_chat_model(cfg)
        return self._cache[key]

    def base(self) -> BaseChatModel:
        """Model for the orchestrator's own planning/routing/synthesis."""
        return self.get(self.config.llm)

    def for_agent(self, name: str) -> BaseChatModel:
        return self.get(self.config.llm_for(name))

    def describe(self, name: str) -> str:
        c = self.config.llm_for(name)
        return f"{c.provider}:{c.model}"
