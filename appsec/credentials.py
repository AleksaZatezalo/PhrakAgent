"""API keys for cloud model providers, stored inside the workspace's ``.phrack``.

PHRAK is local-first, but the ``anthropic`` provider needs a key. It lives in
``<workspace>/.phrack/credentials`` — deliberately **not** in ``config.yaml``,
which ``phrak config --show`` prints and which the RAG indexer embeds (``.phrack``
is indexed on purpose so ``/ask`` can answer questions about reports and config).
The credentials file is created ``0600`` and has no indexed extension, so it is
never chunked into the vector store.

At startup :func:`load_into_env` exports each stored key as a process-wide
environment variable — ``ANTHROPIC_API_KEY`` for ``anthropic`` — which is where
the provider SDK looks for it. Nothing downstream has to thread a key through:
the chat-model factory just builds the client and the SDK picks the key up.
"""

from __future__ import annotations

import os
from pathlib import Path

from .config import Config, credentials_path

# provider -> the environment variable its SDK reads. Adding a cloud provider
# means adding a row here plus a branch in llm.build_chat_model.
PROVIDER_ENV_VARS: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
}


def read_all(workspace: str | Path = ".") -> dict[str, str]:
    """Every ``NAME=value`` pair in the workspace's credentials file.

    A missing or unreadable file is an empty mapping — a workspace with no
    cloud provider configured is the normal case, not an error.
    """
    p = credentials_path(workspace)
    try:
        text = p.read_text()
    except OSError:
        return {}
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        name, value = name.strip(), value.strip()
        if name:
            out[name] = value
    return out


def get_key(workspace: str | Path, provider: str) -> str:
    """The stored key for ``provider``, or "" if there isn't one."""
    var = PROVIDER_ENV_VARS.get(provider.lower())
    return read_all(workspace).get(var, "") if var else ""


def set_key(workspace: str | Path, provider: str, key: str) -> Path:
    """Store (or clear, with an empty ``key``) a provider's API key.

    Other providers' entries are preserved. The file is written ``0600`` before
    any content lands in it, so the key is never briefly world-readable.
    """
    var = PROVIDER_ENV_VARS.get(provider.lower())
    if not var:
        raise ValueError(f"{provider!r} does not take an API key")

    entries = read_all(workspace)
    if key:
        entries[var] = key
    else:
        entries.pop(var, None)

    p = credentials_path(workspace)
    p.parent.mkdir(parents=True, exist_ok=True)
    body = (
        "# PHRAK provider API keys — keep out of version control.\n"
        "# Managed by `phrak config`; exported as environment variables at startup.\n"
        + "".join(f"{k}={v}\n" for k, v in sorted(entries.items()))
    )
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(body)
    os.chmod(p, 0o600)   # re-assert in case the file already existed
    return p


def load_into_env(config: Config) -> list[str]:
    """Export the workspace's stored keys as environment variables.

    Returns the variable names that were set. The stored key **wins over one
    already exported in the shell**: it is this workspace's explicit
    configuration, so a stale ambient key shouldn't silently take precedence.
    """
    exported = []
    for name, value in read_all(config.paths.workspace).items():
        if value:
            os.environ[name] = value
            exported.append(name)
    return exported


def missing_key_hint(config: Config) -> str:
    """Warning text if the configured provider needs a key and none is set.

    Empty string when everything the provider needs is present — callers print
    it verbatim and skip when it's falsy.
    """
    provider = config.llm.provider.lower()
    var = PROVIDER_ENV_VARS.get(provider)
    if not var or os.environ.get(var):
        return ""
    return (
        f"no {var} found — the '{provider}' provider will fail. "
        f"Run `phrak config` to store one in "
        f"{credentials_path(config.paths.workspace)}."
    )
