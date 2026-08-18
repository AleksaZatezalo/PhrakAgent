"""
Description: Middleware that rescues tool calls from models that "verbalize" them.
Author: Aleksa Zatezalo
Date Created: 08-01-2026

SECURITY: Verbalized-call extraction is a compensating control for weak local
models that print JSON instead of emitting structured tool calls. It's also a
prompt-injection surface — content the model saw (a file it read, a user
message it quoted, an "example" it's warning about) can end up echoed into the
reply as JSON that *looks* like a call. The rules below narrow what counts as a
genuine intent to call a tool:

  1. Only fenced code blocks (```...```) or explicit <tool_call>...</tool_call>
     tags are considered — raw JSON in prose is IGNORED. The prior fallback
     that scanned bare content is removed.
  2. Even inside a fence, if the surrounding prose (± ~120 chars) frames the
     block as an example ("for example", "for instance", "e.g.", "such as",
     "do not run", "never run"), the call is skipped.
  3. Inline `code spans` and blockquoted lines (`> ...`) never trigger a call.
"""

from __future__ import annotations

import json
import re
import uuid

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import AIMessage

from .llm import message_text

_FENCE = re.compile(r"```(?:json|tool_call|python)?\s*(.*?)```", re.DOTALL)
_TAG = re.compile(r"<tool_call>\s*(.*?)\s*</tool_call>", re.DOTALL)

# Words in nearby prose that flag a fenced block as illustrative, not a call.
_EXAMPLE_MARKERS = re.compile(
    r"\b(for\s+example|for\s+instance|e\.?g\.?|such\s+as|do\s+not\s+run|"
    r"never\s+run|do\s+not\s+actually|would\s+print|might\s+print|"
    r"bad\s+model|illustrat\w+|hypothetical|wire\s+format)\b",
    re.IGNORECASE,
)

# How much context around a fenced block to examine for example markers.
_EXAMPLE_WINDOW = 120


def _iter_json_objects(text: str):
    """Yield (obj, (start, end)) for each top-level balanced JSON object."""
    depth, start = 0, None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start is not None:
                frag = text[start : i + 1]
                try:
                    yield json.loads(frag), (start, i + 1)
                except json.JSONDecodeError:
                    pass
                start = None


def _to_call(obj: dict, valid: set[str]):
    if not isinstance(obj, dict):
        return None
    name = obj.get("name")
    if not isinstance(name, str) or (valid and name not in valid):
        return None
    args = obj.get("arguments", obj.get("parameters", obj.get("args", {})))
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {}
    if not isinstance(args, dict):
        args = {}
    return {"name": name, "args": args, "id": uuid.uuid4().hex, "type": "tool_call"}


def _looks_like_example(content: str, span: tuple[int, int]) -> bool:
    """True if the prose around the fenced block frames it as illustrative."""
    s, e = span
    before = content[max(0, s - _EXAMPLE_WINDOW) : s]
    after = content[e : e + _EXAMPLE_WINDOW]
    return bool(_EXAMPLE_MARKERS.search(before) or _EXAMPLE_MARKERS.search(after))


def _blockquoted_lines(content: str) -> set[int]:
    """Character offsets that fall inside a `> ...` blockquote line."""
    offsets: set[int] = set()
    pos = 0
    for line in content.splitlines(keepends=True):
        if line.lstrip().startswith(">"):
            offsets.update(range(pos, pos + len(line)))
        pos += len(line)
    return offsets


def _inline_code_spans(content: str) -> list[tuple[int, int]]:
    """Spans covered by single-backtick inline `code` (not triple-backtick fences).

    Runs of exactly one backtick pair, non-greedy. Triple fences are already
    consumed by _FENCE — we just avoid matching them here by requiring the
    delimiters not to be `` ` `` runs of length >1.
    """
    spans: list[tuple[int, int]] = []
    for m in re.finditer(r"(?<!`)`([^`\n]+?)`(?!`)", content):
        spans.append(m.span())
    return spans


def _in_any_span(pos: int, spans: list[tuple[int, int]]) -> bool:
    return any(s <= pos < e for s, e in spans)


def extract_verbalized_calls(content: str, valid: set[str]):
    """Return (tool_calls, cleaned_content).

    Only fenced ``` blocks and <tool_call> tags are considered. Bare JSON in
    prose is ignored (was previously extracted, which is a prompt-injection
    hazard when the model echoes content it read). Fenced blocks are also
    skipped when the surrounding prose flags them as illustrative examples.
    """
    calls, spans = [], []

    quoted = _blockquoted_lines(content)
    inline_spans = _inline_code_spans(content)

    def _is_quoted_or_inline(span: tuple[int, int]) -> bool:
        s, _ = span
        return s in quoted or _in_any_span(s, inline_spans)

    for m in list(_TAG.finditer(content)):
        if _is_quoted_or_inline(m.span()):
            continue
        # <tool_call> is unambiguous intent — no example-marker check.
        for obj, _ in _iter_json_objects(m.group(1)):
            tc = _to_call(obj, valid)
            if tc:
                calls.append(tc)
                spans.append(m.span())

    for m in list(_FENCE.finditer(content)):
        if _is_quoted_or_inline(m.span()):
            continue
        if _looks_like_example(content, m.span()):
            continue
        for obj, _ in _iter_json_objects(m.group(1)):
            tc = _to_call(obj, valid)
            if tc:
                calls.append(tc)
                spans.append(m.span())

    if not calls:
        return [], content

    cleaned = content
    for s, e in sorted(set(spans), reverse=True):
        cleaned = cleaned[:s] + cleaned[e:]
    return calls, cleaned.strip()


class VerbalizedToolCallMiddleware(AgentMiddleware):
    """Convert content-embedded tool calls into real tool calls.

    Off by default for capable providers (Anthropic emits structured calls
    natively); on for Ollama, whose small models frequently print JSON.
    """

    def __init__(self, enabled: bool = True) -> None:
        super().__init__()
        self.enabled = enabled

    @staticmethod
    def _valid_tool_names(request) -> set[str]:
        names: set[str] = set()
        tools = getattr(request, "tools", None) or []
        for t in tools:
            n = getattr(t, "name", None) or (
                t.get("name") if isinstance(t, dict) else None
            )
            if n:
                names.add(n)
        return names

    def wrap_model_call(self, request, handler):
        response = handler(request)
        if not self.enabled:
            return response
        msgs = getattr(response, "result", None)
        if not msgs:
            return response
        msg = msgs[-1]
        if not isinstance(msg, AIMessage) or getattr(msg, "tool_calls", None):
            return response  # already has structured calls, or not an AI message

        content = message_text(msg)
        if not content:
            return response
        calls, cleaned = extract_verbalized_calls(
            content, self._valid_tool_names(request)
        )
        if not calls:
            return response
        return AIMessage(content=cleaned, tool_calls=calls, id=getattr(msg, "id", None))
