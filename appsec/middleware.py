"""
Description: Middleware that rescues tool calls from models that "verbalize" them.
Author: Aleksa Zatezalo
Date Created: 08-01-2026
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


def extract_verbalized_calls(content: str, valid: set[str]):
    """Return (tool_calls, cleaned_content)."""
    calls, spans = [], []

    for m in list(_TAG.finditer(content)) + list(_FENCE.finditer(content)):
        for obj, _span in _iter_json_objects(m.group(1)):
            tc = _to_call(obj, valid)
            if tc:
                calls.append(tc)
                spans.append(m.span())

    if not calls:  # no tags/fences — scan raw content
        for obj, span in _iter_json_objects(content):
            tc = _to_call(obj, valid)
            if tc:
                calls.append(tc)
                spans.append(span)

    if not calls:
        return [], content

    cleaned = content
    for s, e in sorted(set(spans), reverse=True):
        cleaned = cleaned[:s] + cleaned[e:]
    return calls, cleaned.strip()


class VerbalizedToolCallMiddleware(AgentMiddleware):
    """Convert content-embedded tool calls into real tool calls."""

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
        return AIMessage(
            content=cleaned, tool_calls=calls, id=getattr(msg, "id", None)
        )
