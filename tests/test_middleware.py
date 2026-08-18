"""
Description: Rescuing verbalized tool calls from models that don't emit structured calls.
Author: Aleksa Zatezalo
Date Created: 07-29-2026
"""

from __future__ import annotations

from appsec.middleware import extract_verbalized_calls

VALID = {"read_file", "list_dir", "search_code"}


def test_fenced_json_block():
    content = '```json\n{"name": "read_file", "arguments": {"path": "a.py"}}\n```'
    calls, cleaned = extract_verbalized_calls(content, VALID)
    assert len(calls) == 1
    assert calls[0]["name"] == "read_file"
    assert calls[0]["args"] == {"path": "a.py"}
    assert cleaned == ""


def test_tool_call_tag():
    content = '<tool_call>{"name": "list_dir", "args": {"path": "."}}</tool_call>'
    calls, _ = extract_verbalized_calls(content, VALID)
    assert calls and calls[0]["name"] == "list_dir"


def test_fenced_parameters_key():
    """`parameters` (vs `arguments`) alias still works inside a fence."""
    content = (
        '```json\n{"name": "read_file", "parameters": {"path": "x"}}\n```'
    )
    calls, _ = extract_verbalized_calls(content, VALID)
    assert calls and calls[0]["args"] == {"path": "x"}


def test_args_as_json_string_is_parsed():
    """`arguments` value can be a JSON-encoded string; still parsed (in a fence)."""
    content = (
        '```json\n{"name": "read_file", "arguments": "{\\"path\\": \\"y\\"}"}\n```'
    )
    calls, _ = extract_verbalized_calls(content, VALID)
    assert calls and calls[0]["args"] == {"path": "y"}


def test_raw_json_in_prose_is_ignored_security():
    """Bare JSON in prose is ignored — prompt-injection hardening."""
    content = 'sure: {"name": "read_file", "parameters": {"path": "x"}} done'
    calls, cleaned = extract_verbalized_calls(content, VALID)
    assert calls == []
    assert cleaned == content


def test_unknown_tool_name_rejected():
    content = '{"name": "definitely_not_a_tool", "args": {}}'
    calls, cleaned = extract_verbalized_calls(content, VALID)
    assert calls == []
    assert cleaned == content


def test_plain_text_returns_no_calls():
    calls, cleaned = extract_verbalized_calls("just a normal answer", VALID)
    assert calls == []
    assert cleaned == "just a normal answer"
