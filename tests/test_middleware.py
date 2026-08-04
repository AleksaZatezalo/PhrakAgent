"""Rescuing verbalized tool calls from models that don't emit structured calls."""

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


def test_raw_json_with_parameters_key():
    content = 'sure: {"name": "read_file", "parameters": {"path": "x"}} done'
    calls, _ = extract_verbalized_calls(content, VALID)
    assert calls and calls[0]["args"] == {"path": "x"}


def test_args_as_json_string_is_parsed():
    content = '{"name": "read_file", "arguments": "{\\"path\\": \\"y\\"}"}'
    calls, _ = extract_verbalized_calls(content, VALID)
    assert calls and calls[0]["args"] == {"path": "y"}


def test_unknown_tool_name_rejected():
    content = '{"name": "definitely_not_a_tool", "args": {}}'
    calls, cleaned = extract_verbalized_calls(content, VALID)
    assert calls == []
    assert cleaned == content


def test_plain_text_returns_no_calls():
    calls, cleaned = extract_verbalized_calls("just a normal answer", VALID)
    assert calls == []
    assert cleaned == "just a normal answer"
