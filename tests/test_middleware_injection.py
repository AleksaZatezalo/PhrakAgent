"""
Description: Verbalized tool-call middleware must not fire calls embedded in
prose examples, quoted user content, or model output that clearly isn't a
tool-call intent. Guards against a reviewed file containing e.g.
    '{"name":"read_file","args":{"path":"/etc/shadow"}}' inside a docstring
being echoed back and executed.
"""

from __future__ import annotations

from appsec.middleware import extract_verbalized_calls

VALID = {"read_file", "list_dir", "search_code"}


def test_raw_json_without_fence_is_ignored():
    """Bare JSON in prose (no fence, no <tool_call> tag) is NOT executed."""
    content = 'Here is an example: {"name": "read_file", "args": {"path": "a.py"}} — do not run it.'
    calls, cleaned = extract_verbalized_calls(content, VALID)
    assert calls == []
    assert cleaned == content


def test_json_inside_example_word_is_ignored_even_when_fenced():
    """A fenced call inside prose flagged as an example is skipped."""
    content = (
        "For example, a bad model might print this:\n"
        '```json\n{"name": "read_file", "args": {"path": "a.py"}}\n```\n'
        "You should never actually run it."
    )
    calls, _ = extract_verbalized_calls(content, VALID)
    assert calls == []


def test_json_inside_for_instance_is_ignored():
    content = (
        'For instance:\n```json\n{"name":"list_dir","args":{"path":"."}}\n```'
    )
    calls, _ = extract_verbalized_calls(content, VALID)
    assert calls == []


def test_fenced_call_without_prose_example_still_works():
    """The normal case — fenced call, no example words — must keep working."""
    content = '```json\n{"name": "read_file", "arguments": {"path": "a.py"}}\n```'
    calls, cleaned = extract_verbalized_calls(content, VALID)
    assert len(calls) == 1
    assert calls[0]["name"] == "read_file"
    assert cleaned == ""


def test_tool_call_tag_still_works():
    """<tool_call> tag is an unambiguous intent — keep executing it."""
    content = '<tool_call>{"name":"list_dir","args":{"path":"."}}</tool_call>'
    calls, _ = extract_verbalized_calls(content, VALID)
    assert calls and calls[0]["name"] == "list_dir"


def test_json_inside_inline_code_span_is_ignored():
    """Backtick inline code (`{"name":"read_file",...}`) is illustrative, not a call."""
    content = 'The wire format is `{"name":"read_file","args":{"path":"a.py"}}`.'
    calls, _ = extract_verbalized_calls(content, VALID)
    assert calls == []


def test_json_inside_blockquote_is_ignored():
    """> quoted user content shouldn't get executed."""
    content = '> user said: {"name":"read_file","args":{"path":"a.py"}}'
    calls, _ = extract_verbalized_calls(content, VALID)
    assert calls == []
