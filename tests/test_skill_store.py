"""Learned-skills store: write/read/list + lexical relevance + prompt block."""

from __future__ import annotations


def test_skills_roundtrip(skills):
    path = skills.write_skill(
        "sqli-taint-trace",
        "user input reaches a SQL query",
        ["find sources", "trace to sink"],
    )
    assert path.endswith("sqli-taint-trace.md")
    assert "sqli-taint-trace" in skills.list_skills()
    body = skills.read_skill("sqli-taint-trace")
    assert "When to use" in body


def test_read_missing_skill_is_empty(skills):
    assert skills.read_skill("does-not-exist") == ""


def test_relevant_skills_ranks_by_overlap(skills):
    skills.write_skill("sqli-taint-trace", "user input reaches a SQL query",
                       ["find sources", "trace to sink"])
    skills.write_skill("xss-review", "reflected output without encoding",
                       ["find sinks"])
    relevant = skills.relevant_skills("trace user input to a sql sink")
    assert relevant and any("sqli" in r.lower() for r in relevant)


def test_skills_block_empty_when_no_match(skills):
    skills.write_skill("xss-review", "reflected output", ["find sinks"])
    assert skills.skills_block("totally unrelated cryptography question") == ""


def test_skills_block_formats_section(skills):
    skills.write_skill("sqli-taint-trace", "user input reaches a SQL query",
                       ["find sources"])
    block = skills.skills_block("sql injection user input")
    assert block.startswith("## Applicable skills")
    assert "sqli-taint-trace" in block
