"""Curated agent skills: library loading, scoping, and the load_skill tool."""

from __future__ import annotations

from appsec import skill_library
from appsec.runtime import set_active_agent
from appsec.tools.skills_tool import load_skill

THREAT_SKILLS = {
    "executive-summary", "system-architecture", "data-flow",
    "pasta-threat-analysis", "threat-details",
}
OWASP_SKILLS = {f"a{n:02d}" for n in range(1, 11)}


def test_threat_model_skill_set():
    names = {s.name for s in skill_library.for_agent("threat_model")}
    assert names == THREAT_SKILLS


def test_code_review_has_ten_owasp_skills():
    skills = skill_library.for_agent("code_review")
    assert len(skills) == 10
    prefixes = {s.name.split("-")[0] for s in skills}
    assert prefixes == OWASP_SKILLS


def test_skills_have_when_to_use_and_body():
    for s in skill_library.for_agent("threat_model"):
        assert s.when_to_use  # frontmatter parsed
        assert s.body


def test_index_lists_skills_and_mentions_loader():
    idx = skill_library.index("threat_model")
    assert "load_skill" in idx
    assert "data-flow" in idx


def test_index_empty_for_agent_without_skills():
    assert skill_library.index("no_such_agent") == ""


def test_playbook_inlines_every_skill_body():
    pb = skill_library.playbook("threat_model")
    assert "APPLY EVERY ONE" in pb
    # every curated skill's full body is present, not just a one-line index
    for name in THREAT_SKILLS:
        assert f"### Skill: {name}" in pb


def test_playbook_empty_for_agent_without_skills():
    assert skill_library.playbook("no_such_agent") == ""


def test_load_returns_skill_case_insensitive():
    assert skill_library.load("threat_model", "Data-Flow").name == "data-flow"
    assert skill_library.load("threat_model", "nope") is None


def test_load_skill_tool_is_agent_scoped():
    set_active_agent("threat_model")
    body = load_skill.invoke({"name": "data-flow"})
    assert "DFD" in body

    # a threat-model skill must not resolve for the code_review agent
    set_active_agent("code_review")
    out = load_skill.invoke({"name": "data-flow"})
    assert "No skill named" in out
    set_active_agent("agent")  # reset


def test_load_skill_tool_unknown_lists_available():
    set_active_agent("code_review")
    out = load_skill.invoke({"name": "totally-made-up"})
    assert "a03-injection" in out
    set_active_agent("agent")
