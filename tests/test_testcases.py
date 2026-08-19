"""
Description: Test-case model, backlog store, and the non-agentic management commands.
Author: Aleksa Zatezalo
Date Created: 08-18-2026
"""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace

from appsec.models.findings import FindingEvidence, SecurityFinding
from appsec.models.testcases import (
    SecurityTestCase,
    dedupe_test_cases,
    normalize_result,
    normalize_status,
    validate_test_case,
)
from appsec.store import FindingStore
from appsec.store import TestCaseStore as Store  # aliased: not a test class
from appsec.testcase_cmds import (
    add_manual_test_case,
    link_test_case,
    note_test_case,
    parse_testcase_flags,
    prompt_for_test_case,
    set_test_case_status,
)

# These are named test_* in the source; import them under different names so
# pytest doesn't try to collect the imported functions as test cases.
from appsec.testcase_cmds import test_case_detail as detail_of
from appsec.testcase_cmds import test_cases_json as backlog_json
from appsec.testcase_cmds import test_cases_list as list_backlog


def _case(**over) -> SecurityTestCase:
    base = dict(
        title="SQLi via id parameter",
        target="GET /user?id",
        steps=["send id=1' OR '1'='1", "observe the response"],
        expected_result="all rows returned proves injection",
        severity="high",
        source_agent="test_case",
    )
    base.update(over)
    return SecurityTestCase(**base).ensure_identity()


def _finding(**over) -> SecurityFinding:
    base = dict(
        title="SQL injection in /user",
        category="SQL injection",
        severity="high",
        confidence=0.8,
        affected_files=["app.py"],
        evidence=[FindingEvidence(path="app.py", start_line=11, reason="tainted")],
        source_agent="code_review",
    )
    base.update(over)
    return SecurityFinding(**base).ensure_identity()


def _app(config, cases=(), findings=()):
    if cases:
        Store(config).upsert(list(cases))
    if findings:
        FindingStore(config).upsert(list(findings), run_id="r1")
    return SimpleNamespace(config=config)


# ---------------------------------------------------------------- the model
def test_id_is_generated_and_stable():
    a, b = _case(), _case()
    assert a.id.startswith("TC-") and a.id == b.id  # same title+target -> same id
    assert _case(title="Something else").id != a.id


def test_id_is_not_overwritten_when_already_set():
    tc = SecurityTestCase(title="t", target="x", id="TC-custom").ensure_identity()
    assert tc.id == "TC-custom"


def test_validation_requires_the_parts_that_make_a_test_runnable():
    errs = validate_test_case(SecurityTestCase(title="only a title"))
    joined = " ".join(errs)
    assert "target is required" in joined
    assert "at least one step" in joined
    assert "expected_result is required" in joined
    assert validate_test_case(_case()) == []


def test_validation_rejects_bad_vocabulary():
    assert any("severity" in e for e in validate_test_case(_case(severity="spicy")))
    assert any("status" in e for e in validate_test_case(_case(status="maybe")))
    assert any("result" in e for e in validate_test_case(_case(result="probably")))


def test_status_and_result_normalization():
    assert normalize_status("In Progress") == "in_progress"
    assert normalize_status("in-progress") == "in_progress"
    assert normalize_status("DONE") == "complete"
    assert normalize_status("nonsense") == ""
    assert normalize_result("PASS") == "pass"
    assert normalize_result("") == ""
    assert normalize_result("maybe") == "!"  # sentinel for invalid


def test_round_trip_serialization():
    tc = _case(finding_id="FND-abc", notes=["ran it"])
    back = SecurityTestCase.from_dict(json.loads(json.dumps(tc.to_dict())))
    assert back.id == tc.id and back.steps == tc.steps
    assert back.finding_id == "FND-abc" and back.notes == ["ran it"]


def test_dedupe_keeps_the_richer_test_and_preserves_a_link():
    thin = _case(finding_id="FND-abc")
    rich = _case(steps=["a", "b", "c", "d"])
    out = dedupe_test_cases([thin, rich])
    assert len(out) == 1
    assert len(out[0].steps) == 4  # richer wins
    assert out[0].finding_id == "FND-abc"  # link survives


# ---------------------------------------------------------------- the store
def test_upsert_preserves_operator_progress_across_reauthoring(config):
    """Re-running test_case must refresh instructions, never your progress."""
    store = Store(config)
    store.upsert([_case()])
    ident = _case().id
    store.set_status(ident, "complete", "fail")
    store.link_finding(ident, "FND-abc123")
    store.add_note(ident, "reproduced on staging")

    store.upsert([_case(steps=["new 1", "new 2", "new 3"], severity="critical")])

    tc = store.get(ident)
    assert tc.steps == ["new 1", "new 2", "new 3"]  # instructions refreshed
    assert tc.severity == "critical"
    assert tc.status == "complete" and tc.result == "fail"  # progress kept
    assert tc.finding_id == "FND-abc123"
    assert len(tc.notes) == 1


def test_add_refuses_a_duplicate(config):
    store = Store(config)
    _, first = store.add(_case())
    assert "added" in first
    _, second = store.add(_case())
    assert "already exists" in second
    assert len(store.list()) == 1


def test_lookup_by_prefix_and_missing(config):
    store = Store(config)
    store.upsert([_case()])
    ident = _case().id
    assert store.get(ident) is not None
    assert store.get(ident[3:11]) is not None  # fingerprint prefix
    assert store.get("nope") is None


def test_parallel_upserts_lose_nothing(config):
    barrier = threading.Barrier(3)

    def agent(base):
        batch = [_case(title=f"Test {i}") for i in range(base, base + 5)]
        barrier.wait()
        Store(config).upsert(batch)

    threads = [threading.Thread(target=agent, args=(b,)) for b in (0, 100, 200)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert len(Store(config).list()) == 15


# ------------------------------------------------------------- the commands
def test_list_empty_and_populated(config):
    assert "No test cases recorded yet" in list_backlog(_app(config))
    out = list_backlog(_app(config, [_case()]))
    assert "1 test case(s)" in out and "SQLi via id parameter" in out


def test_list_filters(config):
    app = _app(config, [_case(), _case(title="XSS in search", severity="low")])
    assert "XSS" not in list_backlog(app, severity="high")
    assert "SQLi" not in list_backlog(app, severity="low")
    assert "2 test case(s)" in list_backlog(app, status="new")  # both start new
    assert "No test cases match" in list_backlog(app, status="complete")
    assert "2 test case(s)" in list_backlog(app, unlinked=True)

    Store(config).set_status(_case().id, "complete")
    assert "1 test case(s)" in list_backlog(app, status="complete")
    assert "1 test case(s)" in list_backlog(app, status="new")


def test_list_rejects_unknown_filter_values(config):
    """A typo'd filter must not read as 'you have no such test cases'."""
    app = _app(config, [_case()])
    assert "Unknown severity 'spicy'" in list_backlog(app, severity="spicy")
    assert "Unknown status 'maybe'" in list_backlog(app, status="maybe")


def test_parse_flags_shape_only():
    kwargs, err = parse_testcase_flags("--status Complete --finding FND-1 --unlinked")
    assert err == ""
    assert kwargs["status"] == "Complete" and kwargs["unlinked"] is True
    assert "unknown or incomplete" in parse_testcase_flags("--status")[1]
    assert "unknown or incomplete" in parse_testcase_flags("--bogus")[1]


def test_detail_and_missing(config):
    app = _app(config, [_case()])
    out = detail_of(app, _case().id)
    assert "SQLi via id parameter" in out and "Expected result" in out
    assert "usage: /testcase" in detail_of(app, "")
    assert "No test case matching" in detail_of(app, "nope")


def test_set_status_with_and_without_result(config):
    app = _app(config, [_case()])
    ident = _case().id
    assert "status -> in_progress" in set_test_case_status(app, f"{ident} in-progress")
    out = set_test_case_status(app, f"{ident} complete fail")
    assert "status -> complete" in out and "result=fail" in out
    assert Store(config).get(ident).result == "fail"


def test_set_status_rejects_bad_vocabulary(config):
    app = _app(config, [_case()])
    ident = _case().id
    assert "Unknown status 'finished'" in set_test_case_status(app, f"{ident} finished")
    assert "Unknown result" in set_test_case_status(app, f"{ident} complete perhaps")
    assert "usage:" in set_test_case_status(app, ident)


def test_link_to_a_real_finding(config):
    f = _finding()
    app = _app(config, [_case()], [f])
    out = link_test_case(app, f"{_case().id} {f.id}")
    assert f.id in out and "SQL injection in /user" in out
    assert Store(config).get(_case().id).finding_id == f.id


def test_link_rejects_an_unknown_finding_id(config):
    """A typo'd link should fail now, not silently at report time."""
    app = _app(config, [_case()], [_finding()])
    out = link_test_case(app, f"{_case().id} FND-doesnotexist")
    assert "No finding matching" in out
    assert Store(config).get(_case().id).finding_id == ""


def test_link_can_be_cleared(config):
    f = _finding()
    app = _app(config, [_case()], [f])
    link_test_case(app, f"{_case().id} {f.id}")
    assert "cleared" in link_test_case(app, f"{_case().id} none")
    assert Store(config).get(_case().id).finding_id == ""


def test_note(config):
    app = _app(config, [_case()])
    assert "note added" in note_test_case(app, f"{_case().id} blocked on creds")
    assert "blocked on creds" in Store(config).get(_case().id).notes[0]
    assert "usage: /testcase-note" in note_test_case(app, "only-an-id")


def test_json_export(config):
    assert json.loads(backlog_json(_app(config))) == []  # empty store first
    data = json.loads(backlog_json(_app(config, [_case()])))
    assert len(data) == 1
    assert data[0]["id"] == _case().id
    assert data[0]["title"] == "SQLi via id parameter"


# --------------------------------------------------------- manual entry (no AI)
def test_add_manual_test_case(config):
    app = _app(config)
    out = add_manual_test_case(
        app,
        title="Rate limit on /login",
        target="POST /login",
        steps="1. send 100 requests\n2. observe",
        expected_result="requests are throttled after N",
        severity="medium",
    )
    assert "added TC-" in out
    tc = Store(config).list()[0]
    assert tc.steps == ["send 100 requests", "observe"]  # numbering stripped
    assert tc.source_agent == ""  # marks it hand-written
    assert tc.status == "new"


def test_manual_steps_accept_the_separators_a_shell_can_produce(config):
    from appsec.tools.testcase_tool import _steps

    assert _steps("a\nb") == ["a", "b"]
    assert _steps("a | b") == ["a", "b"]
    assert _steps(r"1. a\n2. b") == ["a", "b"]  # literal backslash-n from a shell
    assert _steps("- a\n* b\n3) c") == ["a", "b", "c"]  # numbering stripped
    assert _steps("") == []


def test_add_manual_test_case_validates(config):
    app = _app(config)
    assert "Unknown severity" in add_manual_test_case(
        app, title="t", target="x", steps="a", expected_result="b", severity="spicy"
    )
    assert "Not added" in add_manual_test_case(
        app, title="t", target="x", steps="", expected_result="b"
    )


def test_add_manual_test_case_with_a_finding_link(config):
    f = _finding()
    app = _app(config, findings=[f])
    out = add_manual_test_case(
        app,
        title="Verify the SQLi",
        target="GET /user",
        steps="send a quote",
        expected_result="error reveals injection",
        finding_id=f.id,
    )
    assert "added" in out
    assert Store(config).list()[0].finding_id == f.id


def test_add_manual_test_case_rejects_an_unknown_finding(config):
    app = _app(config)
    out = add_manual_test_case(
        app,
        title="t",
        target="x",
        steps="a",
        expected_result="b",
        finding_id="FND-nope",
    )
    assert "No finding matching" in out
    assert Store(config).list() == []


def test_interactive_prompt_collects_fields():
    answers = iter(
        [
            "Auth bypass on /admin",  # title
            "GET /admin",  # target
            "log out",  # step 1
            "request /admin",  # step 2
            "",  # end steps
            "admin page renders without a session",  # expected
            "high",  # severity
            "",  # objective
            "",  # preconditions
            "",  # finding id
        ]
    )
    fields = prompt_for_test_case(ask=lambda _prompt: next(answers))
    assert fields["title"] == "Auth bypass on /admin"
    assert fields["steps"] == "log out\nrequest /admin"
    assert fields["severity"] == "high"
    assert fields["finding_id"] == ""


def test_interactive_prompt_aborts_on_interrupt():
    def _ask(_prompt):
        raise KeyboardInterrupt

    assert prompt_for_test_case(ask=_ask) is None
