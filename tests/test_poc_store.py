"""
Description: PoC store (list/get/save) + /poc command helpers, no container.
Author: Aleksa Zatezalo
Date Created: 09-22-2026
"""

from __future__ import annotations

from types import SimpleNamespace

from appsec.poc_cmds import list_pocs, poc_detail, run_poc
from appsec.poc_store import PocStore, render_detail, render_list


def _app(config):
    return SimpleNamespace(config=config)


# ------------------------------------------------------------------- store
def test_save_assigns_id_and_infers_kind(config):
    store = PocStore(config)
    py = store.save("FND-1", "print('x')", outcome="confirmed")
    sh = store.save("FND-2", "#!/bin/bash\ncurl $PHRAK_TARGET")
    assert py.id.startswith("POC-") and py.filename.endswith(".py")
    assert py.kind == "python" and py.outcome == "confirmed"
    assert sh.kind == "sh" and sh.filename.endswith(".sh")
    # both persisted and readable
    assert store.read_script(py) == "print('x')"
    assert len(store.list()) == 2


def test_save_empty_is_noop(config):
    assert PocStore(config).save("FND-1", "   ") is None
    assert PocStore(config).list() == []


def test_get_by_id_suffix_and_finding(config):
    store = PocStore(config)
    rec = store.save("FND-abc", "print('x')")
    assert store.get(rec.id).id == rec.id
    assert store.get(rec.id[-6:]).id == rec.id  # suffix match
    assert store.get("FND-abc").id == rec.id  # by finding id
    assert store.get("nope") is None


def test_set_target_records_last_url(config):
    store = PocStore(config)
    rec = store.save("FND-abc", "print('x')")
    store.set_target(rec, "http://localhost:8000")
    assert store.get(rec.id).target == "http://localhost:8000"


# --------------------------------------------------------------- rendering
def test_render_list_empty_and_populated(config):
    assert "No PoCs" in render_list([])
    rec = PocStore(config).save("FND-abc", "print('x')", outcome="confirmed")
    text = render_list([rec])
    assert rec.id in text and "FND-abc" in text


def test_render_detail_has_fenced_script(config):
    rec = PocStore(config).save("FND-abc", "print('x')")
    text = render_detail(rec, "print('x')")
    assert "```python" in text and "print('x')" in text


# ---------------------------------------------------------- command helpers
def test_list_and_detail_via_helpers(config):
    rec = PocStore(config).save("FND-abc", "print('x')")
    assert rec.id in list_pocs(_app(config))
    assert rec.id in poc_detail(_app(config), rec.id)
    assert "no PoC matching" in poc_detail(_app(config), "POC-zzz")


def test_run_poc_off_by_default(config):
    assert config.enable_verify is False
    rec = PocStore(config).save("FND-abc", "print('x')")
    assert "enable_verify" in run_poc(_app(config), rec.id, "http://localhost:8000")


def test_run_poc_requires_target(config):
    config.enable_verify = True
    rec = PocStore(config).save("FND-abc", "print('x')")
    assert "no target" in run_poc(_app(config), rec.id, "")


def test_run_poc_unknown_id(config):
    config.enable_verify = True
    assert "no PoC matching" in run_poc(_app(config), "POC-zzz", "http://localhost:8000")
