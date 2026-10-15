"""Tests for nexora.store: SQLite workspace DB (offline, stdlib only)."""
from __future__ import annotations

import json
import os

import pytest

store_mod = pytest.importorskip("nexora.store")


@pytest.fixture
def store(tmp_path):
    st = store_mod.Store(str(tmp_path / "test.db"))
    yield st
    st.close()


# --------------------------------------------------------------------------- #
# Workspaces
# --------------------------------------------------------------------------- #
def test_default_workspace_is_default(store):
    assert store.current_workspace() == "default"
    assert "default" in store.list_workspaces()


def test_use_workspace_switch_and_list(store):
    store.use_workspace("project-alpha")
    assert store.current_workspace() == "project-alpha"
    assert "project-alpha" in store.list_workspaces()
    store.use_workspace("default")
    assert store.current_workspace() == "default"


@pytest.mark.parametrize("bad", ["bad name", "a/b", "x" * 65, "", "  "])
def test_use_workspace_invalid_name_raises(store, bad):
    with pytest.raises(ValueError):
        store.use_workspace(bad)


def test_workspace_isolation(store):
    store.use_workspace("ws1")
    store.add_note("note in ws1")
    store.use_workspace("ws2")
    assert store.notes_list() == []
    store.use_workspace("ws1")
    assert len(store.notes_list()) == 1


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
def test_finding_roundtrip_and_severity_filter(store):
    store.add_finding("recon/domain", "example.com", "high",
                      "risk score 70", detail="no DMARC",
                      data={"score": 70})
    store.add_finding("recon/url", "https://x.test", "low",
                      "weak headers")
    rows = store.findings()
    assert len(rows) == 2
    top = [r for r in rows if r["title"] == "risk score 70"][0]
    assert top["severity"] == "HIGH"          # severity normalized to upper
    assert top["module"] == "recon/domain"
    assert json.loads(top["data"]) == {"score": 70}
    highs = store.findings(severity="high")
    assert len(highs) == 1
    assert highs[0]["title"] == "risk score 70"
    assert store.findings(severity="nope") == []


# --------------------------------------------------------------------------- #
# Hosts
# --------------------------------------------------------------------------- #
def test_host_upsert_same_host_one_row(store):
    store.add_host("a.example.com", ip="1.1.1.1", module="recon/domain")
    store.add_host("a.example.com", ip="2.2.2.2", module="recon/domain")
    rows = store.hosts_list()
    assert len(rows) == 1
    assert rows[0]["host"] == "a.example.com"
    assert rows[0]["ip"] == "2.2.2.2"         # ip updated on re-add
    assert rows[0]["first_seen"]              # still populated


def test_host_keeps_old_ip_when_readded_without_ip(store):
    store.add_host("b.example.com", ip="3.3.3.3")
    store.add_host("b.example.com")
    rows = store.hosts_list()
    assert len(rows) == 1
    assert rows[0]["ip"] == "3.3.3.3"


def test_services_roundtrip(store):
    store.add_service("1.2.3.4", 443, proto="tcp", name="https",
                      info="nginx")
    rows = store.services_list()
    assert len(rows) == 1
    assert rows[0]["port"] == 443
    assert rows[0]["name"] == "https"


# --------------------------------------------------------------------------- #
# Search / summary / notes
# --------------------------------------------------------------------------- #
def test_search_matches_findings_notes_hosts(store):
    store.add_finding("recon/domain", "example.com", "HIGH",
                      "foobar exposure", detail="detail text")
    store.add_note("my foobar note")
    store.add_host("foobar.host.internal", ip="9.9.9.9")
    rows = store.search("foobar")
    sources = {r["source"] for r in rows}
    assert sources == {"findings", "notes", "hosts"}
    assert store.search("nothing-here-ever") == []


def test_summary_counts(store):
    store.add_host("h1", ip="1.1.1.1")
    store.add_service("h1", 80)
    store.add_finding("m", "t", "LOW", "title")
    store.add_evidence("m", "run", "t", {"k": 1})
    store.add_note("hello")
    summary = store.summary()
    assert summary["workspace"] == "default"
    assert summary["hosts"] == 1
    assert summary["services"] == 1
    assert summary["findings"] == 1
    assert summary["evidence"] == 1
    assert summary["notes"] == 1


def test_notes_roundtrip(store):
    store.add_note("first note")
    store.add_note("second note")
    rows = store.notes_list()
    bodies = {r["body"] for r in rows}
    assert bodies == {"first note", "second note"}


def test_evidence_roundtrip(store):
    store.add_evidence("recon/ip", "run", "1.2.3.4", {"ports": [1, 2]})
    rows = store.evidence_list()
    assert len(rows) == 1
    assert json.loads(rows[0]["data"]) == {"ports": [1, 2]}


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #
def test_export_json_parseable_with_workspace_data(store, tmp_path):
    store.use_workspace("expws")
    store.add_host("e1.example.com", ip="5.5.5.5")
    store.add_finding("recon/domain", "e1.example.com", "MEDIUM", "a title")
    store.add_note("export me")
    out = tmp_path / "export" / "dump.json"
    path = store.export_json(str(out))
    assert os.path.isfile(path)
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["workspace"] == "expws"
    assert len(data["hosts"]) == 1
    assert data["hosts"][0]["host"] == "e1.example.com"
    assert data["findings"][0]["title"] == "a title"
    assert data["notes"][0]["body"] == "export me"
    assert data["summary"]["findings"] == 1


def test_context_manager(tmp_path):
    path = str(tmp_path / "ctx.db")
    with store_mod.Store(path) as st:
        st.add_note("inside")
    # reopening works and data persisted
    with store_mod.Store(path) as st2:
        assert len(st2.notes_list()) == 1
