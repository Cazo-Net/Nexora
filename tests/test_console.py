"""Tests for nexora.console: the Nexconsole REPL (fully offline)."""
from __future__ import annotations

import io
import json
import sys
import types

import pytest

console_mod = pytest.importorskip("nexora.console")
modules_mod = pytest.importorskip("nexora.modules")
store_mod = pytest.importorskip("nexora.store")


@pytest.fixture
def store(tmp_path):
    st = store_mod.Store(str(tmp_path / "console.db"))
    yield st
    st.close()


@pytest.fixture
def con(store, capsys):
    """A non-interactive console writing to a StringIO."""
    out = io.StringIO()
    c = console_mod.Nexconsole(store=store, interactive=False, out=out)
    yield c
    c.out = out  # keep for assertions after run_lines


@pytest.fixture
def out_of(con):
    return con.out


# --------------------------------------------------------------------------- #
# show modules / use / options
# --------------------------------------------------------------------------- #
def test_show_modules_lists_registry(con, out_of):
    con.run_lines(["show modules"])
    text = out_of.getvalue()
    assert "recon/domain" in text
    assert "recon/ip" in text
    assert "util/cache" in text


def test_use_and_show_options(con, out_of):
    con.run_lines(["use recon/ip", "show options"])
    text = out_of.getvalue()
    assert "target" in text
    assert "yes" in text          # target is required
    assert con.current_module is not None
    assert con.current_module.path == "recon/ip"


def test_set_reflected_in_show_options(con, out_of):
    con.run_lines(["use recon/ip", "set target 1.2.3.4", "show options"])
    assert "1.2.3.4" in out_of.getvalue()
    assert con.options["target"] == "1.2.3.4"


def test_bad_int_option_warns_not_crash(con, out_of):
    rc = con.run_lines(["use recon/domain", "set timeout abc"])
    assert rc == 0
    text = out_of.getvalue()
    assert "timeout" in text              # warning names the option
    assert "timeout" not in con.options   # value NOT stored


def test_unknown_option_warns_but_stores(con, out_of):
    con.run_lines(["use recon/ip", "set weird 42"])
    assert "weird" in out_of.getvalue()
    assert con.options["weird"] == "42"


def test_unset_removes_option(con, out_of):
    con.run_lines(["use recon/ip", "set target 1.2.3.4", "unset target"])
    assert "target" not in con.options


def test_use_unknown_module_message(con, out_of):
    con.run_lines(["use recon/nope"])
    text = out_of.getvalue()
    assert "module not found" in text
    assert "show modules" in text
    assert con.current_module is None


def test_back_deselects_module(con, out_of):
    con.run_lines(["use recon/ip", "back"])
    assert con.current_module is None
    assert con.options == {}


# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #
def test_run_requires_module(con, out_of):
    con.run_lines(["run"])
    assert "No module selected" in out_of.getvalue()


def test_run_missing_required_lists_target_no_network(con, out_of):
    con.run_lines(["use recon/ip", "run"])
    text = out_of.getvalue()
    assert "missing required option(s)" in text
    assert "target" in text
    # no_network fixture guarantees no HTTP happened; also nothing ingested
    assert con.store.summary()["evidence"] == 0


def test_setg_overlays_defaults(con, out_of):
    con.run_lines(["setg target 9.9.9.9", "use recon/ip", "show options"])
    assert "9.9.9.9" in out_of.getvalue()


# --------------------------------------------------------------------------- #
# run with a fake registered module (no network)
# --------------------------------------------------------------------------- #
@pytest.fixture
def echo_module():
    """Register util/echo backed by a fake 'tests.fake' runner module."""
    fake = types.ModuleType("tests.fake")

    def run(options, emit):
        emit("echo", options.get("msg", ""))
        return {"score": 50, "sources_status": {"x": "ok"}}

    fake.run = run
    mod = modules_mod.Module(
        path="util/echo", kind="util", title="echo test module",
        description="returns a canned payload",
        options=[modules_mod.Option("msg", "hi")],
        runner_ref=("tests.fake", "run"),
    )
    modules_mod.register(mod)
    sys.modules["tests.fake"] = fake
    yield mod
    sys.modules.pop("tests.fake", None)
    modules_mod.REGISTRY.pop("util/echo", None)


def test_run_fake_module_prints_and_ingests(con, out_of, echo_module):
    con.run_lines(["use util/echo", "run"])
    text = out_of.getvalue()
    assert "completed in" in text
    assert "score=50" in text
    # auto-ingest stored an evidence row for the payload
    assert con.store.summary()["evidence"] == 1
    ev = con.store.evidence_list()[0]
    assert ev["kind"] == "util/echo"
    assert json.loads(ev["data"])["score"] == 50


def test_emit_events_printed(con, out_of, echo_module):
    con.run_lines(["use util/echo", "run"])
    assert "[+] echo: hi" in out_of.getvalue()


# --------------------------------------------------------------------------- #
# unknown command + suggestion
# --------------------------------------------------------------------------- #
def test_unknown_command_suggests(con, out_of):
    con.run_lines(["sow modules"])     # typo of 'show'
    text = out_of.getvalue()
    assert "Unknown command 'sow'" in text
    assert "Did you mean 'show'?" in text
    assert "use" in console_mod.COMMANDS


def test_command_list_contains_use():
    assert "use" in console_mod.COMMANDS


# --------------------------------------------------------------------------- #
# workspace / search / notes / export
# --------------------------------------------------------------------------- #
def test_workspace_switch(con, store):
    con.run_lines(["workspace newname"])
    assert store.current_workspace() == "newname"


def test_workspace_list_marks_current(con, out_of, store):
    con.run_lines(["workspace alpha", "workspace"])
    text = out_of.getvalue()
    assert "* alpha" in text


def test_workspace_invalid_name_message(con, out_of, store):
    con.run_lines(["workspace " + "x" * 100])
    assert "error" in out_of.getvalue().lower()
    assert store.current_workspace() == "default"


def test_search_seeded_store(con, out_of, store):
    store.add_note("foo bar baz")
    con.run_lines(["search foo"])
    assert "foo bar baz" in out_of.getvalue()


def test_notes_add_and_list(con, out_of):
    con.run_lines(["notes add hello nurse", "notes"])
    text = out_of.getvalue()
    assert "note added" in text
    assert "hello nurse" in text


def test_export_writes_file(con, out_of, tmp_path):
    store = con.store
    store.add_note("exported note")
    target = str(tmp_path / "ws.json")
    con.run_lines(["export " + target])
    assert "exported" in out_of.getvalue()
    with open(target, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["notes"][0]["body"] == "exported note"


# --------------------------------------------------------------------------- #
# misc commands
# --------------------------------------------------------------------------- #
def test_help_lists_use(con, out_of):
    con.run_lines(["help"])
    text = out_of.getvalue()
    assert "use" in text
    assert "show modules" in text


def test_help_alias_question_mark(con, out_of):
    con.run_lines(["?"])
    assert "Commands:" in out_of.getvalue()


def test_version_command(con, out_of):
    con.run_lines(["version"])
    assert "Nexora Nexconsole" in out_of.getvalue()


def test_quit_returns_zero(con):
    assert con.run_lines(["quit"]) == 0
    assert con.run_lines(["exit"]) == 0
    assert con.run_lines(["q"]) == 0


def test_empty_and_comment_lines_ignored(con, out_of):
    assert con.run_lines(["", "   ", "# just a comment"]) == 0
    assert out_of.getvalue() == ""


def test_history_records_commands(con, out_of):
    con.run_lines(["help", "version"])
    con.run_lines(["history"])
    text = out_of.getvalue()
    assert "help" in text and "version" in text


def test_show_options_without_module(con, out_of):
    con.run_lines(["show options"])
    assert "No module selected" in out_of.getvalue()


# --------------------------------------------------------------------------- #
# batch splitting
# --------------------------------------------------------------------------- #
def test_split_commands_semicolon_and_quotes():
    assert console_mod.split_commands("a; b") == ["a", "b"]
    assert console_mod.split_commands("set skip 'x;y'; run") == \
        ["set skip 'x;y'", "run"]
    assert console_mod.split_commands("# comment\nuse recon/ip") == \
        ["use recon/ip"]


# --------------------------------------------------------------------------- #
# interactive loop: EOF + Ctrl-C
# --------------------------------------------------------------------------- #
def test_loop_eof_returns_zero(store, monkeypatch, capsys):
    def fake_input(_prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", fake_input)
    c = console_mod.Nexconsole(store=store, interactive=True)
    assert c.loop() == 0


def test_loop_ctrlc_continues_then_quit(store, monkeypatch, capsys):
    calls = {"n": 0}

    def fake_input(_prompt):
        calls["n"] += 1
        if calls["n"] == 1:
            raise KeyboardInterrupt
        return "quit"

    monkeypatch.setattr("builtins.input", fake_input)
    c = console_mod.Nexconsole(store=store, interactive=True)
    assert c.loop() == 0
    captured = capsys.readouterr().out
    assert "^C (use 'quit' to exit)" in captured


# --------------------------------------------------------------------------- #
# main() batch entry points
# --------------------------------------------------------------------------- #
def test_main_c_shows_modules(tmp_path, capsys):
    db = str(tmp_path / "main.db")
    rc = console_mod.main(["-c", "show modules", "--no-banner", "--db", db])
    assert rc == 0
    out = capsys.readouterr().out
    assert "recon/domain" in out


def test_main_c_multiple_commands(tmp_path, capsys):
    db = str(tmp_path / "main2.db")
    rc = console_mod.main(["-c", "use recon/ip; show options",
                           "--no-banner", "--quiet", "--db", db])
    assert rc == 0
    out = capsys.readouterr().out
    assert "target" in out


def test_main_x_command_file(tmp_path, capsys):
    script = tmp_path / "cmds.txt"
    script.write_text("# batch file\nshow modules\nversion\n",
                      encoding="utf-8")
    db = str(tmp_path / "main3.db")
    rc = console_mod.main(["-x", str(script), "--no-banner", "--db", db])
    assert rc == 0
    out = capsys.readouterr().out
    assert "recon/domain" in out
    assert "Nexora Nexconsole" in out


def test_main_x_missing_file_returns_1(tmp_path, capsys):
    db = str(tmp_path / "main4.db")
    rc = console_mod.main(["-x", str(tmp_path / "nope.txt"),
                           "--no-banner", "--db", db])
    assert rc == 1


def test_main_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        console_mod.main(["--version"])
    assert exc.value.code == 0
    assert "Nexora Nexconsole" in capsys.readouterr().out


def test_ingest_domain_payload(store):
    payload = {
        "query": "example.com",
        "subdomains": [
            {"hostname": "www.example.com", "ips": ["1.2.3.4"]},
            {"hostname": "mail.example.com", "ips": []},
        ],
        "risk_score": {"score": 55, "grade": "D", "findings": ["no DMARC"]},
        "subdomain_takeover": [{"subdomain": "blog.example.com",
                                "vulnerable": True}],
        "sensitive_paths": [{"path": "/.git/config"}],
        "ports": [{"port": 443, "state": "open", "service": "https"}],
    }
    console_mod._ingest("recon/domain", "example.com", payload, store)
    summary = store.summary()
    assert summary["hosts"] == 2
    assert summary["findings"] == 3     # risk + takeover + sensitive paths
    assert summary["services"] == 1
    assert summary["evidence"] == 1
    highs = store.findings(severity="HIGH")
    titles = " ".join(r["title"] for r in highs)
    assert "takeover" in titles
    assert "risk score" in titles


def test_ingest_email_breaches(store):
    payload = {"email": "a@b.com",
               "breach_check": {"breach_count": 2,
                                "breaches": ["Adobe", "LinkedIn"]}}
    console_mod._ingest("recon/email", "a@b.com", payload, store)
    rows = store.findings(severity="HIGH")
    assert any("breach" in r["title"] for r in rows)


def test_ingest_ip_payload(store):
    payload = {"ip": "9.9.9.9", "reverse_dns": "dns9.quad9.net",
               "ports": [{"port": 53, "state": "open", "service": "domain"}]}
    console_mod._ingest("recon/ip", "9.9.9.9", payload, store)
    hosts = {h["host"] for h in store.hosts_list()}
    assert "9.9.9.9" in hosts
    assert "dns9.quad9.net" in hosts
    assert store.services_list()[0]["port"] == 53


def test_ingest_url_score_and_bad_payloads(store):
    console_mod._ingest("recon/url", "http://x.test",
                        {"security_score": 20}, store)
    assert store.findings(severity="MEDIUM")
    # non-dict payloads must not crash
    console_mod._ingest("recon/url", "x", None, store)
    console_mod._ingest("recon/url", "x", ["list"], store)
    assert store.summary()["evidence"] == 1   # only the dict payload stored
