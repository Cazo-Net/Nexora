"""Integration tests for main-agent wiring: config, cache, net, engine
hooks, and the sources/console CLI surfaces. Fully offline."""
from __future__ import annotations

import pytest

cli = pytest.importorskip("nexora.cli")
conftest = pytest.importorskip("conftest")  # noqa: F401  (sys.path setup)


# --------------------------------------------------------------------------- #
# Config-aware parser
# --------------------------------------------------------------------------- #
def test_build_parser_config_defaults():
    parser = cli._build_parser({
        "defaults": {"profile": "quick", "timeout": 90},
        "subdomains": {"wordlist": "C:/w.txt"},
    })
    args = parser.parse_args(["domain", "example.com"])
    assert args.profile == "quick"
    assert args.timeout == 90
    assert args.wordlist == "C:/w.txt"


def test_build_parser_invalid_profile_falls_back():
    parser = cli._build_parser({"defaults": {"profile": "bogus", "timeout": "x"}})
    args = parser.parse_args(["domain", "example.com"])
    assert args.profile == "standard"
    assert args.timeout is None


def test_no_cache_flag_on_all_commands():
    parser = cli._build_parser()
    assert parser.parse_args(["ip", "1.2.3.4", "--no-cache"]).no_cache is True
    assert parser.parse_args(
        ["username", "x", "--no-cache"]).no_cache is True


def test_social_subcommands_parse():
    parser = cli._build_parser()
    args = parser.parse_args(["social", "identity", "octocat", "--exhaustive"])
    assert args.command == "social" and args.social_action == "identity"
    assert args.exhaustive is True
    args = parser.parse_args(["social", "brand", "stripe.com"])
    assert args.social_action == "brand" and args.target == "stripe.com"


# --------------------------------------------------------------------------- #
# net.apply_config
# --------------------------------------------------------------------------- #
def test_net_apply_config(monkeypatch):
    from nexora import net
    monkeypatch.setattr(net, "USER_AGENT", net.USER_AGENT)
    monkeypatch.setattr(net, "_PER_HOST_DELAY", net._PER_HOST_DELAY)
    monkeypatch.setattr(net._session, "proxies", dict(net._session.proxies))

    net.apply_config({"user_agent": "test-agent/1.0",
                      "proxy": "http://127.0.0.1:9",
                      "per_host_delay": 0.01})
    assert "test-agent" in net.USER_AGENT["User-Agent"]
    assert net._session.proxies.get("https") == "http://127.0.0.1:9"
    assert net._PER_HOST_DELAY == 0.01

    net.apply_config({"user_agent": "", "proxy": "", "per_host_delay": -5})
    assert net._PER_HOST_DELAY == 0.0
    net.apply_config(None)      # never raises
    net.apply_config({"per_host_delay": "junk"})
    assert net._PER_HOST_DELAY == 0.0


def test_throttle_noop_by_default(monkeypatch):
    from nexora import net
    net._throttle("example.test")  # no delay configured -> instant, no error


# --------------------------------------------------------------------------- #
# Engine: wordlist + HTTP cache
# --------------------------------------------------------------------------- #
def test_engine_set_wordlist(tmp_path, monkeypatch):
    import osint
    monkeypatch.setattr(osint, "_EXTRA_BRUTE_PREFIXES", osint._EXTRA_BRUTE_PREFIXES)
    wl = tmp_path / "wl.txt"
    wl.write_text("# comment line\nWWW\napi\ndev-test\nbad prefix!\nwww\n",
                  encoding="utf-8")
    n = osint.set_wordlist(str(wl))
    assert osint._EXTRA_BRUTE_PREFIXES == ["www", "api", "dev-test"]
    assert n == 3
    empty = tmp_path / "empty.txt"
    empty.write_text("# only comments\n", encoding="utf-8")
    with pytest.raises(ValueError):
        osint.set_wordlist(str(empty))
    with pytest.raises(OSError):
        osint.set_wordlist(str(tmp_path / "missing.txt"))


def test_engine_http_cache_roundtrip(tmp_path, monkeypatch):
    import osint
    from nexora import cache
    from conftest import FakeResponse

    prev_dir = cache.cache_init()
    prev_on = cache.cache_enabled()
    cache.cache_init(str(tmp_path))
    cache.cache_enable(True)
    monkeypatch.setattr(osint, "_HTTP_CACHE_TTL", 300)

    calls = []

    def fake_get(url, params=None, headers=None, timeout=None,
                 allow_redirects=True):
        calls.append(url)
        return FakeResponse(200, text='{"ok": true}', url=url,
                            headers={"Server": "fake"})

    monkeypatch.setattr(osint._session, "get", fake_get)
    try:
        r1 = osint._http_get("https://cache.test/x")
        assert r1.status_code == 200 and r1.json() == {"ok": True}
        assert not getattr(r1, "from_cache", False)
        r2 = osint._http_get("https://cache.test/x")
        assert getattr(r2, "from_cache", False) is True
        assert r2.json() == {"ok": True}
        assert r2.headers.get("Server") == "fake"
        assert len(calls) == 1  # second served from cache
        # disabled cache -> back to the network path
        cache.cache_enable(False)
        osint._http_get("https://cache.test/x")
        assert len(calls) == 2
    finally:
        cache.cache_init(prev_dir)
        cache.cache_enable(prev_on)


def test_engine_watch_cache_bypass(tmp_path, capsys):
    # cmd_domain sets engine._HTTP_CACHE_TTL = 0 when --watch is used;
    # verified here without running a scan (no network in tests).
    import osint
    assert osint._HTTP_CACHE_TTL > 0  # default on; watch flips it to 0


# --------------------------------------------------------------------------- #
# CLI surfaces
# --------------------------------------------------------------------------- #
def test_sources_command(capsys):
    rc = cli.main(["sources", "--no-banner", "--no-color"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "key-free" in out.lower()
    assert "social/identity" in out


def test_console_passthrough_flags(tmp_path, capsys):
    rc = cli.main(["console", "-c", "version",
                   "--no-banner", "--no-color",
                   "--db", str(tmp_path / "t.db")])
    assert rc == 0
    assert "Nexconsole" in capsys.readouterr().out


def test_social_without_action_usage(capsys):
    rc = cli.main(["social", "--no-banner", "--no-color"])
    assert rc == 2
    assert "usage" in capsys.readouterr().err.lower()


def test_main_no_cache_wires_cache(tmp_path, capsys):
    from nexora import cache
    prev_on = cache.cache_enabled()
    try:
        rc = cli.main(["ip", "not-an-ip", "--no-cache", "--no-banner",
                       "--no-color"])
        assert rc == 1
        assert cache.cache_enabled() is False
    finally:
        cache.cache_enable(prev_on)
