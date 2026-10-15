"""Tests for nexora.modules: registry, lazy runners, fake osint (offline)."""
from __future__ import annotations

import sys
import types

import pytest

modules = pytest.importorskip("nexora.modules")

BUILTIN_PATHS = (
    "recon/domain", "recon/ip", "recon/email", "recon/username",
    "recon/asn", "recon/url", "recon/phone",
    "util/deep", "util/cache",
    "social/identity", "social/graph", "social/posts", "social/media",
    "social/brand",
)


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
def test_registry_has_14_builtins():
    assert len(modules.REGISTRY) >= 13
    for path in BUILTIN_PATHS:
        assert path in modules.REGISTRY, "missing built-in %s" % path


def test_get_unknown_raises_keyerror_with_hint():
    with pytest.raises(KeyError) as exc:
        modules.get("recon/nope")
    assert "show modules" in str(exc.value)


def test_get_known_returns_module():
    mod = modules.get("recon/domain")
    assert mod.path == "recon/domain"
    assert mod.kind == "recon"


def test_search_domain_finds_recon_domain():
    hits = modules.search("domain")
    assert "recon/domain" in [m.path for m in hits]


def test_list_modules_kind_filter():
    socials = modules.list_modules(kind="social")
    assert socials and all(m.kind == "social" for m in socials)
    assert len(socials) == 5


def test_option_kinds_on_recon_domain():
    mod = modules.get("recon/domain")
    by_name = {o.name: o for o in mod.options}
    assert by_name["profile"].kind == "str"
    assert by_name["timeout"].kind == "int"
    assert by_name["deep"].kind == "bool"
    assert by_name["target"].required is True


def test_runner_refs_point_at_importable_strings():
    """Runners stay lazy: refs are (dotted.path, attr) string pairs."""
    for mod in modules.list_modules():
        ref = mod.runner_ref
        assert isinstance(ref, tuple) and len(ref) == 2
        assert all(isinstance(s, str) and s for s in ref)


def test_import_is_lazy_no_osint(monkeypatch):
    """register()/importing nexora.modules must not pull in osint or
    network modules."""
    import importlib

    # Remove osint + heavy nexora modules so we can detect (re)import.
    saved = {}
    for name in ("osint", "nexora.ip", "nexora.email", "nexora.username",
                 "nexora.url", "nexora.asn", "nexora.phone", "nexora.deep"):
        saved[name] = sys.modules.pop(name, None)
    try:
        importlib.reload(modules)
        assert "osint" not in sys.modules
        assert "nexora.ip" not in sys.modules
    finally:
        for name, mod in saved.items():
            if mod is not None:
                sys.modules[name] = mod


# --------------------------------------------------------------------------- #
# _run_recon_domain with a fake osint engine
# --------------------------------------------------------------------------- #
@pytest.fixture
def fake_osint(monkeypatch):
    calls = {}

    def fake_lookup(raw_query, timeout=None, skip_categories=None,
                    on_source_complete=None):
        calls["raw_query"] = raw_query
        calls["timeout"] = timeout
        calls["skip_categories"] = skip_categories
        if on_source_complete:
            on_source_complete("fake-source", {"ok": True})
        return {"queried": raw_query}

    fake = types.SimpleNamespace(
        lookup_domain=fake_lookup,
        intel_to_dict=lambda result: {"serialized": result},
    )
    monkeypatch.setitem(sys.modules, "osint", fake)
    return calls


def test_run_recon_domain_serializes(fake_osint):
    events = []
    payload = modules._run_recon_domain(
        {"target": "example.com", "profile": "", "timeout": 0,
         "skip": "", "deep": False},
        lambda ev, data: events.append((ev, data)))
    assert payload == {"serialized": {"queried": "example.com"}}
    assert fake_osint["raw_query"] == "example.com"
    assert fake_osint["timeout"] is None          # 0 -> auto
    assert fake_osint["skip_categories"] is None  # empty -> None
    assert events == [("source", "fake-source")]


def test_run_recon_domain_skip_categories_parsed(fake_osint):
    modules._run_recon_domain(
        {"target": "example.com", "profile": "", "timeout": 30,
         "skip": "ports, threat_intel ,", "deep": False},
        lambda ev, data: None)
    assert fake_osint["timeout"] == 30
    assert fake_osint["skip_categories"] == {"ports", "threat_intel"}


def test_run_recon_domain_missing_target_errors():
    payload = modules._run_recon_domain({}, lambda ev, data: None)
    assert "error" in payload


def test_run_recon_domain_engine_failure_is_error(monkeypatch):
    fake = types.SimpleNamespace(
        lookup_domain=lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("boom")),
        intel_to_dict=lambda r: r,
    )
    monkeypatch.setitem(sys.modules, "osint", fake)
    payload = modules._run_recon_domain(
        {"target": "example.com", "profile": "", "timeout": 0,
         "skip": "", "deep": False},
        lambda ev, data: None)
    assert "error" in payload and "boom" in payload["error"]


# --------------------------------------------------------------------------- #
# util/cache runner
# --------------------------------------------------------------------------- #
@pytest.fixture
def tmp_cache(tmp_path):
    from nexora import cache as cache_mod

    prev_dir = cache_mod._dir
    prev_enabled = cache_mod.cache_enabled()
    prev_mem = dict(cache_mod._mem)
    cache_mod.cache_init(str(tmp_path))
    cache_mod.cache_enable(True)
    cache_mod._mem.clear()
    yield cache_mod
    cache_mod._mem.clear()
    cache_mod._mem.update(prev_mem)
    cache_mod.cache_init(prev_dir)
    cache_mod.cache_enable(prev_enabled)


def test_util_cache_stats_path(tmp_cache):
    payload = modules._run_util_cache({"action": "stats"},
                                      lambda ev, data: None)
    assert payload["dir"] == str_cache_dir(tmp_cache)
    assert payload["enabled"] is True


def str_cache_dir(cache_mod):
    return cache_mod.cache_init()


def test_util_cache_clear_path(tmp_cache):
    tmp_cache.cache_set("some-key", 123)
    payload = modules._run_util_cache({"action": "clear"},
                                      lambda ev, data: None)
    assert payload.get("cleared") is True
    assert tmp_cache.cache_stats()["file_entries"] == 0


def test_util_cache_unknown_action_errors():
    payload = modules._run_util_cache({"action": "bogus"},
                                      lambda ev, data: None)
    assert "error" in payload


# --------------------------------------------------------------------------- #
# social runner (package may not exist yet — must degrade, not crash)
# --------------------------------------------------------------------------- #
def test_run_social_without_package_errors_gracefully(monkeypatch):
    """Force the social import to fail — runner must return an error dict."""
    real_import = modules.importlib.import_module

    def failing_import(name, *args, **kwargs):
        if name.startswith("nexora.social"):
            raise ImportError("social package not available")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(modules.importlib, "import_module", failing_import)
    payload = modules._run_social(
        {"_module_path": "social/identity", "handle": "jdoe", "limit": 5},
        lambda ev, data: None)
    assert "error" in payload
    assert "social modules unavailable" in payload["error"]


def test_run_social_unknown_kind_errors():
    payload = modules._run_social({"_module_path": "social/bogus"},
                                  lambda ev, data: None)
    assert "error" in payload


def test_run_social_dispatches_to_injected_package(monkeypatch):
    """Inject a fake nexora.social.brand to prove dispatch works."""
    fake_brand = types.ModuleType("nexora.social.brand")

    def lookup_brand(domain, status_cb=None):
        return {"domain": domain}

    fake_brand.lookup_brand = lookup_brand
    pkg = types.ModuleType("nexora.social")
    monkeypatch.setitem(sys.modules, "nexora.social", pkg)
    monkeypatch.setitem(sys.modules, "nexora.social.brand", fake_brand)
    payload = modules._run_social(
        {"_module_path": "social/brand", "domain": "acme.example",
         "limit": 7},
        lambda ev, data: None)
    # brand's real signature has no `limit` — the option is dropped, not fatal
    assert payload == {"domain": "acme.example"}


def test_run_social_graph_maps_limit_to_max_items(monkeypatch):
    """social/graph's `limit` option must reach lookup_graph as max_items."""
    fake_graph = types.ModuleType("nexora.social.graph")

    def lookup_graph(handle, max_items=100, status_cb=None):
        return {"handle": handle, "max_items": max_items}

    fake_graph.lookup_graph = lookup_graph
    pkg = types.ModuleType("nexora.social")
    monkeypatch.setitem(sys.modules, "nexora.social", pkg)
    monkeypatch.setitem(sys.modules, "nexora.social.graph", fake_graph)
    payload = modules._run_social(
        {"_module_path": "social/graph", "handle": "octocat", "limit": 7},
        lambda ev, data: None)
    assert payload == {"handle": "octocat", "max_items": 7}


def test_media_runner_tries_candidates_in_order(monkeypatch):
    """media may expose lookup_media / inspect_url / inspect_media."""
    fake_media = types.ModuleType("nexora.social.media")

    def inspect_media(target, limit=10, status_cb=None):
        return {"via": "inspect_media", "target": target}

    fake_media.inspect_media = inspect_media
    pkg = types.ModuleType("nexora.social")
    monkeypatch.setitem(sys.modules, "nexora.social", pkg)
    monkeypatch.setitem(sys.modules, "nexora.social.media", fake_media)
    payload = modules._run_social(
        {"_module_path": "social/media", "target": "https://x.test/p",
         "limit": 3},
        lambda ev, data: None)
    assert payload["via"] == "inspect_media"
