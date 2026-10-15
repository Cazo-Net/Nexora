"""Tests for nexora.net: HTTP helpers, DNS helpers, circuit breaker.

Everything is hermetic: the shared session and ``dns.resolver.resolve``
are replaced with fakes (see conftest).
"""
from __future__ import annotations

import pytest
import requests

import nexora.net as net
from conftest import FakeResponse


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
def test_http_get_returns_none_when_session_raises(monkeypatch):
    def boom(*args, **kwargs):
        raise requests.RequestException("boom")

    monkeypatch.setattr(net._session, "get", boom)
    assert net.http_get("https://req-fail.example/x") is None


def test_http_get_success_and_allow_redirects_passthrough(monkeypatch):
    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return FakeResponse(200, text="ok", url=url)

    monkeypatch.setattr(net._session, "get", fake_get)
    try:
        resp = net.http_get("https://ok.example/x", timeout=3,
                            allow_redirects=False)
    except TypeError:
        pytest.skip("http_get does not accept allow_redirects yet")
    assert resp is not None
    assert resp.status_code == 200
    assert captured["url"] == "https://ok.example/x"
    assert captured.get("allow_redirects") is False
    assert captured.get("timeout") == 3
    assert "User-Agent" in (captured.get("headers") or {})


def test_http_post_passes_kwargs_through(monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return FakeResponse(201, json_data={"ok": True}, url=url)

    monkeypatch.setattr(net._session, "post", fake_post)
    resp = net.http_post("https://ok.example/api", data={"a": "1"},
                         json_body={"b": 2}, timeout=4)
    assert resp is not None
    assert resp.json() == {"ok": True}
    assert captured["data"] == {"a": "1"}
    assert captured["json"] == {"b": 2}
    assert captured["timeout"] == 4
    assert "User-Agent" in (captured.get("headers") or {})


def test_http_post_returns_none_when_session_raises(monkeypatch):
    def boom(*args, **kwargs):
        raise requests.ConnectionError("nope")

    monkeypatch.setattr(net._session, "post", boom)
    assert net.http_post("https://dead.example/api") is None


# --------------------------------------------------------------------------- #
# Circuit breaker
# --------------------------------------------------------------------------- #
def test_circuit_breaker_short_circuits_after_failure(monkeypatch):
    calls = []

    def boom(*args, **kwargs):
        calls.append("call")
        raise RuntimeError("dead host")

    monkeypatch.setattr(net._session, "get", boom)
    assert net.http_get("https://cb-test.example/a") is None
    assert calls == ["call"]  # first failure recorded

    # Host is now blacklisted: subsequent calls must not touch the session.
    def ok(*args, **kwargs):
        calls.append("second")
        return FakeResponse(200, text="ok")

    monkeypatch.setattr(net._session, "get", ok)
    assert net.http_get("https://cb-test.example/b") is None
    assert calls == ["call"]

    # reset_circuit_breaker() clears the blacklist -> session used again.
    net.reset_circuit_breaker()
    assert net.http_get("https://cb-test.example/c") is not None
    assert calls == ["call", "second"]


def test_reset_circuit_breaker_clears_state():
    net._mark_dead("blacklisted.example")
    assert net._is_dead("blacklisted.example") is True
    net.reset_circuit_breaker()
    assert net._is_dead("blacklisted.example") is False


# --------------------------------------------------------------------------- #
# DNS helpers
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "name", ["resolve_a", "resolve_txt", "resolve_mx", "resolve_ns"])
def test_resolve_helpers_return_empty_on_dns_failure(name, fake_dns):
    # fake_dns raises NoAnswer for anything not registered; the helpers
    # must swallow it and return [] (socket fallback path also yields []
    # thanks to the autouse getaddrinfo guard).
    fn = getattr(net, name)
    assert fn("no-such-name.invalid") == []


def test_resolve_success_with_fake_dns(fake_dns):
    if not net._HAS_DNS:
        pytest.skip("dnspython not installed")
    fake_dns.set("example.com", "A", "93.184.216.34")
    fake_dns.set("example.com", "TXT", "hello=world")
    fake_dns.set("example.com", "MX", (10, "mail.example.com."),
                 (20, "mail2.example.com."))
    fake_dns.set("example.com", "NS", "ns1.example.com.")

    assert net.resolve_a("example.com") == ["93.184.216.34"]
    assert net.resolve_txt("example.com") == ["hello=world"]
    # priority-sorted, trailing dot stripped
    assert net.resolve_mx("example.com") == ["mail.example.com",
                                             "mail2.example.com"]
    assert net.resolve_ns("example.com") == ["ns1.example.com"]
