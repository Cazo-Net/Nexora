"""Tests for nexora.platforms and the email/phone/username enhancements.

Everything is offline: HTTP is injected or patched, DNS is blocked by the
autouse fixture (resolvers degrade to empty lists).
"""
from __future__ import annotations

import pytest

import nexora.platforms as pf_mod
import nexora.email as email_mod
import nexora.phone as phone_mod
import nexora.username as username_mod
from conftest import FakeResponse
from nexora.advanced import EmailSecurity


# --------------------------------------------------------------------------- #
# platforms_for_email
# --------------------------------------------------------------------------- #
def test_platforms_for_email_rejects_invalid():
    with pytest.raises(ValueError):
        pf_mod.platforms_for_email("not-an-email")


def _full_getter(url, params=None, headers=None, **kwargs):
    if "keybase.io" in url:
        return FakeResponse(200, json_data={
            "status": {"code": 200},
            "them": [{
                "username": "kbuser",
                "proofs": [
                    {"proof_type": "twitter", "nametracker_payload": "@tbob",
                     "url": "https://twitter.com/tbob", "verified": True},
                    {"proof_type": "github", "nametracker_payload": "tbob",
                     "url": "https://github.com/tbob", "verified": True},
                    {"proof_type": "dns", "nametracker_payload": "tbob.dev"},
                ],
            }],
        }, url=url)
    if "api.github.com/search/commits" in url:
        return FakeResponse(200, json_data={
            "total_count": 3,
            "items": [
                {"author": {"login": "tbob"},
                 "html_url": "https://github.com/x/repo/commit/1",
                 "repository": {"full_name": "x/repo"}},
                {"author": {"login": "tbob"},
                 "html_url": "https://github.com/x/repo/commit/2",
                 "repository": {"full_name": "x/repo"}},
            ],
        }, url=url)
    if "gravatar.com" in url:
        return FakeResponse(200, json_data=[{
            "display_name": "T Bob",
            "accounts": [
                {"shortname": "twitter", "url": "https://twitter.com/tbob",
                 "username": "tbob", "verified": True},
            ],
        }], url=url)
    if "keys.openpgp.org" in url:
        return FakeResponse(200, json_data={
            "uid": [{"name": "T Bob", "email": "a@b.com"}],
        }, url=url)
    return FakeResponse(404, url=url)


def test_platforms_for_email_full():
    pf = pf_mod.platforms_for_email("a@b.com", getter=_full_getter)
    assert pf["platform_count"] == len(pf["platforms"])
    plats = {p["platform"] for p in pf["platforms"]}
    assert {"keybase", "twitter", "github", "openpgp"} <= plats
    kb = [p for p in pf["platforms"] if p["platform"] == "keybase"][0]
    assert kb["handle"] == "kbuser" and kb["verified"] is True
    gh_evidence = [p["evidence"] for p in pf["platforms"]
                   if p["platform"] == "github"]
    assert any("x/repo" in ev for ev in gh_evidence)
    assert all(v == "ok" for v in pf["sources_status"].values())
    assert '"a@b.com" site:github.com' in pf["dorks"]


def test_platforms_for_email_rate_limited():
    def getter(url, **kwargs):
        if "api.github.com" in url:
            return FakeResponse(403, url=url)
        return FakeResponse(404, url=url)

    pf = pf_mod.platforms_for_email("a@b.com", getter=getter)
    assert pf["sources_status"]["github-commits"] == "rate_limited"
    assert pf["platforms"] == []


def test_platforms_for_email_unreachable():
    pf = pf_mod.platforms_for_email("a@b.com", getter=lambda *a, **k: None)
    assert pf["platforms"] == []
    assert all(v.startswith("error:") for v in pf["sources_status"].values())


# --------------------------------------------------------------------------- #
# phone platform map
# --------------------------------------------------------------------------- #
def test_platforms_for_phone_formats():
    pf = pf_mod.platforms_for_phone("+1 415 555-2671")
    assert pf["e164"] == "+14155552671"
    urls = {p["platform"]: p["url"] for p in pf["platforms"]}
    assert urls["whatsapp"] == "https://wa.me/14155552671"
    assert urls["signal"] == "https://signal.me/#p/+14155552671"
    assert "telegram" in urls
    assert pf["dorks"][0] == '"+14155552671"'
    assert '"+14155552671" site:facebook.com' in pf["dorks"]
    assert "14155552671" in pf["handle_candidates"]
    assert pf["sources_status"]["platform-map"].startswith("ok")


def test_platforms_for_phone_00_prefix():
    pf = pf_mod.platforms_for_phone("00442071838750")
    assert pf["e164"] == "+442071838750"


def test_platforms_for_phone_rejects_garbage():
    with pytest.raises(ValueError):
        pf_mod.platforms_for_phone("")
    with pytest.raises(ValueError):
        pf_mod.platforms_for_phone("hello")


def test_username_dorks():
    dorks = pf_mod.username_dorks("octocat")
    assert dorks[0] == '"octocat"'
    assert '"octocat" site:x.com' in dorks


# --------------------------------------------------------------------------- #
# email integration
# --------------------------------------------------------------------------- #
def _patch_email_network(monkeypatch):
    def fake_collect(domain, status):
        status["email-security"] = "ok"
        return EmailSecurity(domain=domain, spf_record="v=spf1 -all",
                             spf_valid=True)
    monkeypatch.setattr(email_mod, "_collect_email_security", fake_collect)
    monkeypatch.setattr(email_mod, "http_get", lambda *a, **k: None)
    monkeypatch.setattr(email_mod, "resolve_txt", lambda *a, **k: [])


def test_lookup_email_includes_platforms(monkeypatch):
    _patch_email_network(monkeypatch)
    result = email_mod.lookup_email("someone@example.com")
    assert result["connected_platforms"] == []
    assert '"someone@example.com" site:github.com' in result["dorks"]
    status = result["sources_status"]
    assert status["platforms"] == "no_results"
    assert status["pf-keybase"].startswith("error:")
    assert status["rdap"].startswith("error:")
    assert status["bimi"] in ("no_results",) or status["bimi"].startswith("error:")
    assert "rdap" in result and "bimi" in result


def test_email_render_new_sections(capsys):
    payload = {
        "email": "a@b.com", "domain": "b.com", "valid": True,
        "is_disposable": False, "username_guesses": ["a"],
        "email_security": None, "gravatar": None, "breach_check": None,
        "connected_platforms": [
            {"platform": "github", "handle": "tbob",
             "url": "https://github.com/tbob",
             "evidence": "committed with this email", "verified": True},
        ],
        "dorks": ['"a@b.com" site:github.com'],
        "rdap": {"registrar": "Registrar Inc", "created": "2000-01-01",
                 "abuse_email": "abuse@reg.example", "statuses": ["client transfer"]},
        "bimi": {"record": "v=BIMI1; l=https://b.com/logo.svg; a=;"},
        "sources_status": {},
    }
    email_mod.render_text(payload)
    out = capsys.readouterr().out
    assert "CONNECTED PLATFORMS" in out
    assert "tbob" in out and "github" in out
    assert "SEARCH DORKS" in out
    assert "DOMAIN REGISTRY" in out
    assert "abuse@reg.example" in out
    assert "BIMI" in out


# --------------------------------------------------------------------------- #
# phone integration
# --------------------------------------------------------------------------- #
def test_lookup_phone_includes_platforms():
    result = phone_mod.lookup_phone("+14155552671")
    assert result["connected_platforms"], "platform map expected"
    urls = [p["url"] for p in result["connected_platforms"]]
    assert any("wa.me/14155552671" in u for u in urls)
    assert result["dorks"] and result["handle_candidates"]
    assert result["sources_status"]["platform-map"].startswith("ok")


def test_phone_render_sections(capsys):
    result = phone_mod.lookup_phone("+14155552671")
    phone_mod.render_text(result)
    out = capsys.readouterr().out
    assert "CONNECTED PLATFORMS" in out
    assert "wa.me" in out
    assert "SEARCH DORKS" in out


def test_lookup_phone_garbage_still_degrades():
    # invalid input never crashes the CLI: ValueError only via platforms
    # (with phonenumbers it raises at parse; without it degrades)
    try:
        result = phone_mod.lookup_phone("garbage-input")
    except ValueError:
        return  # phonenumbers installed: parse rejects it — acceptable
    assert result["connected_platforms"] == []


# --------------------------------------------------------------------------- #
# username integration
# --------------------------------------------------------------------------- #
def test_lookup_username_identifier_pivots(monkeypatch):
    u = "testuser"

    def fake_http(url, params=None, **kwargs):
        if "api.github.com/users/" in url:
            return FakeResponse(200, json_data={
                "email": "dev@example.com", "twitter_username": "tbob",
                "blog": "https://dev.example.com",
                "name": "T Bob", "public_repos": 5, "followers": 10,
            }, url=url)
        if "keybase.io/_/api" in url:
            return FakeResponse(200, json_data={
                "them": [{"username": u, "proofs": [
                    {"proof_type": "twitter", "nametracker_payload": "@tbob",
                     "url": "https://twitter.com/tbob", "verified": True},
                    {"proof_type": "github", "nametracker_payload": u,
                     "url": f"https://github.com/{u}", "verified": True},
                    {"proof_type": "dns", "nametracker_payload": "x.dev"},
                ]}],
            }, url=url)
        return None  # site checks + reddit/devto -> unknown

    monkeypatch.setattr(username_mod, "http_get", fake_http)
    result = username_mod.lookup_username(u, concurrency=16)

    assert result["emails_found"] == [
        {"email": "dev@example.com", "source": "github"}]
    accounts = {(a["platform"], a["handle"], a["via"])
                for a in result["linked_accounts"]}
    assert ("twitter", "tbob", "github") in accounts
    assert ("twitter", "@tbob", "keybase") in accounts
    # the searched handle itself is never reported as a pivot
    assert ("github", u, "keybase") not in accounts
    assert any(w["url"] == "https://dev.example.com"
               for w in result["websites"])
    assert '"testuser" site:x.com' in result["dorks"]
    assert "enrich-keybase" in result["sources_status"]
    assert "Keybase" in result["profiles"]


def test_username_render_identifier_pivots(capsys):
    payload = {
        "username": "testuser", "checks": [], "found": [], "maybe": [],
        "not_found_count": 0, "unknown_count": 0, "profiles": {},
        "avatars": [],
        "emails_found": [{"email": "dev@example.com", "source": "github"}],
        "linked_accounts": [{"platform": "twitter", "handle": "tbob",
                             "via": "github", "url": "https://twitter.com/tbob"}],
        "websites": [{"url": "https://dev.example.com", "source": "github"}],
        "dorks": ['"testuser" site:x.com'],
        "sources_status": {},
    }
    username_mod.render_text(payload)
    out = capsys.readouterr().out
    assert "IDENTIFIER PIVOTS" in out
    assert "dev@example.com" in out
    assert "nexora email dev@example.com" in out
    assert "SEARCH DORKS" in out
