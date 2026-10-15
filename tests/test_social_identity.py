"""Offline tests for nexora.social.identity: pure correlation scoring,
handle validation and hermetic presence checks."""
from __future__ import annotations

import pytest

import nexora.social.identity as identity_mod
from conftest import FakeResponse


# --------------------------------------------------------------------------- #
# Pure correlation scoring
# --------------------------------------------------------------------------- #
def test_correlation_shared_avatar_and_handle_is_strong():
    """Same avatar on 2 platforms + identical handle -> strongly correlated."""
    profiles = {
        "GitHub": {"name": "Alice Doe", "bio": ""},
        "Reddit": {"display_name": "Alice Doe", "public_description": ""},
        "Dev.to": {"name": "Alice Doe", "summary": ""},
    }
    avatars = [
        {"site": "GitHub", "url": "https://avatars.githubusercontent.com/u/1?v=1"},
        {"site": "Reddit", "url": "https://avatars.githubusercontent.com/u/1"},
    ]
    found = [{"site": "GitHub"}, {"site": "Reddit"}, {"site": "Dev.to"}]
    aliases = [{"alias": "alice", "github_confirmed": True}]
    score = identity_mod._score_correlation(found, profiles, avatars, aliases)
    assert score["score"] >= 70
    assert score["verdict"] == "strongly correlated"
    assert any("avatar" in s for s in score["signals"])


def test_correlation_no_signals_is_insufficient():
    score = identity_mod._score_correlation([], {}, [], [])
    assert score["score"] == 0
    assert score["verdict"] == "insufficient signal"


def test_correlation_only_unreliable_matches_clamp_to_zero():
    found = [{"site": "X (Twitter)", "unreliable": True},
             {"site": "Instagram", "unreliable": True}]
    score = identity_mod._score_correlation(found, {}, [], [])
    assert score["score"] == 0  # -20 + handle(+10) clamped at 0
    assert score["verdict"] == "insufficient signal"


def test_correlation_bio_jaccard_boosts_score():
    long_bio = ("security researcher and python developer "
                "open source enthusiast")
    profiles = {
        "GitHub": {"name": "Bob", "bio": long_bio},
        "Reddit": {"display_name": "Bob",
                   "public_description": long_bio},
        "Keybase": {"linked_accounts": [{"proof_type": "github"}]},
    }
    found = [{"site": "GitHub"}, {"site": "Reddit"}, {"site": "Keybase"}]
    aliases = [{"alias": "bob"}]
    score = identity_mod._score_correlation(found, profiles, [], aliases)
    assert score["score"] >= 40
    assert any("overlap" in s for s in score["signals"])


def test_correlation_score_is_clamped():
    profiles = {
        "GitHub": {"name": "Same Name Here"},
        "Reddit": {"display_name": "Same Name Here"},
        "Dev.to": {"name": "Same Name Here"},
        "Keybase": {"linked_accounts": [{"proof_type": "twitter"}]},
    }
    avatars = [
        {"site": "GitHub", "url": "https://a/x.png"},
        {"site": "Reddit", "url": "https://a/x.png"},
        {"site": "Dev.to", "url": "https://a/x.png"},
    ]
    found = [{"site": "GitHub"}, {"site": "Reddit"}, {"site": "Dev.to"},
             {"site": "Keybase"}]
    aliases = [{"alias": "x"}]
    score = identity_mod._score_correlation(found, profiles, avatars, aliases)
    assert 0 <= score["score"] <= 100


# --------------------------------------------------------------------------- #
# Handle validation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad", ["", "a b", "x" * 50, "user/name", None])
def test_lookup_identity_rejects_invalid_handles(bad):
    with pytest.raises(ValueError):
        identity_mod.lookup_identity(bad)


# --------------------------------------------------------------------------- #
# Hermetic presence + enrichment
# --------------------------------------------------------------------------- #
def _fake_http(url, **kwargs):
    if url.startswith("https://api.github.com/users/"):
        return FakeResponse(200, json_data={
            "login": "testuser", "name": "Test User",
            "bio": "security researcher and ctf player",
            "company": None, "location": "Berlin",
            "blog": "", "twitter_username": None,
            "followers": 3, "public_repos": 7,
            "created_at": "2020-01-01T00:00:00Z",
            "avatar_url": "https://avatars.example/testuser.png",
            "html_url": "https://github.com/testuser",
        }, url=url)
    if "github.com" in url:
        return FakeResponse(200, url=url)
    if "gitlab.com" in url:
        return FakeResponse(404, url=url)
    return FakeResponse(404, url=url)


def test_presence_counts_and_enrichment(monkeypatch):
    monkeypatch.setattr(identity_mod, "http_get", _fake_http)
    monkeypatch.setattr(identity_mod, "cache_get", lambda *a, **k: None)
    monkeypatch.setattr(identity_mod, "cache_set", lambda *a, **k: None)

    result = identity_mod.lookup_identity("testuser")

    assert result["handle"] == "testuser"
    checks = result["presence"]
    assert len(checks) >= 30  # default priority subset
    found = [c for c in checks if c["result"] == "found"]
    assert result["found_count"] == len(found) == 1
    assert found[0]["site"] == "GitHub"

    gitlab = [c for c in checks if c["site"] == "GitLab"]
    assert gitlab and gitlab[0]["result"] == "not_found"
    assert gitlab[0]["status_code"] == 404

    # enrichment ran for the only found platform
    assert "GitHub" in result["profiles"]
    assert result["profiles"]["GitHub"]["name"] == "Test User"
    assert result["sources_status"]["profile:GitHub"] == "ok"
    # platforms that were not found are explicitly skipped
    assert result["sources_status"]["profile:Keybase"].startswith("skipped")

    # alias list: original handle confirmed through GitHub
    assert result["aliases"][0]["alias"] == "testuser"
    assert result["aliases"][0]["github_confirmed"] is True

    # walled gardens are never fetched — dork suggestions instead
    assert any("site:x.com" in d for d in result["dorks"])
    assert isinstance(result["correlation"], dict)
    assert "score" in result["correlation"]


def test_presence_walled_sites_not_fetched(monkeypatch):
    fetched = []

    def fake_http(url, **kwargs):
        fetched.append(url)
        return _fake_http(url, **kwargs)

    monkeypatch.setattr(identity_mod, "http_get", fake_http)
    monkeypatch.setattr(identity_mod, "cache_get", lambda *a, **k: None)
    monkeypatch.setattr(identity_mod, "cache_set", lambda *a, **k: None)

    identity_mod.lookup_identity("someone", exhaustive=True)
    joined = " ".join(fetched)
    assert "instagram.com" not in joined
    assert "tiktok.com" not in joined
    assert "facebook.com" not in joined
    # x.com presence URL must not be requested either
    assert "https://x.com/" not in joined


def test_render_text_smoke(monkeypatch, capsys):
    monkeypatch.setattr(identity_mod, "http_get", _fake_http)
    monkeypatch.setattr(identity_mod, "cache_get", lambda *a, **k: None)
    monkeypatch.setattr(identity_mod, "cache_set", lambda *a, **k: None)
    result = identity_mod.lookup_identity("testuser")
    identity_mod.render_text(result)
    out = capsys.readouterr().out
    assert "testuser" in out
    assert "SUMMARY" in out


def test_social_modules_registry():
    import nexora.social as social_pkg
    assert set(social_pkg.SOCIAL_MODULES) == {
        "identity", "graph", "posts", "media", "brand"}
    # our own entry point must always be wired up
    assert social_pkg.SOCIAL_MODULES["identity"] is identity_mod.lookup_identity
