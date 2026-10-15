"""Tests for nexora.username: site catalogue, validation, classification."""
from __future__ import annotations

import pytest

import nexora.username as username_mod
from conftest import FakeResponse

KNOWN_CATEGORIES = {
    "code", "social", "gaming", "creative", "music", "video", "commerce",
    "professional", "writing", "forum", "other",
}


# --------------------------------------------------------------------------- #
# Catalogue
# --------------------------------------------------------------------------- #
def test_sites_catalogue_size():
    assert len(username_mod.SITES) >= 70


def test_sites_urls_have_placeholder():
    for site in username_mod.SITES:
        assert "{u}" in site["url"], "site %r lacks {u}" % site["name"]


def test_sites_names_unique():
    names = [s["name"] for s in username_mod.SITES]
    assert len(names) == len(set(names))


def test_sites_categories_known():
    for site in username_mod.SITES:
        assert site.get("category") in KNOWN_CATEGORIES, \
            "site %r has unknown category %r" % (site["name"],
                                                 site.get("category"))


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad", ["a b", "", "x" * 50, "user name", "a/b"])
def test_lookup_username_rejects_invalid(bad):
    with pytest.raises(ValueError):
        username_mod.lookup_username(bad)


# --------------------------------------------------------------------------- #
# Classification rules
# --------------------------------------------------------------------------- #
def test_classify_rules():
    classify = username_mod._classify
    assert classify({"name": "X"}, 200) == "found"
    # unreliable sites always return 200 -> never proof of existence
    assert classify({"name": "X", "unreliable": True}, 200) == "unknown"
    assert classify({"name": "X"}, 404) == "not_found"
    assert classify({"name": "X"}, 410) == "not_found"
    assert classify({"name": "X"}, 403) == "maybe"
    assert classify({"name": "X", "unreliable": True}, 403) == "unknown"
    assert classify({"name": "X"}, 500) == "unknown"


# --------------------------------------------------------------------------- #
# Hermetic lookup
# --------------------------------------------------------------------------- #
def test_lookup_username_hermetic(monkeypatch):
    u = "testuser"
    url_map = {s["url"].format(u=u): s for s in username_mod.SITES}
    reliable = [s for s in username_mod.SITES if not s.get("unreliable")]
    assert reliable, "catalogue must contain reliable sites"
    fallback_name = reliable[0]["name"]  # this one gets the None response

    def fake_http(url, **kwargs):
        site = url_map.get(url)
        if site is None:
            # enrichment endpoints (GitHub/Reddit/Dev.to APIs)
            return FakeResponse(200, text="{}", url=url)
        if site["name"] == fallback_name:
            return None  # dead host -> graceful fallback
        if site.get("unreliable"):
            return FakeResponse(403, url=url)  # bot-walled
        return FakeResponse(200, text="{}", url=url)

    monkeypatch.setattr(username_mod, "http_get", fake_http)
    result = username_mod.lookup_username(u, concurrency=16)

    assert result["username"] == u
    checks = result["checks"]
    assert len(checks) == len(username_mod.SITES)

    unreliable_names = {s["name"] for s in username_mod.SITES
                        if s.get("unreliable")}

    # reliable 200s count as found; unreliable ones never do
    assert len(result["found"]) > 0
    for ch in result["found"]:
        assert ch["result"] == "found"
        assert ch["status_code"] == 200
        assert ch["site"] not in unreliable_names

    # the None-fallback site degrades to "unknown"
    fallback_checks = [c for c in checks if c["site"] == fallback_name]
    assert fallback_checks
    assert fallback_checks[0]["result"] == "unknown"
    assert fallback_checks[0]["status_code"] is None

    # aggregate counts stay consistent with per-site results
    assert result["not_found_count"] == sum(
        1 for c in checks if c["result"] == "not_found")
    assert result["unknown_count"] == sum(
        1 for c in checks if c["result"] == "unknown")
    assert len(result["found"]) + len(result["maybe"]) + \
        result["not_found_count"] + result["unknown_count"] == len(checks)

    assert "profile-checks" in result["sources_status"]
