"""Offline tests for nexora.social.brand: pure HTML parsing, variant
generation, severity mapping, domain validation and hermetic lookup."""
from __future__ import annotations

import pytest

import nexora.social.brand as brand_mod
from conftest import FakeResponse


SAMPLE_HTML = """
<html><head>
  <meta property="og:site_name" content="Acme"/>
  <link rel="me" href="https://github.com/acme">
</head><body>
  <a href="https://twitter.com/acme">Twitter</a>
  <a href="https://x.com/acme-handle">X</a>
  <a href="https://github.com/acme-labs">GitHub</a>
  <a href="https://t.me/acme">Telegram</a>
  <a href="https://www.instagram.com/acme/">Instagram</a>
  <a href="/about">Relative page</a>
  <a href="mailto:hi@acme.com">Mail</a>
  <a href="javascript:void(0)">JS</a>
  <a href="https://discord.gg/acme">Discord invite</a>
  <a href="https://www.linkedin.com/in/acme-founder">LinkedIn</a>
</body></html>
"""


# --------------------------------------------------------------------------- #
# Pure HTML parsing
# --------------------------------------------------------------------------- #
def test_extract_official_parses_platform_links():
    official = brand_mod._extract_official(SAMPLE_HTML, "acme.com")
    by_key = {(a["platform"], a["handle"]): a for a in official}

    assert ("twitter", "acme") in by_key
    assert ("twitter", "acme-handle") in by_key  # x.com counts as twitter
    assert ("github", "acme-labs") in by_key
    assert ("telegram", "acme") in by_key
    assert ("instagram", "acme") in by_key
    assert ("discord", "acme") in by_key
    assert ("linkedin", "acme-founder") in by_key

    # rel=me link recorded with the preferred source
    rel_me = [a for a in official if a["source"] == "rel=me"]
    assert rel_me and rel_me[0]["handle"] == "acme"

    # relative / mailto / javascript links are ignored
    urls = " ".join(a["url"] for a in official)
    assert "/about" not in urls
    assert "mailto" not in urls
    assert "javascript" not in urls

    # every entry has url + handle + source
    for acc in official:
        assert acc["url"].startswith("https://")
        assert acc["handle"]
        assert acc["source"] in ("homepage", "rel=me", "webfinger")


def test_extract_official_mastodon_at_handle():
    html = '<a href="https://mastodon.social/@acme@mastodon.social">M</a>'
    official = brand_mod._extract_official(html, "acme.com")
    assert any(a["platform"] == "mastodon" for a in official)


def test_extract_official_empty_html():
    assert brand_mod._extract_official("", "acme.com") == []
    assert brand_mod._extract_official("<html></html>", "acme.com") == []


# --------------------------------------------------------------------------- #
# Variant generation
# --------------------------------------------------------------------------- #
def test_build_variants_for_simple_domain():
    variants = brand_mod._build_variants("acme.com")
    assert variants[0] == "acme"
    assert "acmeofficial" in variants
    assert "acmesupport" in variants
    assert "acmehelp" in variants
    assert "acmehq" in variants
    assert "acmecorp" in variants
    assert "acme-team" in variants
    assert len(variants) <= 7
    assert len(variants) == len(set(variants))
    assert all(len(v) <= 40 for v in variants)


def test_build_variants_for_subdomain_uses_registrable_label():
    variants = brand_mod._build_variants("app.acme.co.uk")
    assert variants[0] == "acme"


# --------------------------------------------------------------------------- #
# Severity mapping
# --------------------------------------------------------------------------- #
def test_candidate_reason_severity_mapping():
    reason, severity = brand_mod._candidate_reason(
        "acmesupport", "github", "acme.com")
    assert severity == "high"
    assert "acmesupport" in reason and "github" in reason
    assert "acme.com" in reason

    _, severity = brand_mod._candidate_reason("acmeofficial", "reddit",
                                              "acme.com")
    assert severity == "high"
    _, severity = brand_mod._candidate_reason("acmehelp", "reddit",
                                              "acme.com")
    assert severity == "high"

    _, severity = brand_mod._candidate_reason("acmehq", "github", "acme.com")
    assert severity == "medium"
    _, severity = brand_mod._candidate_reason("acme-team", "github",
                                              "acme.com")
    assert severity == "medium"

    _, severity = brand_mod._candidate_reason("acme", "github", "acme.com")
    assert severity == "low"


# --------------------------------------------------------------------------- #
# Domain validation / normalization
# --------------------------------------------------------------------------- #
def test_domain_validation():
    with pytest.raises(ValueError):
        brand_mod.lookup_brand("nodot")
    with pytest.raises(ValueError):
        brand_mod.lookup_brand("")
    with pytest.raises(ValueError):
        brand_mod.lookup_brand("https:///bad")


def test_domain_normalization_strips_scheme_and_path(monkeypatch):
    monkeypatch.setattr(brand_mod, "http_get",
                        lambda url, **kw: None)  # hermetic
    result = brand_mod.lookup_brand("https://Acme.COM/about/team")
    assert result["domain"] == "acme.com"


# --------------------------------------------------------------------------- #
# Hermetic lookup: homepage + impersonation probes
# --------------------------------------------------------------------------- #
def _make_fake_http(homepage_html, found_variants=(), official_handles=()):
    """Build a fake http_get: homepage 200, probe sites per variant set."""
    def fake_http(url, **kwargs):
        if url.rstrip("/").endswith("acme.com"):
            return FakeResponse(200, text=homepage_html, url=url)
        # probe URLs look like https://github.com/acmeofficial etc.
        for site in brand_mod.SITES:
            for variant in brand_mod._build_variants("acme.com"):
                probe = site["url"].format(u=variant)
                if url == probe:
                    if variant in found_variants \
                            and site["name"] == "GitHub":
                        return FakeResponse(200, url=url)
                    return FakeResponse(404, url=url)
        return FakeResponse(404, url=url)
    return fake_http


def test_lookup_brand_flags_impersonation(monkeypatch):
    html = ('<html><body>'
            '<a href="https://github.com/acme">GitHub</a>'
            '</body></html>')
    fake = _make_fake_http(html, found_variants=("acmesupport", "acme"))
    monkeypatch.setattr(brand_mod, "http_get", fake)

    result = brand_mod.lookup_brand("acme.com")
    assert result["domain"] == "acme.com"
    assert result["official_count"] == 1
    assert result["official"][0]["platform"] == "github"
    assert result["official"][0]["handle"] == "acme"

    # 'acme' on GitHub matches the official link -> NOT a candidate
    # 'acmesupport' on GitHub is not linked -> high-severity candidate
    assert len(result["candidates"]) == 1
    cand = result["candidates"][0]
    assert cand["handle"] == "acmesupport"
    assert cand["platform"] == "github"
    assert cand["severity"] == "high"
    assert "not linked from acme.com" in cand["reason"]

    assert "acme" in result["variants_checked"]
    assert result["sources_status"]["homepage"] == "ok"
    # coverage notes flag missing official accounts
    notes = " ".join(n["note"] for n in result["coverage_notes"])
    assert "instagram" in notes.lower()


def test_lookup_brand_no_candidates_is_clean(monkeypatch):
    html = '<html><body><a href="https://github.com/acme">gh</a></body></html>'
    fake = _make_fake_http(html, found_variants=())
    monkeypatch.setattr(brand_mod, "http_get", fake)

    result = brand_mod.lookup_brand("acme.com")
    assert result["candidates"] == []
    assert result["official_count"] == 1


def test_lookup_brand_homepage_down_degrades(monkeypatch):
    def fake_http(url, **kwargs):
        return None

    monkeypatch.setattr(brand_mod, "http_get", fake_http)
    result = brand_mod.lookup_brand("acme.com")
    assert result["official"] == []
    assert result["official_count"] == 0
    assert result["sources_status"]["homepage"] == "error: no_response"


def test_render_text_smoke(monkeypatch, capsys):
    html = ('<html><body>'
            '<a href="https://github.com/acme">GitHub</a>'
            '</body></html>')
    fake = _make_fake_http(html, found_variants=("acmesupport",))
    monkeypatch.setattr(brand_mod, "http_get", fake)
    result = brand_mod.lookup_brand("acme.com")
    brand_mod.render_text(result)
    out = capsys.readouterr().out
    assert "acme.com" in out
    assert "acmesupport" in out
    assert "SUMMARY" in out
