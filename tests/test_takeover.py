"""Tests for nexora.takeover: fingerprint matching + end-to-end checks.

All DNS/HTTP is faked: ``_get_cname_chain`` reads canned CNAMEs from
``fake_dns`` (or is patched directly) and ``_fetch_body`` returns canned
bodies.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

import nexora.takeover as takeover


# --------------------------------------------------------------------------- #
# Fingerprint catalogue
# --------------------------------------------------------------------------- #
def test_fingerprints_shape():
    assert isinstance(takeover.FINGERPRINTS, dict)
    assert len(takeover.FINGERPRINTS) >= 10
    for service, markers in takeover.FINGERPRINTS.items():
        assert isinstance(service, str) and service
        assert isinstance(markers, list) and markers
        for marker in markers:
            assert isinstance(marker, str) and marker
    assert takeover.KNOWN_SERVICES == sorted(takeover.FINGERPRINTS)


def test_matches_service():
    match = takeover._matches_service
    assert match("blog.github.io") == "github.io"
    assert match("mybucket.s3.amazonaws.com") is not None
    assert match("static.example.net") is None
    assert match("github.io.evil.com") is None  # suffix must be at a dot


# --------------------------------------------------------------------------- #
# _check_one (pure matching with patched chain/body)
# --------------------------------------------------------------------------- #
def test_check_one_vulnerable_high_confidence(monkeypatch):
    monkeypatch.setattr(takeover, "_get_cname_chain",
                        lambda host, max_hops=5: ["mybucket.s3.amazonaws.com"])
    monkeypatch.setattr(takeover, "_fetch_body",
                        lambda url: "s3 remote error: nosuchbucket")
    item = takeover._check_one("bucket.example.com")
    assert item is not None
    assert item["subdomain"] == "bucket.example.com"
    assert item["vulnerable"] is True
    assert item["confidence"] == "high"
    assert "nosuchbucket" in (item["evidence"] or "")
    assert item["service"] in takeover.FINGERPRINTS


def test_check_one_clean_body_is_not_vulnerable(monkeypatch):
    monkeypatch.setattr(takeover, "_get_cname_chain",
                        lambda host, max_hops=5: ["app.github.io"])
    monkeypatch.setattr(takeover, "_fetch_body",
                        lambda url: "welcome to our real site")
    item = takeover._check_one("app.example.com")
    # service matches but no fingerprint -> at most a dangling candidate
    if item is not None:
        assert item["vulnerable"] is False
        assert item["confidence"] in ("medium", "low")


def test_check_one_unknown_service_returns_none(monkeypatch):
    monkeypatch.setattr(takeover, "_get_cname_chain",
                        lambda host, max_hops=5: ["internal.lb.example.com"])
    assert takeover._check_one("intranet.example.com") is None


def test_check_one_no_cname_returns_none(monkeypatch):
    monkeypatch.setattr(takeover, "_get_cname_chain",
                        lambda host, max_hops=5: [])
    assert takeover._check_one("plain.example.com") is None


# --------------------------------------------------------------------------- #
# check_subdomain_takeover (end-to-end with fake DNS)
# --------------------------------------------------------------------------- #
def test_get_cname_chain_with_fake_dns(fake_dns):
    if not takeover._HAS_DNS:
        pytest.skip("dnspython not installed")
    fake_dns.set("dangling.example.com", "CNAME", "bucket.s3.amazonaws.com.")
    assert takeover._get_cname_chain("dangling.example.com") == \
        ["bucket.s3.amazonaws.com"]
    # unknown names give an empty chain, never an exception
    assert takeover._get_cname_chain("nothing.example.com") == []


def test_check_subdomain_takeover_end_to_end(fake_dns, monkeypatch):
    if not takeover._HAS_DNS:
        pytest.skip("dnspython not installed")
    fake_dns.set("vuln.example.com", "CNAME", "bucket.s3.amazonaws.com.")
    monkeypatch.setattr(takeover, "_fetch_body",
                        lambda url: "s3 remote error: nosuchbucket")

    status = {}
    findings = takeover.check_subdomain_takeover(
        ["vuln.example.com", "clean.example.com"], status)

    assert len(findings) == 1
    vuln = findings[0]
    assert vuln["vulnerable"] is True
    assert vuln["subdomain"] == "vuln.example.com"
    assert status["subdomain-takeover"] == "1 vulnerable"


def test_check_subdomain_takeover_accepts_all_target_shapes(monkeypatch):
    if not takeover._HAS_DNS:
        pytest.skip("dnspython not installed")
    monkeypatch.setattr(takeover, "_get_cname_chain",
                        lambda host, max_hops=5: [])

    status = {}
    targets = [
        "plain.example.com",
        {"hostname": "dict.example.com"},
        SimpleNamespace(hostname="obj.example.com"),
    ]
    findings = takeover.check_subdomain_takeover(targets, status)
    assert findings == []
    assert status["subdomain-takeover"] == "no_findings"


def test_check_subdomain_takeover_no_targets(monkeypatch):
    if not takeover._HAS_DNS:
        pytest.skip("dnspython not installed")
    status = {}
    assert takeover.check_subdomain_takeover([], status) == []
    assert status["subdomain-takeover"] == "no_targets"
