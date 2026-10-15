"""Tests for nexora.advanced: risk scoring + email-security collector."""
from __future__ import annotations

import pytest

from nexora import advanced
from nexora.advanced import (
    EmailSecurity,
    RiskScore,
    SensitivePath,
    SecurityHeaders,
    WafCdn,
    _collect_email_security,
    compute_risk_score,
)


def _finding_text(finding):
    """Findings are strings today ("... (+N)"); tolerate dict-shaped
    findings if the module evolves."""
    if isinstance(finding, dict):
        return str(finding.get("detail") or finding.get("finding")
                   or finding.get("message") or finding)
    return str(finding)


def _score(**kwargs):
    args = dict(
        domain="example.com",
        email_security=None,
        waf_cdn=None,
        security_headers=None,
        sensitive_paths=None,
        web_fingerprint=None,
        subdomain_count=0,
        port_count=0,
        vulnerabilities=None,
        whois=None,
        sources_status={},
        subdomain_takeover=None,
    )
    args.update(kwargs)
    return compute_risk_score(**args)


# --------------------------------------------------------------------------- #
# compute_risk_score
# --------------------------------------------------------------------------- #
def test_all_collectors_none_returns_valid_score():
    rs = _score()
    assert rs is not None
    assert isinstance(rs, RiskScore)
    assert 0 <= rs.score <= 100
    assert rs.grade in ("A", "B", "C", "D", "F")
    assert isinstance(rs.findings, list)
    for f in rs.findings:
        assert _finding_text(f)  # every finding has readable text
    # nothing was collected -> nothing to complain about
    assert rs.score == 0
    assert rs.grade == "A"


def test_missing_dmarc_spf_scores_worse_than_present():
    absent = EmailSecurity(domain="example.com")  # all records None
    present = EmailSecurity(
        domain="example.com",
        spf_record="v=spf1 -all", spf_valid=True,
        dmarc_record="v=DMARC1; p=reject", dmarc_policy="reject",
        dkim_selectors_found=["google"],
    )
    rs_absent = _score(email_security=absent)
    rs_present = _score(email_security=present)
    texts = [_finding_text(f) for f in rs_absent.findings]
    assert any("DMARC" in t for t in texts)
    assert any("SPF" in t for t in texts)
    assert rs_absent.score > rs_present.score
    assert rs_present.score == 0


def test_takeover_vulnerable_pushes_score_up():
    clean = [{"subdomain": "a.example.com", "vulnerable": False}]
    vulnerable = [{"subdomain": "a.example.com", "vulnerable": True}]
    rs_clean = _score(subdomain_takeover=clean)
    rs_vuln = _score(subdomain_takeover=vulnerable)
    assert rs_vuln.score > rs_clean.score
    assert any("takeover" in _finding_text(f) for f in rs_vuln.findings)


def test_missing_hsts_csp_adds_header_findings():
    bare = SecurityHeaders()  # every header None, grade "F"
    complete = SecurityHeaders(
        strict_transport_security="max-age=31536000",
        content_security_policy="default-src 'self'",
        x_frame_options="DENY",
        x_content_type_options="nosniff",
        grade="A",
    )
    rs_bare = _score(security_headers=bare)
    rs_full = _score(security_headers=complete)
    texts = [_finding_text(f) for f in rs_bare.findings]
    assert any("Strict-Transport-Security" in t for t in texts)
    assert any("Content-Security-Policy" in t for t in texts)
    assert rs_bare.score > rs_full.score
    assert rs_full.score == 0


def test_waf_findings_add_weight():
    rs = _score(waf_cdn=WafCdn(cors_wildcard=True,
                               http_to_https_redirect=False,
                               cookies_secure=False))
    texts = [_finding_text(f) for f in rs.findings]
    assert any("CORS" in t for t in texts)
    assert rs.score >= 28  # 15 + 8 + 5


def test_backup_sensitive_path_adds_finding():
    path = SensitivePath(path="/backup.sql", status=200, category="backup",
                         severity="critical",
                         description="Database backup exposed")
    rs = _score(sensitive_paths=[path])
    assert rs.score >= 25
    assert any("backup.sql" in _finding_text(f) for f in rs.findings)

    # restricted paths are ignored
    restricted = SensitivePath(path="/backup.sql", status=200,
                               category="backup", severity="critical",
                               description="x", restricted=True)
    assert _score(sensitive_paths=[restricted]).score == 0


def test_grade_thresholds_sanity():
    low = _score(port_count=1)        # +5  -> score 5  -> grade A
    assert low.score < 15
    assert low.grade == "A"
    edge = _score(port_count=10)      # +15 -> score 15 -> grade B
    assert edge.score == 15
    assert edge.grade == "B"


# --------------------------------------------------------------------------- #
# _collect_email_security (hermetic via fake_dns)
# --------------------------------------------------------------------------- #
def test_collect_email_security_full_records(fake_dns):
    import nexora.net as net
    if not net._HAS_DNS:
        pytest.skip("dnspython not installed")
    fake_dns.set("example.com", "MX", (10, "aspmx.l.google.com."))
    fake_dns.set("example.com", "TXT", "v=spf1 -all")
    fake_dns.set("_dmarc.example.com", "TXT",
                 "v=DMARC1; p=reject; rua=mailto:dmarc@example.com")
    fake_dns.set("google._domainkey.example.com", "TXT",
                 "v=DKIM1; k=rsa; p=MIGfMA0GCS")

    status = {}
    es = _collect_email_security("example.com", status)
    assert es is not None
    assert es.mx_hosts == ["aspmx.l.google.com"]
    assert es.provider == "Google Workspace"
    assert es.spf_record is not None
    assert es.spf_valid is True
    assert es.dmarc_record is not None
    assert es.dmarc_policy == "reject"
    assert "google" in es.dkim_selectors_found
    assert status["email-mx"] == "ok"
    assert status["email-security"] == "ok"
    assert 0 <= es.score <= 100


def test_collect_email_security_no_records(fake_dns):
    status = {}
    es = _collect_email_security("bare.example", status)
    assert es is not None
    assert es.mx_hosts == []
    assert es.spf_record is None
    assert es.dmarc_record is None
    assert status["email-mx"] == "no_mx"
    assert es.issues
    assert es.score < 100
