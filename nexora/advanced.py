"""Standalone advanced web-security collectors (CLI parity with
``app.engine.osint_advanced``).

Provides, all key-free and graceful-degrading:

* Email security      — SPF / DMARC / DKIM / MTA-STS / TLS-RPT / DANE
* Sensitive paths     — 35+ probes with soft-404 baseline detection
* Web intel           — WAF/CDN detection, security headers, CORS, cookies,
                         technology fingerprinting, content harvesting
* Redirect checks     — HTTP → HTTPS enforcement
* Risk scoring        — weighted findings -> 0–100 score + letter grade

``osint.py`` falls back to this module when the FastAPI app is unavailable.
"""
from __future__ import annotations

import io
import random
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .net import http_get, resolve_mx, resolve_txt

# --------------------------------------------------------------------------- #
# Data structures (mirrors the shapes produced by osint_advanced)
# --------------------------------------------------------------------------- #
@dataclass
class EmailSecurity:
    domain: str = ""
    mx_hosts: List[str] = field(default_factory=list)
    provider: Optional[str] = None
    spf_record: Optional[str] = None
    spf_lookups: int = 0
    spf_valid: Optional[bool] = None
    dmarc_record: Optional[str] = None
    dmarc_policy: Optional[str] = None
    dmarc_sub_policy: Optional[str] = None
    dmarc_rua: Optional[str] = None
    dmarc_enforce: Optional[bool] = None
    dkim_selectors_tested: List[str] = field(default_factory=list)
    dkim_selectors_found: List[str] = field(default_factory=list)
    mta_sts: Optional[str] = None
    tls_rpt: Optional[str] = None
    dane_tlsa: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    score: int = 100


@dataclass
class WafCdn:
    detections: List[str] = field(default_factory=list)
    provider: Optional[str] = None
    cors_origin: Optional[str] = None
    cors_wildcard: bool = False
    cookies_secure: Optional[bool] = None
    cookies_httponly: Optional[bool] = None
    cookies_samesite: Optional[str] = None
    http_to_https_redirect: Optional[bool] = None
    redirect_url: Optional[str] = None


@dataclass
class SecurityHeaders:
    strict_transport_security: Optional[str] = None
    content_security_policy: Optional[str] = None
    x_frame_options: Optional[str] = None
    x_content_type_options: Optional[str] = None
    referrer_policy: Optional[str] = None
    permissions_policy: Optional[str] = None
    x_xss_protection: Optional[str] = None
    cross_origin_opener_policy: Optional[str] = None
    cross_origin_resource_policy: Optional[str] = None
    expect_ct: Optional[str] = None
    server: Optional[str] = None
    powered_by: Optional[str] = None
    missing: List[str] = field(default_factory=list)
    grade: str = "F"


@dataclass
class SensitivePath:
    path: str
    status: int
    category: str
    severity: str
    description: str
    size: int = 0
    restricted: bool = False


@dataclass
class WebFingerprint:
    title: Optional[str] = None
    cms: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    trackers: List[str] = field(default_factory=list)
    meta_generator: Optional[str] = None
    email_addresses: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    social_links: List[str] = field(default_factory=list)
    html_comments: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class RiskScore:
    score: int = 0
    grade: str = "A"
    findings: List[str] = field(default_factory=list)
    factors: Dict[str, int] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Email security (SPF / DMARC / DKIM / MTA-STS / TLS-RPT / DANE)
# --------------------------------------------------------------------------- #
_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "s1", "s2",
    "mail", "dkim", "smtp", "20161025", "scph0520",
]
_MAIL_PROVIDERS = [
    ("aspmx.l.google.com", "Google Workspace"), ("google.com", "Google Workspace"),
    ("protection.outlook.com", "Microsoft 365"), ("email_srvr", "Proofpoint"),
    ("mail.proton.me", "Proton Mail"), ("mx.zoho", "Zoho Mail"),
    ("mx.ezhostingserver", "Zoho"), ("fastmail", "Fastmail"),
    ("mx.sendgrid.net", "SendGrid"), ("amazonses.com", "Amazon SES"),
    ("mailgun.org", "Mailgun"), ("postmarkapp.com", "Postmark"),
    ("spf.mandrillapp.com", "Mandrive/Mailchimp"), ("email.awsapps.com", "Amazon WorkMail"),
    ("messagingengine.com", "Fastmail"), ("lxer.com", None),
]


def _parse_spf(record: str) -> Tuple[int, Optional[str], List[str]]:
    """Return (lookup_count, all_mechanism, issues) for an SPF record."""
    issues: List[str] = []
    terms = record.split()[1:]
    lookups = 0
    all_mech: Optional[str] = None
    for t in terms:
        low = t.lower()
        if low.startswith(("include:", "redirect=", "exists:", "a:", "mx:", "ptr:")):
            if not low.startswith("redirect=") or "=" in low:
                lookups += 1 if not low.startswith("a:") else 1
        if low in ("+all", "~all", "-all", "?all"):
            all_mech = t
    if all_mech == "+all":
        issues.append("SPF '+all' — mail from ANY source is accepted (critical)")
    elif all_mech in ("?all", "~all"):
        issues.append(f"SPF '{all_mech}' — soft pass, spoofing still possible")
    if lookups > 10:
        issues.append(f"SPF uses {lookups} DNS lookups (RFC limit is 10 — record may be ignored)")
    return lookups, all_mech, issues


def _collect_email_security(domain: str, status: Dict[str, str]) -> Optional[EmailSecurity]:
    es = EmailSecurity(domain=domain)

    # MX
    es.mx_hosts = resolve_mx(domain)
    if es.mx_hosts:
        status["email-mx"] = "ok"
        low = " ".join(es.mx_hosts).lower()
        for needle, name in _MAIL_PROVIDERS:
            if needle in low and name:
                es.provider = name
                break
    else:
        status["email-mx"] = "no_mx"
        es.issues.append("No MX records found")

    # SPF
    txts = resolve_txt(domain)
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    if spf:
        es.spf_record = spf[0]
        es.spf_lookups, _, spf_issues = _parse_spf(spf[0])
        es.issues.extend(spf_issues)
        es.spf_valid = not any("critical" in i for i in spf_issues)
    else:
        es.spf_valid = False
        es.issues.append("No SPF record — anyone can spoof your domain")

    # DMARC
    dmarc_txts = resolve_txt(f"_dmarc.{domain}")
    dmarc = [t for t in dmarc_txts if t.upper().startswith("V=DMARC1")]
    if dmarc:
        es.dmarc_record = dmarc[0]
        for part in dmarc[0].split(";"):
            part = part.strip()
            if part.lower().startswith("p="):
                es.dmarc_policy = part[2:].lower()
            elif part.lower().startswith("sp="):
                es.dmarc_sub_policy = part[3:].lower()
            elif part.lower().startswith("rua="):
                es.dmarc_rua = part[4:]
        es.dmarc_enforce = es.dmarc_policy in ("quarantine", "reject")
        if es.dmarc_policy == "none":
            es.issues.append("DMARC policy 'p=none' — monitor only, no enforcement")
    else:
        es.issues.append("No DMARC record — spoofed mail won't be blocked")

    # DKIM (common selectors)
    es.dkim_selectors_tested = list(_DKIM_SELECTORS)
    for sel in _DKIM_SELECTORS:
        recs = resolve_txt(f"{sel}._domainkey.{domain}")
        if any(("p=" in r and "v=DKIM1" in r) or r.startswith("v=DKIM1") for r in recs):
            es.dkim_selectors_found.append(sel)
    if not es.dkim_selectors_found:
        es.issues.append("No DKIM record on common selectors (mail may be unsigned)")

    # MTA-STS + TLS-RPT
    sts = [t for t in resolve_txt(f"_mta-sts.{domain}") if t.startswith("v=STSv1")]
    es.mta_sts = sts[0] if sts else None
    rpt = [t for t in resolve_txt(f"_smtp._tls.{domain}") if t.startswith("v=TLSRPTv1")]
    es.tls_rpt = rpt[0] if rpt else None

    # DANE TLSA (443 + 25)
    try:
        import dns.resolver  # type: ignore
        for port in ("443", "25"):
            try:
                ans = dns.resolver.resolve(f"_{port}._tcp.{domain}", "TLSA", lifetime=4)
                es.dane_tlsa.extend(f"_{port}._tcp: {r}" for r in ans)
            except Exception:
                continue
    except Exception:
        pass

    # Score
    score = 100
    if not es.dmarc_record:
        score -= 35
    elif es.dmarc_policy == "none":
        score -= 15
    if not es.spf_record:
        score -= 20
    elif not es.spf_valid:
        score -= 15
    if not es.dkim_selectors_found:
        score -= 10
    if not es.mx_hosts:
        score -= 10
    es.score = max(0, min(100, score))
    status["email-security"] = "ok"
    return es


# --------------------------------------------------------------------------- #
# Sensitive paths (with soft-404 baseline)
# --------------------------------------------------------------------------- #
_SENSITIVE_PATHS = [
    ("/.git/config", "source-control", "critical", "Git repository metadata exposed"),
    ("/.git/HEAD", "source-control", "high", "Git HEAD file exposed"),
    ("/.svn/entries", "source-control", "high", "Subversion metadata exposed"),
    ("/.hg/hgrc", "source-control", "high", "Mercurial config exposed"),
    ("/.env", "config", "critical", "Environment file may contain secrets"),
    ("/.aws/credentials", "credentials", "critical", "AWS credentials file"),
    ("/config.json", "config", "high", "Configuration file exposed"),
    ("/composer.json", "config", "medium", "PHP dependencies exposed"),
    ("/package.json", "config", "medium", "Node dependencies exposed"),
    ("/.htaccess", "config", "medium", "Apache config exposed"),
    ("/web.config", "config", "medium", "IIS config exposed"),
    ("/wp-config.php.bak", "config", "critical", "WordPress config backup"),
    ("/wp-config.php~", "config", "critical", "WordPress config backup"),
    ("/phpinfo.php", "debug", "high", "phpinfo() exposed"),
    ("/info.php", "debug", "high", "phpinfo() exposed"),
    ("/server-status", "server", "medium", "Apache status page"),
    ("/server-info", "server", "medium", "Apache server info"),
    ("/actuator/health", "debug", "medium", "Spring Boot actuator exposed"),
    ("/actuator/env", "debug", "high", "Spring Boot env endpoint (secrets)"),
    ("/actuator/mappings", "debug", "medium", "Spring Boot mappings exposed"),
    ("/jmx-console/", "debug", "high", "JBoss JMX console exposed"),
    ("/elmah.axd", "debug", "medium", "ELMAH error log exposed"),
    ("/trace.axd", "debug", "medium", "ASP.NET trace exposed"),
    ("/swagger-ui.html", "debug", "low", "API documentation exposed"),
    ("/backup.zip", "backup", "high", "Backup archive exposed"),
    ("/backup.sql", "backup", "critical", "Database backup exposed"),
    ("/dump.sql", "backup", "critical", "Database dump exposed"),
    ("/db.sql", "backup", "critical", "Database dump exposed"),
    ("/.DS_Store", "info", "medium", "macOS directory listing leaked"),
    ("/.travis.yml", "ci", "medium", "CI config exposed"),
    ("/.gitlab-ci.yml", "ci", "low", "CI config exposed"),
    ("/security.txt", "info", "low", "Security contact file"),
    ("/.well-known/security.txt", "info", "low", "Security contact file"),
    ("/crossdomain.xml", "info", "low", "Flash cross-domain policy"),
    ("/.well-known/change-password", "info", "low", "Password change endpoint"),
    ("/admin", "admin", "medium", "Admin interface detected"),
    ("/administrator", "admin", "medium", "Admin interface detected"),
    ("/console", "admin", "medium", "Console interface detected"),
]


def _read_body(resp, cap: int = 16384) -> bytes:
    buf = b""
    try:
        for chunk in resp.iter_content(8192):
            buf += chunk
            if len(buf) >= cap:
                break
    except Exception:
        pass
    finally:
        try:
            resp.close()
        except Exception:
            pass
    return buf[:cap]


def _collect_sensitive_paths(domain: str, status: Dict[str, str]) -> List[SensitivePath]:
    found: List[SensitivePath] = []

    # Soft-404 baseline: fetch a random non-existent path to learn what
    # "not found" looks like (status + size) on this site.
    base_status, base_len, base_sig = 404, 0, b""
    probe = f"/nexora-404-{random.getrandbits(32):08x}"
    r = http_get(f"https://{domain}{probe}", timeout=6, stream=True)
    if r is None or r.status_code >= 500:
        r = http_get(f"http://{domain}{probe}", timeout=6, stream=True)
    if r is not None:
        base_status = r.status_code
        body = _read_body(r)
        base_len, base_sig = len(body), body[:300]
    status["soft-404-baseline"] = f"status_{base_status}"

    def _probe(entry: Tuple[str, str, str, str]) -> Optional[SensitivePath]:
        path, category, severity, desc = entry
        for scheme in ("https", "http"):
            resp = http_get(f"{scheme}://{domain}{path}", timeout=6, stream=True)
            if resp is None:
                continue
            try:
                code = resp.status_code
                if code not in (200, 401, 403):
                    break
                if code == 200:
                    body = _read_body(resp)
                    # Soft-404: catch-all SPA returns 200 for everything
                    if base_status == 200:
                        if abs(len(body) - base_len) < 40 and body[:300] == base_sig:
                            break
                        ctype = resp.headers.get("Content-Type", "")
                        if "text/html" in ctype and len(body) < 400:
                            break
                    return SensitivePath(
                        path=path, status=code, category=category,
                        severity=severity, description=desc, size=len(body),
                        restricted=False,
                    )
                # 401 / 403 — resource exists but is protected
                return SensitivePath(
                    path=path, status=code, category=category,
                    severity="low" if severity in ("high", "critical") else severity,
                    description=desc + " (restricted)", size=0, restricted=True,
                )
            except Exception:
                break
        return None

    with ThreadPoolExecutor(max_workers=15) as ex:
        for fut in as_completed([ex.submit(_probe, e) for e in _SENSITIVE_PATHS]):
            try:
                item = fut.result()
                if item:
                    found.append(item)
            except Exception:
                pass

    active = [f for f in found if not f.restricted]
    if active:
        status["sensitive-paths"] = f"{len(active)} found"
    elif found:
        status["sensitive-paths"] = f"{len(found)} restricted"
    else:
        status["sensitive-paths"] = "no_results"
    found.sort(key=lambda p: (p.restricted, p.path))
    return found


# --------------------------------------------------------------------------- #
# Web intel: WAF/CDN + security headers + CORS/cookies + fingerprint
# --------------------------------------------------------------------------- #
_WAF_SIGNATURES = [
    ("Cloudflare", [("cf-ray", None), ("cf-cache-status", None), ("server", "cloudflare")]),
    ("Sucuri", [("x-sucuri-id", None), ("server", "sucuri")]),
    ("Imperva/Incapsula", [("x-iinfo", None), ("x-cdn", "incapsula")]),
    ("Fastly", [("x-fastly-request-id", None), ("x-served-by", "fastly")]),
    ("Akamai", [("x-akamai-transformed", None), ("server", "akamaighost"), ("x-akamai-grn", None)]),
    ("AWS CloudFront", [("x-amz-cf-id", None), ("x-amz-cf-pop", None)]),
    ("AWS ALB", [("x-amzn-requestid", None), ("server", "awselb")]),
    ("F5 BIG-IP", [("set-cookie", "bigipserver")]),
    ("KeyCDN", [("x-keycdn", None)]),
    ("StackPath", [("x-served-by", "stackpath")]),
    ("EdgeCast", [("server", "ecs")]),
    ("Varnish", [("x-varnish", None)]),
    ("Wordfence", [("set-cookie", "wordfence")]),
    ("BunnyCDN", [("server", "bunnycdn")]),
]

_TRACKER_SIGNATURES = {
    "Google Tag Manager": ["googletagmanager.com/gtm.js", "gtm.js"],
    "Google Analytics": ["google-analytics.com/analytics.js", "ga.js", "gtag(", "google-analytics.com/ga"],
    "Facebook Pixel": ["fbq(", "connect.facebook.net", "fbevents.js"],
    "Hotjar": ["hotjar.com", "static.hotjar.com"],
    "Segment": ["segment.com/analytics.js", "cdn.segment.com"],
    "Mixpanel": ["mixpanel.com", "mixpanel.init"],
    "Matomo/Piwik": ["matomo.js", "piwik.js", "matomo.cloud"],
    "Plausible": ["plausible.io/js"],
    "Fathom Analytics": ["fathom.cloud", "cdn.usefathom.com"],
    "Microsoft Clarity": ["clarity.ms"],
    "FullStory": ["fullstory.com", "fs.js"],
    "Heap": ["heap-api.com", "heapanalytics.com"],
    "Intercom": ["intercom.io", "intercomcdn.com"],
    "Drift": ["drift.com", "js.driftt.com"],
    "Crisp": ["crisp.chat"],
    "tawk.to": ["tawk.to"],
    "HubSpot": ["js.hs-scripts.com", "hubspot.com"],
    "Mailchimp": ["list-manage.com", "mailchimp.com"],
    "Zendesk": ["zendesk.com", "static.zdassets.com"],
    "reCAPTCHA": ["recaptcha.net", "google.com/recaptcha"],
    "New Relic": ["newrelic.com", "nr-data.net"],
    "Sentry": ["browser.sentry-cdn.com", "sentry.io"],
    "Optimizely": ["optimizely.com"],
}

_CMS_SIGNATURES = {
    "WordPress": ["wp-content/", "wp-includes/", "/wp-json/"],
    "Drupal": ["drupal-settings-json", "/sites/default/", "drupal.js"],
    "Joomla": ["/media/jui/", "com_content", "joomla"],
    "Shopify": ["cdn.shopify.com", "Shopify.theme"],
    "Magento": ["/static/version", "Magento_", "mage/"],
    "Wix": ["wix.com", "wixstatic.com"],
    "Squarespace": ["squarespace.com", "static1.squarespace"],
    "Webflow": ["webflow.js", "assets.website-files.com"],
    "Ghost": ["ghost.io", "/assets/built/"],
    "HubSpot CMS": ["hs-scripts.com", "hs-sites.com"],
    "TYPO3": ["typo3", "fileadmin/"],
}

_SOCIAL_DOMAINS = (
    "twitter.com", "x.com", "facebook.com", "linkedin.com", "instagram.com",
    "github.com", "youtube.com", "tiktok.com", "medium.com", "reddit.com",
    "pinterest.com", "t.me", "discord.gg", "slack.com",
)

_COMMENT_CATEGORIES = [
    (("password", "secret", "api key", "apikey", "token", "credential"), "credential"),
    (("todo", "fixme", "hack", "xxx"), "todo"),
    (("copyright", "license", "all rights"), "legal"),
    (("note:", "warning", "deprecated", "temp", "temporary"), "note"),
]


def _grade_headers(sh: SecurityHeaders, https: bool) -> None:
    penalty = 0
    checks = [
        (sh.strict_transport_security, "Strict-Transport-Security", 30 if https else 0),
        (sh.content_security_policy, "Content-Security-Policy", 25),
        (sh.x_frame_options, "X-Frame-Options", 10),
        (sh.x_content_type_options, "X-Content-Type-Options", 10),
        (sh.referrer_policy, "Referrer-Policy", 10),
        (sh.permissions_policy, "Permissions-Policy", 5),
        (sh.cross_origin_opener_policy, "Cross-Origin-Opener-Policy", 5),
    ]
    for value, name, weight in checks:
        if not value and weight:
            sh.missing.append(name)
            penalty += weight
    raw = max(0, 100 - penalty)
    sh.grade = ("A" if raw >= 90 else "B" if raw >= 80 else
                "C" if raw >= 70 else "D" if raw >= 60 else "F")


def _harvest_fingerprint(body_text: str, headers: Dict[str, str]) -> WebFingerprint:
    fp = WebFingerprint()
    low = body_text.lower()

    m = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.I | re.S)
    if m:
        fp.title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]

    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body_text, re.I)
    if m:
        fp.meta_generator = m.group(1)[:120]

    # Technologies from headers
    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    for value in (server, powered):
        if value:
            fp.technologies.append(value.split("/")[0].strip())
    if headers.get("CF-Ray"):
        fp.technologies.append("Cloudflare")

    # CMS
    for name, sigs in _CMS_SIGNATURES.items():
        if any(s.lower() in low for s in sigs):
            fp.cms = name
            fp.technologies.append(name)
            break

    # JS libraries / frameworks
    lib_sigs = {
        "jQuery": ["jquery.min.js", "jquery-", "jquery("],
        "React": ["react.min.js", "react-dom", "__react"],
        "Vue.js": ["vue.min.js", "vue.runtime", "__vue__"],
        "Angular": ["ng-version", "angular.min.js"],
        "Svelte": ["svelte.", "__svelte"],
        "Next.js": ["__next/", "_next/static"],
        "Nuxt.js": ["__nuxt", "_nuxt/"],
        "Bootstrap": ["bootstrap.min.css", "bootstrap.js"],
        "Tailwind CSS": ["tailwindcss", "tw-"],
        "Axios": ["axios.min.js", "axios@"],
        "Lodash": ["lodash.min.js", "lodash.com"],
        "Alpine.js": ["alpinejs", "x-data="],
    }
    for name, sigs in lib_sigs.items():
        if any(s.lower() in low for s in sigs):
            fp.technologies.append(name)

    # Trackers
    for name, sigs in _TRACKER_SIGNATURES.items():
        if any(s.lower() in low for s in sigs):
            fp.trackers.append(name)

    # Emails (mailto + plaintext)
    emails = set(re.findall(r"mailto:([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", body_text, re.I))
    emails.update(re.findall(
        r"(?<![\w.-])([A-Za-z0-9._%+-]+@(?!example\.(?:com|org|net)|test\.[a-z]{2,})"
        r"[A-Za-z0-9.-]+\.[A-Za-z]{2,})", body_text))
    fp.email_addresses = sorted(emails)[:25]

    # Phone numbers
    fp.phone_numbers = sorted(set(re.findall(
        r"(?<!\d)(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{3,4}[\s.-]\d{3,4}(?:[\s.-]\d{3,4})?(?!\d)",
        body_text)))[:15]

    # Social links
    socials = set()
    for href in re.findall(r'href=["\']([^"\']+)["\']', body_text, re.I):
        h = href.lower()
        if any(d in h for d in _SOCIAL_DOMAINS):
            socials.add(href[:200])
    fp.social_links = sorted(socials)[:20]

    # HTML comments (categorized; text preserved for JSON, redacted upstream)
    for raw in re.findall(r"<!--(.*?)-->", body_text, re.S)[:40]:
        text = re.sub(r"\s+", " ", raw).strip()
        if not text or len(text) > 400:
            continue
        category = "info"
        lowt = text.lower()
        for words, cat in _COMMENT_CATEGORIES:
            if any(w in lowt for w in words):
                category = cat
                break
        fp.html_comments.append({"text": text[:300], "category": category})

    # Deduplicate tech, preserve order
    seen, uniq = set(), []
    for t in fp.technologies:
        tl = t.lower()
        if tl and tl not in seen:
            seen.add(tl)
            uniq.append(t)
    fp.technologies = uniq
    return fp


def _collect_web_intel(domain: str, status: Dict[str, str]):
    """Returns (waf_cdn, security_headers, web_fingerprint, cors_dict)."""
    waf = WafCdn()
    sh = SecurityHeaders()
    fp = WebFingerprint()
    cors: Dict[str, object] = {}

    resp = None
    scheme_used = "https"
    for scheme in ("https", "http"):
        resp = http_get(
            f"{scheme}://{domain}/",
            headers={"Origin": "https://nexora-probe.invalid"},
            timeout=8, stream=True,
        )
        if resp is not None and resp.status_code < 500:
            scheme_used = scheme
            break
    if resp is None:
        status["web-intel"] = "error: ConnectionError"
        return waf, sh, fp, cors

    try:
        headers = {k: v for k, v in resp.headers.items()}
        # Read a bounded amount of the body for fingerprinting
        body = _read_body(resp, cap=262144)
        text = body.decode("utf-8", "ignore")
        low_headers = {k.lower(): v for k, v in headers.items()}

        # WAF / CDN detection
        for name, sigs in _WAF_SIGNATURES:
            for key, needle in sigs:
                value = low_headers.get(key, "")
                if value and (needle is None or needle in value.lower()):
                    waf.detections.append(name)
                    break
        if waf.detections:
            waf.provider = waf.detections[0]
        status["waf-cdn"] = ", ".join(waf.detections) if waf.detections else "none_detected"

        # Security headers
        sh.strict_transport_security = headers.get("Strict-Transport-Security")
        sh.content_security_policy = headers.get("Content-Security-Policy")
        sh.x_frame_options = headers.get("X-Frame-Options")
        sh.x_content_type_options = headers.get("X-Content-Type-Options")
        sh.referrer_policy = headers.get("Referrer-Policy")
        sh.permissions_policy = headers.get("Permissions-Policy")
        sh.x_xss_protection = headers.get("X-XSS-Protection")
        sh.cross_origin_opener_policy = headers.get("Cross-Origin-Opener-Policy")
        sh.cross_origin_resource_policy = headers.get("Cross-Origin-Resource-Policy")
        sh.expect_ct = headers.get("Expect-CT")
        sh.server = headers.get("Server")
        sh.powered_by = headers.get("X-Powered-By")
        _grade_headers(sh, https=(scheme_used == "https"))
        status["security-headers"] = f"grade_{sh.grade}"

        # CORS
        acao = headers.get("Access-Control-Allow-Origin")
        waf.cors_origin = acao
        waf.cors_wildcard = acao == "*"
        cors["cors_origin"] = acao
        cors["cors_wildcard"] = waf.cors_wildcard

        # Cookies
        raw_cookies = headers.get("Set-Cookie", "")
        if raw_cookies:
            lowc = raw_cookies.lower()
            waf.cookies_httponly = "httponly" in lowc
            waf.cookies_secure = "secure" in lowc
            m = re.search(r"samesite=([a-z]+)", lowc)
            waf.cookies_samesite = m.group(1).capitalize() if m else None
        cors["cookies_secure"] = waf.cookies_secure
        cors["cookies_httponly"] = waf.cookies_httponly
        cors["cookies_samesite"] = waf.cookies_samesite

        # Fingerprint + harvest
        fp = _harvest_fingerprint(text, headers)
        status["web-fingerprint"] = (
            f"{fp.cms or 'unknown'} +{len(fp.technologies)} tech" if text else "empty_body")
    except Exception as e:
        status["web-intel"] = f"error: {type(e).__name__}"
    return waf, sh, fp, cors


def _collect_web_security(domain: str, status: Dict[str, str]) -> Dict[str, object]:
    """Check HTTP → HTTPS redirect enforcement."""
    result: Dict[str, object] = {"http_to_https_redirect": None, "redirect_url": None}
    try:
        resp = http_get(f"http://{domain}/", timeout=8)
        if resp is None:
            status["http-redirect"] = "error"
            return result
        final = resp.url or ""
        hops = list(getattr(resp, "history", []) or [])
        result["http_to_https_redirect"] = final.startswith("https://") and any(
            h.status_code in (301, 302, 307, 308) for h in hops)
        result["redirect_url"] = final if final and final != f"http://{domain}/" else None
        status["http-redirect"] = "ok" if result["http_to_https_redirect"] else "not_enforced"
    except Exception as e:
        status["http-redirect"] = f"error: {type(e).__name__}"
    return result


# --------------------------------------------------------------------------- #
# Risk scoring
# --------------------------------------------------------------------------- #
def compute_risk_score(
    domain: str,
    email_security,
    waf_cdn,
    security_headers,
    sensitive_paths,
    web_fingerprint,
    subdomain_count: int,
    port_count: int,
    vulnerabilities,
    whois,
    sources_status: Dict[str, str],
    subdomain_takeover,
) -> Optional[RiskScore]:
    """Weighted 0–100 risk score (higher = riskier) with letter grade."""
    try:
        rs = RiskScore()

        def add(weight: int, finding: str, factor: str) -> None:
            rs.score += weight
            rs.factors[factor] = rs.factors.get(factor, 0) + weight
            rs.findings.append(f"{finding} (+{weight})")

        # Email security
        if email_security is not None:
            if getattr(email_security, "dmarc_record", None) is None:
                add(20, "No DMARC record", "email")
            elif getattr(email_security, "dmarc_policy", None) == "none":
                add(10, "DMARC policy is p=none (no enforcement)", "email")
            if getattr(email_security, "spf_record", None) is None:
                add(15, "No SPF record", "email")
            elif getattr(email_security, "spf_valid", True) is False:
                add(10, "SPF record misconfigured", "email")
            if not getattr(email_security, "dkim_selectors_found", []):
                add(5, "No DKIM record on common selectors", "email")

        # Headers
        if security_headers is not None:
            grade = getattr(security_headers, "grade", "F")
            if not getattr(security_headers, "strict_transport_security", None):
                add(8, "Missing Strict-Transport-Security", "headers")
            if not getattr(security_headers, "content_security_policy", None):
                add(8, "Missing Content-Security-Policy", "headers")
            if not getattr(security_headers, "x_frame_options", None):
                add(5, "Missing X-Frame-Options (clickjacking)", "headers")
            if not getattr(security_headers, "x_content_type_options", None):
                add(4, "Missing X-Content-Type-Options", "headers")
            if grade in ("D", "F"):
                add(5, f"Security header grade {grade}", "headers")

        # CORS / cookies
        if waf_cdn is not None:
            if getattr(waf_cdn, "cors_wildcard", False):
                add(15, "CORS allows any origin (*)", "cors")
            if getattr(waf_cdn, "http_to_https_redirect", None) is False:
                add(8, "HTTP does not redirect to HTTPS", "transport")
            if getattr(waf_cdn, "cookies_secure", None) is False:
                add(5, "Cookies missing Secure flag", "cookies")
            if getattr(waf_cdn, "cookies_httponly", None) is False:
                add(5, "Cookies missing HttpOnly flag", "cookies")

        # Sensitive paths
        active = [p for p in (sensitive_paths or [])
                  if not getattr(p, "restricted", False)]
        if active:
            worst = max(active, key=lambda p: {"critical": 4, "high": 3, "medium": 2,
                                               "low": 1, "info": 0}.get(getattr(p, "severity", "low"), 0))
            sev = getattr(worst, "severity", "medium")
            weight = {"critical": 25, "high": 18, "medium": 10}.get(sev, 5)
            add(weight, f"{len(active)} sensitive path(s) exposed "
                        f"(worst: {getattr(worst, 'path', '?')} — {sev})", "exposure")
            if len(active) > 3:
                add(5, f"{len(active)} sensitive paths exposed", "exposure")

        # Takeover
        vulnerable = [t for t in (subdomain_takeover or [])
                      if isinstance(t, dict) and t.get("vulnerable")]
        if vulnerable:
            add(min(30, 25 * len(vulnerable)),
                f"{len(vulnerable)} subdomain(s) vulnerable to takeover", "takeover")

        # Sensitive HTML comments (credentials / internals leaked in source)
        comments = list(getattr(web_fingerprint, "html_comments", []) or [])
        if comments:
            sensitive_c = [c for c in comments if isinstance(c, dict)
                           and c.get("category") in
                           ("credential", "sensitive_keyword",
                            "internal_endpoint", "database_reference")]
            if sensitive_c:
                add(10, f"{len(sensitive_c)} sensitive HTML comments (secrets/internals)",
                    "content")
            else:
                add(3, f"{len(comments)} HTML comments with development notes", "content")

        # Open ports (engine passes a count)
        if port_count:
            if port_count > 5:
                add(15, f"{port_count} exposed ports", "exposure")
            else:
                add(5, f"{port_count} open ports discovered", "exposure")

        # Vulnerabilities (engine passes a count)
        vulns_count = (len(vulnerabilities)
                       if isinstance(vulnerabilities, (list, tuple, set))
                       else int(vulnerabilities or 0))
        if vulns_count > 5:
            add(20, f"{vulns_count} known CVEs in tech stack", "vulns")
        elif vulns_count:
            add(10, f"{vulns_count} known CVEs in tech stack", "vulns")

        # WHOIS age (recently registered = riskier)
        if whois and whois.get("registration_date"):
            import datetime as _dt
            try:
                d = _dt.datetime.fromisoformat(
                    str(whois["registration_date"]).replace("Z", "+00:00"))
                age_days = (_dt.datetime.now(_dt.timezone.utc) - d).days
                if age_days < 90:
                    add(10, f"Domain registered {age_days} days ago (very new)", "whois")
                elif age_days < 365:
                    add(4, f"Domain registered {age_days} days ago (relatively new)", "whois")
            except Exception:
                pass

        # Subdomain sprawl
        if subdomain_count and subdomain_count > 50:
            add(4, f"{subdomain_count} subdomains — large attack surface", "surface")

        rs.score = max(0, min(100, rs.score))
        rs.grade = ("A" if rs.score < 15 else "B" if rs.score < 30 else
                    "C" if rs.score < 50 else "D" if rs.score < 70 else "F")
        rs.findings.sort()
        return rs
    except Exception:
        return None
