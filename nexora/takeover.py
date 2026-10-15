"""Standalone subdomain-takeover detection (CLI parity with
``app.engine.takeover``).

Key-free approach: resolve the CNAME chain of each discovered subdomain; if
it points at a known hosting/service provider, fetch the host and compare
the response body against distinctive provider fingerprints.

Two confidence levels:
    vulnerable — CNAME → known service AND distinctive fingerprint matched
    dangling   — CNAME → known service but body inconclusive (reported, not
                 counted as vulnerable, to avoid false positives)
"""
from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from .net import http_get

try:
    import dns.resolver  # type: ignore
    _HAS_DNS = True
except ImportError:  # pragma: no cover
    _HAS_DNS = False

# service CNAME suffix -> distinctive body fingerprints (case-insensitive)
FINGERPRINTS: Dict[str, List[str]] = {
    "github.io": [
        "there isn't a github pages site here",
        "finding the page you are looking for",
    ],
    "herokuapp.com": ["no such app", "no-such-app"],
    "herokussl.com": ["no such app"],
    "amazonaws.com": [
        "nosuchbucket", "the specified bucket does not exist",
        "s3 remote error: nosuchbucket",
    ],
    "s3.amazonaws.com": ["nosuchbucket", "the specified bucket does not exist"],
    "cloudfront.net": ["distribution is not configured", "bad requested domain name"],
    "fastly.net": ["fastly error: unknown domain"],
    "shopify.com": ["sorry, this shop is currently unavailable"],
    "myshopify.com": ["sorry, this shop is currently unavailable"],
    "tumblr.com": ["there's nothing here"],
    "squarespace.com": ["no such account", "does not exist"],
    "azurewebsites.net": ["microsoft azure app service - site not found"],
    "cloudapp.net": ["404 - not found"],
    "trafficmanager.net": ["404 - not found"],
    "netlify.app": ["not found - request id", "page not found"],
    "netlify.com": ["not found - request id"],
    "vercel.app": ["deployment not found", "404: not_found"],
    "surge.sh": ["project not found"],
    "pantheon.io": ["404 - not found", "unknown domain"],
    "helpjuice.com": ["we could not find what you are looking for"],
    "helpscout.net": ["no settings were found for this company"],
    "uservoice.com": ["this uservoice subdomain no longer exists"],
    "statuspage.io": ["status page doesn't exist", "sorry, we couldn't find that page"],
    "readme.io": ["project doesn't exist", "project not found"],
    "campaignmonitor.com": ["trying to access your account"],
    "zendesk.com": ["this help center no longer exists", "this account has been suspended"],
    "unbouncepages.com": ["the requested url was not found"],
    "cargo.site": ["cargo"],
    "webflow.io": ["this site can't be reached"],
    "ghost.io": ["ghost"],
}

# Suffixes we recognize as takeover-prone services (dangling detection)
KNOWN_SERVICES = sorted(FINGERPRINTS)

_MAX_HOSTS = 20
_TIMEOUT = 5


def _get_cname_chain(host: str, max_hops: int = 5) -> List[str]:
    """Follow CNAME records; returns the chain of targets (may be empty)."""
    if not _HAS_DNS:
        return []
    chain: List[str] = []
    current = host
    for _ in range(max_hops):
        try:
            answers = dns.resolver.resolve(current, "CNAME", lifetime=3)
            target = str(answers[0].target).rstrip(".").lower()
        except Exception:
            break
        if not target or target in chain:
            break
        chain.append(target)
        current = target
    return chain


def _matches_service(cname: str) -> Optional[str]:
    for suffix in KNOWN_SERVICES:
        if cname == suffix or cname.endswith("." + suffix):
            return suffix
    return None


def _fetch_body(url: str) -> str:
    resp = http_get(url, timeout=_TIMEOUT, stream=True)
    if resp is None:
        return ""
    try:
        if resp.status_code >= 500 and url.startswith("https://"):
            resp.close()
            return ""
        buf = b""
        for chunk in resp.iter_content(8192):
            buf += chunk
            if len(buf) >= 32768:
                break
        return buf.decode("utf-8", "ignore").lower()
    except Exception:
        return ""
    finally:
        try:
            resp.close()
        except Exception:
            pass


def _check_one(hostname: str) -> Optional[Dict[str, object]]:
    chain = _get_cname_chain(hostname)
    if not chain:
        return None
    service = None
    for cname in chain:
        service = _matches_service(cname)
        if service:
            break
    if not service:
        return None

    body = _fetch_body(f"https://{hostname}/")
    if not body:
        body = _fetch_body(f"http://{hostname}/")

    fingerprints = FINGERPRINTS.get(service, [])
    evidence = next((f for f in fingerprints if f in body), None)
    return {
        "subdomain": hostname,
        "service": service,
        "cname": chain[-1],
        "chain": chain,
        "vulnerable": evidence is not None and bool(body),
        "confidence": "high" if evidence else "medium",
        "evidence": evidence,
        "http_status": "reachable" if body else "unreachable",
    }


def check_subdomain_takeover(subdomains, status: Dict[str, str]) -> List[Dict[str, object]]:
    """Check each subdomain for dangling CNAME takeover potential.

    Accepts engine ``SubdomainResult`` objects, dicts, or plain hostnames.
    Returns a list of finding dicts (vulnerable + dangling candidates).
    """
    if not _HAS_DNS:
        status["subdomain-takeover"] = "skipped: dnspython missing"
        return []

    hosts: List[str] = []
    for s in subdomains[:_MAX_HOSTS]:
        host = getattr(s, "hostname", None)
        if host is None and isinstance(s, dict):
            host = s.get("hostname")
        if isinstance(s, str):
            host = s
        if host and host not in hosts:
            hosts.append(str(host))
    if not hosts:
        status["subdomain-takeover"] = "no_targets"
        return []

    findings: List[Dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=12) as ex:
        futures = {ex.submit(_check_one, h): h for h in hosts}
        for fut in as_completed(futures):
            try:
                item = fut.result()
                if item:
                    findings.append(item)
            except Exception:
                pass

    findings.sort(key=lambda f: (not f.get("vulnerable"), str(f.get("subdomain"))))
    vulnerable = [f for f in findings if f.get("vulnerable")]
    if vulnerable:
        status["subdomain-takeover"] = f"{len(vulnerable)} vulnerable"
    elif findings:
        status["subdomain-takeover"] = f"{len(findings)} dangling (unconfirmed)"
    else:
        status["subdomain-takeover"] = "no_findings"
    return findings
