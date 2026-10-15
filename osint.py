"""Nexora — Advanced Internet Intelligence Engine.

Aggregates public OSINT for any domain / company from 25+ key-free sources:

* Subdomains & DNS  -> hackertarget, certspotter, crt.sh, alienvault, rapiddns,
                        google dns, cloudflare dns, anubis, threatcrowd, threatminer,
                        subdomaincenter, dns brute-force
* Certificates      -> certspotter API + live TLS cert grab (SAN parse)
* Vulnerabilities   -> NVD CVE API 2.0 + CISA KEV catalog + OSV
* Ports/Services    -> live probe + Shodan InternetDB
* IP Reputation     -> ipinfo, abuseipdb, greynoise, ip-api.com, ipdetails.io
* Threat Intel      -> URLhaus, ThreatFox, Feodo Tracker, StopForumSpam
* BGP/ASN           -> BGPView
* Historical        -> Wayback Machine + Common Crawl

No API keys required. Every source degrades gracefully; a partial result is
always returned. Designed to be called from a request path via a threadpool.
"""
from __future__ import annotations

import os
import sys
import json
import socket
import ssl
import re
import logging
import time
import argparse
import warnings
import concurrent.futures as cf
from dataclasses import dataclass, field
from typing import List, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

log = logging.getLogger("osint")

# ── Global session with connection pooling + auto-retry ──────────── #
_session = requests.Session()
_adapter = HTTPAdapter(
    max_retries=Retry(total=1, backoff_factor=0.2, status_forcelist=[502, 503, 504]),
    pool_connections=20,
    pool_maxsize=20,
)
_session.mount("https://", _adapter)
_session.mount("http://", _adapter)

# Circuit-breaker: hosts that fail are skipped for _DEAD_HOST_TTL seconds.
_DEAD_HOSTS: Dict[str, float] = {}  # host -> expiry timestamp
_DEAD_HOST_TTL = 300  # 5 minutes


def _is_dead_host(host: str) -> bool:
    """Check if a host is in the circuit-breaker blacklist."""
    if not host:
        return False
    expiry = _DEAD_HOSTS.get(host)
    if expiry is None:
        return False
    if time.time() < expiry:
        return True
    _DEAD_HOSTS.pop(host, None)
    return False


def _mark_dead_host(host: str):
    """Add a host to the circuit-breaker blacklist."""
    if host:
        _DEAD_HOSTS[host] = time.time() + _DEAD_HOST_TTL

try:
    from cryptography import x509
except Exception:  # pragma: no cover - cryptography is a hard dep of FastAPI stack
    x509 = None

# --------------------------------------------------------------------------- #
# Sibling module loader: lets this file use the standalone copies of
# app.engine.* (takeover.py, osint_advanced.py) that live next to it.
# --------------------------------------------------------------------------- #
def _load_sibling(filename: str, *attrs: str):
    """Load attributes from a sibling .py file next to this module.

    Used to pick up the standalone versions of ``app.engine.takeover`` and
    ``app.engine.osint_advanced`` when running outside the FastAPI app.
    """
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    if not os.path.isfile(path):
        raise ImportError(f"sibling module not found: {filename}")
    mod_name = "_osint_sibling_" + os.path.splitext(os.path.basename(filename))[0]
    mod = sys.modules.get(mod_name)
    if mod is None:
        spec = importlib.util.spec_from_file_location(mod_name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load sibling module: {filename}")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)
    return tuple(getattr(mod, a) for a in attrs)


try:
    from app.engine.takeover import check_subdomain_takeover
except ImportError:
    # Standalone/CLI mode: use the local async copy first (needs aiohttp),
    # then the nexora sync fallback, then a no-op stub.
    try:
        (check_subdomain_takeover,) = _load_sibling(
            "takeover.py", "check_subdomain_takeover"
        )
    except Exception:
        try:
            from nexora.takeover import check_subdomain_takeover
        except ImportError:
            def check_subdomain_takeover(subdomains, status: Dict[str, str]):
                status["subdomain-takeover"] = "skipped: module unavailable"
                return []

_USER_AGENT = {
    "User-Agent": "Mozilla/5.0 (compatible; Nexora/2.0; +https://nexora.io)",
}
_TIMEOUT = 8

# Common ports probed for the Shodan-style "ports/services/tech" view.
_PROBE_PORTS = [
    21, 22, 25, 53, 80, 110, 143, 443, 587, 993, 995,
    3306, 3389, 5432, 5601, 6379, 8080, 8443, 8880, 9090, 9200, 27017,
]

# Maximum subdomains to resolve DNS for (keeps lookup fast).
_MAX_DNS_RESOLUTIONS = 20

# Maximum hosts to probe for open ports.
_MAX_PORT_PROBE_HOSTS = 3

# Hard overall timeout for the entire lookup (seconds).
# Now configurable via settings.OVERALL_TIMEOUT; this is the fallback.
_OVERALL_TIMEOUT = 120

# Source categories that can be disabled per-request via skip_categories.
SKIP_PORTS = "ports"
SKIP_THREAT_INTEL = "threat_intel"
SKIP_WEB_FINGERPRINT = "web_fingerprint"
SKIP_SENSITIVE_PATHS = "sensitive_paths"
ALL_SKIPPABLE = {SKIP_PORTS, SKIP_THREAT_INTEL, SKIP_WEB_FINGERPRINT, SKIP_SENSITIVE_PATHS}

_CVE_PRODUCT_KEYWORDS = [
    "nginx", "apache", "iis", "openssl", "wordpress", "drupal", "joomla",
    "php", "tomcat", "jetty", "nodejs", "express", "django", "flask",
    "spring", "rails", "mysql", "postgresql", "mongodb", "redis", "elasticsearch",
    "nginx", "cloudflare", "aws", "azure", "google cloud",
]

# In-memory cache for CISA KEV catalog (avoid re-downloading 30MB each lookup).
_KEV_CACHE: Optional[set] = None
_KEV_CACHE_TS: float = 0


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #
@dataclass
class SubdomainResult:
    hostname: str
    ips: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)


@dataclass
class CertResult:
    issuer: Optional[str] = None
    subject: Optional[str] = None
    san: List[str] = field(default_factory=list)
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    serial: Optional[str] = None
    source: Optional[str] = None


@dataclass
class PortResult:
    port: int
    state: str  # open | closed | filtered
    service: Optional[str] = None
    banner: Optional[str] = None
    tls: bool = False
    title: Optional[str] = None


@dataclass
class VulnResult:
    cve_id: str
    description: str
    severity: Optional[str] = None
    cvss: Optional[float] = None
    published: Optional[str] = None
    is_kev: bool = False
    source: str = "NVD"


@dataclass
class IntelResult:
    query: str
    subdomains: List[SubdomainResult] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    certificates: List[CertResult] = field(default_factory=list)
    ports: List[PortResult] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    vulnerabilities: List[VulnResult] = field(default_factory=list)
    ip_reputation: List[Dict[str, object]] = field(default_factory=list)
    whois: Optional[Dict[str, object]] = None
    historical_subdomains: List[str] = field(default_factory=list)
    reverse_ip: List[str] = field(default_factory=list)
    sources_status: Dict[str, str] = field(default_factory=dict)
    # Advanced intelligence
    email_security: Optional[object] = None
    waf_cdn: Optional[object] = None
    security_headers: Optional[object] = None
    sensitive_paths: List[object] = field(default_factory=list)
    web_fingerprint: Optional[object] = None
    reverse_dns_range: List[str] = field(default_factory=list)
    risk_score: Optional[object] = None
    # Nexora v2 additions
    threat_intel: Optional[Dict[str, object]] = None
    bgp_info: Optional[Dict[str, object]] = None
    osv_vulns: List[Dict[str, object]] = field(default_factory=list)
    dmarc_mx_result: Optional[Dict[str, object]] = None
    common_crawl_subdomains: List[str] = field(default_factory=list)
    # Company enrichment
    company_name: Optional[str] = None
    logo_url: Optional[str] = None
    # New intelligence fields
    dns_zone_transfer: Optional[Dict[str, object]] = None
    wildcard_dns: Optional[Dict[str, object]] = None
    dnssec: Optional[Dict[str, object]] = None
    subdomain_takeover: List[Dict[str, object]] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _http_get(url: str, params: Optional[dict] = None, timeout: int = _TIMEOUT):
    """HTTP GET using pooled session. Returns response or None on failure."""
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname
        if _is_dead_host(host):
            return None
        resp = _session.get(
            url, params=params, headers=_USER_AGENT, timeout=timeout,
            allow_redirects=True,
        )
        # Retry once on rate-limit or transient server errors
        if resp.status_code in (429, 503):
            time.sleep(1)
            resp = _session.get(
                url, params=params, headers=_USER_AGENT, timeout=timeout,
                allow_redirects=True,
            )
        return resp
    except Exception:
        if host:
            _mark_dead_host(host)
        return None


def _dns_resolve(host: str, timeout: float = 3.0) -> list:
    """Resolve hostname to A records using dnspython."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(host, "A", lifetime=timeout)
        return [("", 0, 0, "", (r.to_text(), 0)) for r in answers]
    except Exception:
        return []


def _normalize_domain(raw: str) -> str:
    raw = (raw or "").strip().lower()
    raw = re.sub(r"^https?://", "", raw)
    raw = raw.split("/")[0]
    if raw.startswith("www."):
        raw = raw[4:]
    # If no TLD (bare company name like "stripe"), try common TLDs
    if "." not in raw:
        _TLDS = [
            "com", "org", "net", "io", "co", "dev", "app", "tech", "ai",
            "pro", "me", "us", "uk", "ca", "de", "fr", "jp", "au", "in",
            "xyz", "info", "biz", "cloud", "site", "online", "store",
            "digital", "live", "systems", "solutions", "services",
            "security", "network", "computer", "software", "group",
            "company", "enterprises", "consulting", "global", "world",
            "one", "hub", "lab", "space", "works", "tools", "expert",
            "team", "agency", "studio", "media", "design", "creative",
            "finance", "bank", "pay", "money", "capital", "ventures",
            "edu", "gov", "mil", "int", "jobs", "mobi", "name", "museum",
            "aero", "coop", "travel", "asia", "cat", "tel", "post",
            "cc", "ws", "tv", "fm", "am", "fm", "to", "ly", "sh",
        ]
        for tld in _TLDS:
            candidate = f"{raw}.{tld}"
            try:
                if _dns_resolve(candidate, timeout=1.5):
                    raw = candidate
                    break
            except Exception:
                continue
    return raw


def _resolve_dns(domain: str) -> Dict[str, List[str]]:
    records: Dict[str, List[str]] = {}
    types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    try:
        import dns.resolver  # type: ignore

        for t in types:
            try:
                ans = dns.resolver.resolve(domain, t, lifetime=3)
                records[t] = [r.to_text().rstrip(".") for r in ans]
            except Exception:
                continue
    except Exception:
        # Fallback to socket for A records.
        try:
            infos = socket.getaddrinfo(domain, None)
            records["A"] = sorted({i[4][0] for i in infos})
        except Exception:
            pass
    return records


def _grab_cert_sans(domain: str, port: int = 443) -> Optional[Dict[str, object]]:
    if not x509:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((domain, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                der = ss.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der)
                san = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.DNSName)
                issuer = cert.issuer.rfc4514_string()
                subject = cert.subject.rfc4514_string()
                not_before = cert.not_valid_before_utc.isoformat()
                not_after = cert.not_valid_after_utc.isoformat()
                serial = format(cert.serial_number, "X")
                return {
                    "issuer": issuer,
                    "subject": subject,
                    "san": list(san),
                    "not_before": not_before,
                    "not_after": not_after,
                    "serial": serial,
                }
    except Exception:
        return None
    return None


def _probe_port(host: str, port: int) -> PortResult:
    svc = {80: "HTTP", 443: "HTTPS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
           22: "SSH", 21: "FTP", 25: "SMTP", 53: "DNS", 3306: "MySQL",
           5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 3389: "RDP"}.get(port)
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            banner = None
            title = None
            is_tls = port in (443, 8443)
            if is_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    try:
                        ss.sendall(
                            b"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                            % host.encode()
                        )
                        data = ss.recv(2048)
                        banner = data.decode("utf-8", "ignore")[:400]
                    except Exception:
                        pass
            elif port in (80, 8080):
                try:
                    sock.sendall(
                        b"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                        % host.encode()
                    )
                    data = sock.recv(2048)
                    banner = data.decode("utf-8", "ignore")[:400]
                except Exception:
                    pass
            else:
                try:
                    sock.settimeout(3)
                    sock.sendall(b"\r\n")
                    data = sock.recv(256)
                    banner = data.decode("utf-8", "ignore")[:200]
                except Exception:
                    pass
            if banner:
                m = re.search(r"<title[^>]*>(.*?)</title>", banner, re.I | re.S)
                if m:
                    title = m.group(1).strip()[:120]
            return PortResult(port=port, state="open", service=svc, banner=banner, tls=is_tls, title=title)
    except (ConnectionRefusedError, socket.timeout, OSError):
        return PortResult(port=port, state="closed", service=svc)
    except Exception:
        return PortResult(port=port, state="filtered", service=svc)


# --------------------------------------------------------------------------- #
# Source collectors (each returns data + updates sources_status)
# --------------------------------------------------------------------------- #
def _collect_subdomains(domain: str, status: Dict[str, str]) -> List[SubdomainResult]:
    found: Dict[str, SubdomainResult] = {}

    def _merge(source: str, hostnames: Dict[str, List[str]]):
        for host, ips in hostnames.items():
            if host not in found:
                found[host] = SubdomainResult(hostname=host, sources=[source], ips=ips)
            else:
                if source not in found[host].sources:
                    found[host].sources.append(source)
                for ip in ips:
                    if ip and ip not in found[host].ips:
                        found[host].ips.append(ip)

    # Run all HTTP sources concurrently
    def _src_hackertarget() -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        try:
            r = _http_get("https://api.hackertarget.com/hostsearch/", params={"q": domain})
            if r is None:
                status["hackertarget"] = "error: ConnectionError"
                return result
            if r.status_code == 200 and r.text:
                body = r.text.strip()
                if body.lower().startswith("api count exceeded") or body.lower().startswith("error"):
                    status["hackertarget"] = "rate_limited"
                else:
                    for line in body.splitlines():
                        if "," in line:
                            host, ip = line.split(",", 1)
                            host, ip = host.strip().lower(), ip.strip()
                            if host.endswith(domain) or domain in host:
                                result.setdefault(host, []).append(ip)
                    status["hackertarget"] = "ok" if result else "no_results"
            else:
                status["hackertarget"] = f"http_{r.status_code}"
        except Exception as e:
            status["hackertarget"] = f"error: {type(e).__name__}"
        return result

    def _src_certspotter() -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        try:
            r = _http_get("https://api.certspotter.com/v1/issuances",
                          params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"})
            if r is None:
                status["certspotter"] = "error: ConnectionError"
                return result
            if r.status_code == 200:
                for entry in r.json():
                    for name in entry.get("dns_names", []):
                        name = name.lstrip("*.").lower()
                        if name.endswith(domain) or domain in name:
                            result.setdefault(name, [])
                status["certspotter"] = "ok" if result else "no_results"
            else:
                status["certspotter"] = f"http_{r.status_code}"
        except Exception as e:
            status["certspotter"] = f"error: {type(e).__name__}"
        return result

    def _src_crtsh() -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        try:
            r = _http_get("https://crt.sh/", params={"q": f".{domain}", "output": "json"}, timeout=10)
            if r is None:
                status["crtsh"] = "error: ConnectionError"
                return result
            if r.status_code == 200:
                for entry in r.json():
                    for part in entry.get("name_value", "").split("\n"):
                        part = part.strip().lstrip("*.").lower()
                        if part.endswith(domain) or domain in part:
                            result.setdefault(part, [])
                status["crtsh"] = "ok" if result else "no_results"
            else:
                status["crtsh"] = f"http_{r.status_code}"
        except Exception as e:
            status["crtsh"] = f"error: {type(e).__name__}"
        return result

    def _src_alienvault() -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        try:
            r = _http_get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=8)
            if r is None:
                status["alienvault"] = "error: ConnectionError"
                return result
            if r.status_code == 200:
                for entry in r.json().get("passive_dns", []):
                    hostname = entry.get("hostname", "").strip().lower()
                    ip = entry.get("ip", "")
                    if hostname.endswith(domain) or domain in hostname:
                        result.setdefault(hostname, []).append(ip)
                status["alienvault"] = "ok" if result else "no_results"
            else:
                status["alienvault"] = f"http_{r.status_code}"
        except Exception as e:
            status["alienvault"] = f"error: {type(e).__name__}"
        return result

    def _src_rapiddns() -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        try:
            r = _http_get(f"https://rapiddns.io/subdomain/{domain}", params={"full": "1"}, timeout=8)
            if r is None:
                status["rapiddns"] = "error: ConnectionError"
                return result
            if r.status_code == 200:
                for m in re.finditer(r"<td>([\w.-]+\." + re.escape(domain) + r")</td>", r.text):
                    sub = m.group(1).strip().lower()
                    result.setdefault(sub, [])
                status["rapiddns"] = "ok" if result else "no_results"
            else:
                status["rapiddns"] = f"http_{r.status_code}"
        except Exception as e:
            status["rapiddns"] = f"error: {type(e).__name__}"
        return result

    def _src_google_dns() -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        for dns_type in ("A", "AAAA", "MX", "NS", "CNAME", "TXT"):
            try:
                r = _http_get("https://dns.google/resolve",
                              params={"name": domain, "type": dns_type}, timeout=8)
                if r is None:
                    continue
                if r.status_code == 200:
                    for ans in r.json().get("Answer", []):
                        data = ans.get("data", "").rstrip(".")
                        if dns_type == "MX" and " " in data:
                            data = data.split()[-1].rstrip(".")
                        if data and (data.endswith(domain) or domain in data):
                            result.setdefault(data, [])
            except Exception:
                pass
        status["google-dns"] = "ok" if result else "no_results"
        return result

    def _src_cloudflare_dns() -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        for dns_type in ("A", "AAAA", "MX", "NS", "CNAME", "TXT"):
            try:
                r = _http_get("https://cloudflare-dns.com/dns-query",
                              params={"name": domain, "type": dns_type},
                              headers={**_USER_AGENT, "accept": "application/dns-json"},
                              timeout=8)
                if r is None:
                    continue
                if r.status_code == 200:
                    for ans in r.json().get("Answer", []):
                        data = ans.get("data", "").rstrip(".")
                        if dns_type == "MX" and " " in data:
                            data = data.split()[-1].rstrip(".")
                        if data and (data.endswith(domain) or domain in data):
                            result.setdefault(data, [])
            except Exception:
                pass
        status["cloudflare-dns"] = "ok" if result else "no_results"
        return result

    def _src_anubis() -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        try:
            r = _http_get(f"https://jldc.me/anubis/{domain}", timeout=10)
            if r is None:
                status["anubis"] = "error: ConnectionError"
                return result
            if r.status_code == 200:
                for entry in r.json() if isinstance(r.json(), list) else []:
                    host = str(entry).strip().lower()
                    if host.endswith(domain) or domain in host:
                        result.setdefault(host, [])
                status["anubis"] = "ok" if result else "no_results"
            else:
                status["anubis"] = f"http_{r.status_code}"
        except Exception as e:
            status["anubis"] = f"error: {type(e).__name__}"
        return result

    def _src_threatcrowd() -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        try:
            r = _http_get("https://www.threatcrowd.org/searchApi/v2/domain/report/",
                          params={"domain": domain}, timeout=10)
            if r is None:
                status["threatcrowd"] = "error: ConnectionError"
                return result
            if r.status_code == 200:
                data = r.json()
                for host in data.get("subdomains", []):
                    host = host.strip().lower()
                    if host.endswith(domain) or domain in host:
                        result.setdefault(host, [])
                status["threatcrowd"] = "ok" if result else "no_results"
            else:
                status["threatcrowd"] = f"http_{r.status_code}"
        except Exception as e:
            status["threatcrowd"] = f"error: {type(e).__name__}"
        return result

    def _src_threatminer() -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        try:
            r = _http_get("https://api.threatminer.org/v2/domain/q.php",
                          params={"q": domain, "rt": "1"}, timeout=10)
            if r is None:
                status["threatminer"] = "error: ConnectionError"
                return result
            if r.status_code == 200:
                data = r.json()
                for host in data.get("results", []):
                    host = host.strip().lower()
                    if host.endswith(domain) or domain in host:
                        result.setdefault(host, [])
                status["threatminer"] = "ok" if result else "no_results"
            else:
                status["threatminer"] = f"http_{r.status_code}"
        except Exception as e:
            status["threatminer"] = f"error: {type(e).__name__}"
        return result

    def _src_subdomaincenter() -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        try:
            r = _http_get(f"https://api.subdomain.center/subdomain/{domain}", timeout=10)
            if r is None:
                status["subdomaincenter"] = "error: ConnectionError"
                return result
            if r.status_code == 200:
                data = r.json()
                for host in data.get("subdomains", []) if isinstance(data, dict) else data if isinstance(data, list) else []:
                    host = str(host).strip().lower()
                    if host.endswith(domain) or domain in host:
                        result.setdefault(host, [])
                status["subdomaincenter"] = "ok" if result else "no_results"
            else:
                status["subdomaincenter"] = f"http_{r.status_code}"
        except Exception as e:
            status["subdomaincenter"] = f"error: {type(e).__name__}"
        return result

    # Fire all HTTP sources concurrently (9 sources)
    with cf.ThreadPoolExecutor(max_workers=9) as ex:
        futures = {
            ex.submit(_src_hackertarget): "hackertarget",
            ex.submit(_src_certspotter): "certspotter",
            ex.submit(_src_alienvault): "alienvault",
            ex.submit(_src_rapiddns): "rapiddns",
            ex.submit(_src_google_dns): "google-dns",
            ex.submit(_src_cloudflare_dns): "cloudflare-dns",
            ex.submit(_src_anubis): "anubis",
            ex.submit(_src_threatcrowd): "threatcrowd",
            ex.submit(_src_threatminer): "threatminer",
        }
        for f in cf.as_completed(futures):
            try:
                data = f.result(timeout=12)
                _merge(futures[f], data)
            except Exception:
                pass

        # SubdomainCenter (run concurrently)
        try:
            data = _src_subdomaincenter()
            _merge("subdomaincenter", data)
        except Exception:
            pass

        # crt.sh only if certspotter failed or returned few results
        certspotter_count = len(found)
        certspotter_ok = status.get("certspotter", "").startswith("ok") and certspotter_count >= 5
        if not certspotter_ok:
            try:
                data = _src_crtsh()
                _merge("crtsh", data)
            except Exception:
                pass

    # DNS brute-force (top 25, concurrent — fast timeout)
    _DNS_PREFIXES = [
        "www", "mail", "ftp", "smtp", "webmail", "mx", "mx1", "mx2",
        "ns1", "ns2", "dns", "dns1", "dns2",
        "vpn", "remote", "gateway", "ssh",
        "api", "app", "web", "portal", "login", "sso",
        "admin",
        "dev", "blog", "docs",
        "cdn", "static",
        "git", "jenkins",
        "status",
    ]
    _brute_candidates = [f"{prefix}.{domain}" for prefix in _DNS_PREFIXES if f"{prefix}.{domain}" not in found]

    def _try_brute(candidate: str) -> Optional[SubdomainResult]:
        try:
            if _dns_resolve(candidate, timeout=3):
                return SubdomainResult(hostname=candidate, sources=["dns-bruteforce"])
        except Exception:
            pass
        return None

    new_from_brute = 0
    with cf.ThreadPoolExecutor(max_workers=15) as ex:
        for result in ex.map(_try_brute, _brute_candidates):
            if result:
                found[result.hostname] = result
                new_from_brute += 1
    status["dns-bruteforce"] = f"{new_from_brute} found" if new_from_brute else "no_results"

    # Ensure the apex domain is present.
    if domain not in found:
        found[domain] = SubdomainResult(hostname=domain, sources=["apex"])

    # Resolve DNS for discovered hostnames (concurrent, capped).
    to_resolve = [s for s in found.values() if not s.ips][:_MAX_DNS_RESOLUTIONS]

    def _resolve_one(sub: SubdomainResult) -> SubdomainResult:
        try:
            infos = _dns_resolve(sub.hostname, timeout=3)
            sub.ips = sorted({i[4][0] for i in infos})
        except Exception:
            pass
        return sub

    with cf.ThreadPoolExecutor(max_workers=15) as ex:
        list(ex.map(_resolve_one, to_resolve))

    # Reverse DNS on discovered IPs (finds additional hostnames)
    all_ips = set()
    for s in found.values():
        for ip in s.ips:
            if ip:
                all_ips.add(ip)
    for ip in list(all_ips)[:_MAX_DNS_RESOLUTIONS]:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            hostname = hostname.strip().lower()
            if (hostname.endswith(domain) or domain in hostname) and hostname not in found:
                found[hostname] = SubdomainResult(hostname=hostname, ips=[ip], sources=["reverse-dns"])
        except Exception:
            pass

    return list(found.values())


def _collect_certificates(domain: str, status: Dict[str, str]) -> List[CertResult]:
    certs: List[CertResult] = []
    # Live TLS grab on apex + www
    for host in (domain, f"www.{domain}"):
        info = _grab_cert_sans(host)
        if info:
            certs.append(CertResult(source="live-tls", **info))  # type: ignore[arg-type]
    if certs:
        status["live-tls"] = "ok"
    else:
        status["live-tls"] = "no-cert"
    return certs


def _collect_ports(subdomains: List[SubdomainResult], status: Dict[str, str]) -> List[PortResult]:
    # Build probe targets: top subdomains + their resolved IPs, capped.
    hosts = [s.hostname for s in subdomains[:_MAX_PORT_PROBE_HOSTS]]
    ips: List[str] = []
    for s in subdomains[:_MAX_PORT_PROBE_HOSTS]:
        for ip in s.ips:
            if ip not in ips:
                ips.append(ip)
    probe_targets = list(dict.fromkeys(hosts + ips))[:_MAX_PORT_PROBE_HOSTS + 2]
    if not probe_targets:
        status["port-scan"] = "no_targets"
        return []
    results: List[PortResult] = []
    seen_ports = set()
    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        futs = []
        for host in probe_targets:
            for port in _PROBE_PORTS:
                futs.append(ex.submit(_probe_port, host, port))
        for f in cf.as_completed(futs):
            res = f.result()
            if res.state == "open" and res.port not in seen_ports:
                results.append(res)
                seen_ports.add(res.port)
    status["port-scan"] = f"{len(results)} open"

    # 9) Shodan InternetDB — enrich each IP with known open ports + CPEs (concurrent)
    shodan_techs = []
    def _shodan_lookup(ip: str) -> dict:
        try:
            r = _http_get(f"https://internetdb.shodan.io/{ip}", timeout=8)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return {}

    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        for data in ex.map(_shodan_lookup, ips[:10]):
            for port in data.get("ports", []):
                if port not in seen_ports:
                    svc = {80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
                           25: "SMTP", 53: "DNS", 3306: "MySQL", 5432: "PostgreSQL",
                           6379: "Redis", 27017: "MongoDB", 8080: "HTTP-ALT",
                           8443: "HTTPS-ALT", 3389: "RDP"}.get(port)
                    results.append(PortResult(port=port, state="open", service=svc, banner=None, tls=port in (443, 8443)))
                    seen_ports.add(port)
            for cpes in data.get("cpes", []):
                if isinstance(cpes, str) and cpes:
                    shodan_techs.append(cpes)
    if shodan_techs:
        status["shodan-internetdb"] = f"{len(shodan_techs)} cpes"
    else:
        status["shodan-internetdb"] = "ok" if ips else "no_targets"
    return results, shodan_techs


def _collect_vulns(technologies: List[str], status: Dict[str, str]) -> List[VulnResult]:
    global _KEV_CACHE, _KEV_CACHE_TS
    vulns: List[VulnResult] = []
    seen = set()

    # CISA KEV catalog — use in-memory cache (refresh every 6 hours).
    import time as _time
    kev_ids = _KEV_CACHE if _KEV_CACHE and (_time.time() - _KEV_CACHE_TS) < 21600 else None
    if kev_ids is None:
        kev_ids = set()
        try:
            r = _http_get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=8)
            if r.status_code == 200:
                for v in r.json().get("vulnerabilities", []):
                    kev_ids.add(v.get("cveID"))
                status["cisa-kev"] = "ok"
            else:
                status["cisa-kev"] = f"http_{r.status_code}"
        except Exception as e:
            status["cisa-kev"] = f"error: {type(e).__name__}"
        _KEV_CACHE = kev_ids
        _KEV_CACHE_TS = _time.time()

    # NVD keyword search — concurrent for detected technologies.
    if not technologies:
        status["nvd"] = "skipped_no_tech"
        return vulns

    # Filter out generic terms that produce irrelevant CVEs
    _GENERIC_TERMS = {"let's encrypt", "cloudflare", "fastly", "akamai", "amazon", "google", "microsoft"}
    keywords = [t for t in dict.fromkeys(technologies) if t.lower() not in _GENERIC_TERMS][:5]

    if not keywords:
        status["nvd"] = "skipped_generic_tech_only"
        return vulns

    def _nvd_search(kw: str) -> List[VulnResult]:
        local_vulns = []
        try:
            r = _http_get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": kw, "resultsPerPage": 20},
                timeout=10,
            )
            if r is None or r.status_code != 200:
                return local_vulns
            for v in r.json().get("vulnerabilities", []):
                cve = v["cve"]
                cid = cve["id"]
                descr = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        descr = d.get("value", "")
                        break
                # Relevance filter: keyword should appear in description
                if kw.lower() not in descr.lower():
                    continue
                metrics = cve.get("metrics", {})
                cvss = None
                sev = None
                if "cvssMetricV31" in metrics:
                    m = metrics["cvssMetricV31"][0]["cvssData"]
                    cvss = m.get("baseScore")
                    sev = m.get("baseSeverity")
                elif "cvssMetricV30" in metrics:
                    m = metrics["cvssMetricV30"][0]["cvssData"]
                    cvss = m.get("baseScore")
                    sev = m.get("baseSeverity")
                local_vulns.append(VulnResult(
                    cve_id=cid,
                    description=descr[:300],
                    severity=sev,
                    cvss=cvss,
                    published=cve.get("published"),
                    is_kev=cid in kev_ids,
                    source="NVD",
                ))
        except Exception:
            pass
        return local_vulns

    try:
        with cf.ThreadPoolExecutor(max_workers=3) as ex:
            for nvd_vulns in ex.map(_nvd_search, keywords):
                for v in nvd_vulns:
                    if v.cve_id not in seen:
                        seen.add(v.cve_id)
                        vulns.append(v)
        status["nvd"] = f"{len(vulns)} cves" if vulns else "no_results"
    except Exception as e:
        status["nvd"] = f"error: {type(e).__name__}"

    # OSV (Open Source Vulnerabilities) — supplementary for open-source packages
    if technologies:
        osv_keywords = [t for t in dict.fromkeys(technologies) if len(t) > 2][:8]
        try:
            payload = {"queries": [{"package": {"name": kw}, "version": "latest"} for kw in osv_keywords]}
            r = _session.post("https://api.osv.dev/v1/querybatch", json=payload, timeout=12)
            if r.status_code == 200:
                import re as _re
                osv_count = 0
                for resp in r.json().get("results", []):
                    for v in resp.get("vulns", []):
                        vid = v.get("id", "")
                        # Extract CVE ID from OSV ID (e.g., "ALPINE-CVE-2018-16843" -> "CVE-2018-16843")
                        cve_match = _re.search(r"(CVE-\d{4}-\d+)", vid)
                        cid = cve_match.group(1) if cve_match else (vid if vid.startswith("CVE-") else "")
                        if cid and cid not in seen:
                            seen.add(cid)
                            vulns.append(VulnResult(
                                cve_id=cid,
                                description=v.get("summary", "")[:300],
                                severity=None,
                                cvss=None,
                                published=v.get("published"),
                                is_kev=cid in kev_ids,
                                source="OSV",
                            ))
                            osv_count += 1
                status["osv"] = f"{osv_count} vulns" if osv_count else "no_results"
            else:
                status["osv"] = f"http_{r.status_code}"
        except Exception as e:
            status["osv"] = f"error: {type(e).__name__}"

    return vulns


def _infer_technologies(certs: List[CertResult], ports: List[PortResult], subdomains: List[SubdomainResult], domain: str = "") -> List[str]:
    tech = set()
    for c in certs:
        if c.issuer:
            if "Let's Encrypt" in c.issuer:
                tech.add("Let's Encrypt")
            if "Cloudflare" in (c.issuer or ""):
                tech.add("Cloudflare")
    for p in ports:
        if p.service in ("HTTPS", "HTTP", "HTTP-ALT", "HTTPS-ALT"):
            if p.banner:
                for tok in ("nginx", "apache", "cloudflare", "iis", "openresty", "litespeed", "caddy", "gunicorn", "uvicorn", "node", "express", "tomcat"):
                    if tok in p.banner.lower():
                        tech.add(tok)
                if "Server:" in p.banner:
                    m = re.search(r"Server:\s*([^\r\n]+)", p.banner)
                    if m:
                        tech.add(m.group(1).split("/")[0].strip())
                # Detect x-powered-by from banner
                if "X-Powered-By:" in p.banner:
                    m = re.search(r"X-Powered-By:\s*([^\r\n]+)", p.banner)
                    if m:
                        tech.add(m.group(1).split("/")[0].strip())
    # HTTP header probe for server tech (fast HEAD request)
    if domain:
        for scheme in ("https", "http"):
            try:
                r = _http_get(f"{scheme}://{domain}", timeout=5)
                if r is not None:
                    server = r.headers.get("Server", "")
                    if server:
                        tech.add(server.split("/")[0].strip().lower())
                    powered = r.headers.get("X-Powered-By", "")
                    if powered:
                        tech.add(powered.split("/")[0].strip().lower())
                    # Detect CDN/WAF headers
                    if r.headers.get("CF-Ray") or r.headers.get("cf-ray"):
                        tech.add("cloudflare")
                    if r.headers.get("X-Fastly-Request-ID"):
                        tech.add("fastly")
                    if r.headers.get("X-CDN"):
                        tech.add("akamai")
                    break  # got a response, no need to try http
            except Exception:
                pass
    return sorted({t.lower() for t in tech})


# --------------------------------------------------------------------------- #
# IP Reputation, WHOIS, Wayback, Reverse IP collectors
# --------------------------------------------------------------------------- #
def _collect_ip_reputation(ips: List[str], status: Dict[str, str]) -> List[Dict[str, object]]:
    """Query free IP reputation sources for each resolved IP (concurrent)."""
    results = []

    def _check_one_ip(ip: str) -> Dict[str, object]:
        rep: Dict[str, object] = {"ip": ip, "abuse_confidence": 0, "is_tor": False, "country": None, "org": None}

        # IPinfo (free, no key)
        try:
            r = _http_get(f"https://ipinfo.io/{ip}/json", timeout=8)
            if r and r.status_code == 200:
                data = r.json()
                rep["country"] = data.get("country")
                rep["org"] = data.get("org")
                rep["city"] = data.get("city")
                rep["loc"] = data.get("loc")
                rep["hostname"] = data.get("hostname")
                status["ipinfo"] = "ok"
        except Exception:
            pass

        # AbuseIPDB free check
        try:
            r = _http_get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip}, timeout=8)
            if r and r.status_code == 200:
                d = r.json().get("data", {})
                rep["abuse_confidence"] = d.get("abuseConfidenceScore", 0)
                rep["total_reports"] = d.get("totalReports", 0)
                rep["country_code"] = d.get("countryCode")
                rep["usage_type"] = d.get("usageType")
                rep["is_whitelisted"] = d.get("isWhitelisted", False)
                status["abuseipdb"] = "ok"
        except Exception:
            pass

        # GreyNoise Community
        try:
            r = _http_get(f"https://api.greynoise.io/v3/community/{ip}", timeout=8)
            if r and r.status_code == 200:
                d = r.json()
                rep["noise"] = d.get("noise", False)
                rep["riot"] = d.get("riot", False)
                rep["classification"] = d.get("classification")
                rep["name"] = d.get("name")
                status["greynoise"] = "ok"
        except Exception:
            pass

        # ip-api.com
        try:
            r = _http_get(f"http://ip-api.com/json/{ip}",
                          params={"fields": "status,message,country,countryCode,region,regionName,city,isp,org,as,asname,reverse,mobile,proxy,hosting"},
                          timeout=6)
            if r and r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    rep["country"] = rep.get("country") or d.get("country")
                    rep["region"] = d.get("regionName")
                    rep["city"] = rep.get("city") or d.get("city")
                    rep["isp"] = d.get("isp")
                    rep["org"] = rep.get("org") or d.get("org")
                    rep["asn"] = d.get("as")
                    rep["asname"] = d.get("asname")
                    rep["reverse_dns"] = d.get("reverse")
                    rep["is_mobile"] = d.get("mobile", False)
                    rep["is_proxy"] = d.get("proxy", False)
                    rep["is_hosting"] = d.get("hosting", False)
                    status["ip-api"] = "ok"
        except Exception:
            pass

        # IPDetails.io
        try:
            r = _http_get(f"https://ipdetails.io/api/ip/{ip}", timeout=6)
            if r and r.status_code == 200:
                d = r.json()
                rep["country"] = rep.get("country") or d.get("country", {}).get("name")
                rep["org"] = rep.get("org") or d.get("organization", {}).get("name")
                rep["asn"] = rep.get("asn") or d.get("asn")
                rep["is_tor"] = d.get("is_tor", False)
                rep["is_vpn"] = d.get("is_vpn", False)
                rep["is_datacenter"] = d.get("is_datacenter", False)
                status["ipdetails"] = "ok"
        except Exception:
            pass

        return rep

    # Run all IP checks concurrently
    with cf.ThreadPoolExecutor(max_workers=min(len(ips[:4]), 4)) as ex:
        for rep in ex.map(_check_one_ip, ips[:4]):
            results.append(rep)
    return results


def _collect_whois(domain: str, status: Dict[str, str]) -> Optional[Dict[str, object]]:
    """Collect WHOIS data via RDAP (free, no key)."""
    try:
        # Use RDAP (free protocol for domain registration data)
        r = _http_get(f"https://rdap.org/domain/{domain}", timeout=8)
        if r.status_code == 200:
            data = r.json()
            events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
            nameservers = [n.get("ldhName", "").lower() for n in data.get("nameservers", [])]
            status_entries = data.get("status", [])
            entities = data.get("entities", [])
            registrar = None
            for ent in entities:
                if "registrar" in [v.lower() for v in ent.get("roles", [])]:
                    registrar = ent.get("handle") or ent.get("vcardArray", [None, []])[1][0][3] if len(ent.get("vcardArray", [])) > 1 else None
                    break
            result = {
                "name": data.get("ldhName", domain),
                "status": status_entries,
                "nameservers": nameservers,
                "registration_date": events.get("registration"),
                "expiration_date": events.get("expiration"),
                "last_changed": events.get("last changed"),
                "registrar": registrar,
                "handle": data.get("handle"),
            }
            status["whois-rdap"] = "ok"
            return result
    except Exception as e:
        status["whois-rdap"] = f"error: {type(e).__name__}"
    return None


def _collect_wayback(domain: str, status: Dict[str, str]) -> List[str]:
    """Get historical subdomains from Wayback Machine CDX API."""
    historical = []
    try:
        r = _http_get(
            "https://web.archive.org/cdx/search/cdx",
            params={"url": f"*.{domain}", "output": "json", "limit": 200, "fl": "original", "collapse": "urlkey"},
            timeout=8,
        )
        if r is None:
            status["wayback"] = "error: ConnectionError"
            return historical
        if r.status_code == 200:
            rows = r.json()
            seen = set()
            for row in rows[1:]:  # skip header
                if row and row[0]:
                    url = row[0]
                    m = re.match(r"https?://([^:/]+)", url)
                    if m:
                        host = m.group(1).lower()
                        if host.endswith(domain) or domain in host:
                            if host not in seen:
                                seen.add(host)
                                historical.append(host)
            status["wayback"] = f"{len(historical)} found"
        else:
            status["wayback"] = f"http_{r.status_code}"
    except Exception as e:
        status["wayback"] = f"error: {type(e).__name__}"
    return historical


def _collect_reverse_ip(ips: List[str], domain: str, status: Dict[str, str]) -> List[str]:
    """Find other domains hosted on same IPs via BGPView + hackertarget."""
    reverse = []
    # BGPView (ASN/prefix data + reverse DNS)
    for ip in ips[:3]:
        try:
            r = _http_get(f"https://api.bgpview.io/ip/{ip}", timeout=6)
            if r.status_code == 200:
                data = r.json().get("data", {})
                status["bgpview"] = "ok"
        except Exception:
            pass

    # HackerTarget reverse IP (original, works well)
    for ip in ips[:3]:
        try:
            r = _http_get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=8)
            if r.status_code == 200 and r.text and not r.text.lower().startswith("error"):
                for line in r.text.strip().splitlines():
                    host = line.strip().lower()
                    if host and (host.endswith(domain) or domain in host) and host not in reverse:
                        reverse.append(host)
                status["reverse-ip"] = "ok"
        except Exception:
            pass
    if not reverse:
        status["reverse-ip"] = "no_results"
    return reverse


def _collect_bgp_info(ips: List[str], status: Dict[str, str]) -> Optional[Dict[str, object]]:
    """Collect BGP/ASN information for resolved IPs via BGPView."""
    if not ips:
        return None
    ip = ips[0]
    try:
        r = _http_get(f"https://api.bgpview.io/ip/{ip}", timeout=6)
        if r is not None and r.status_code == 200:
            data = r.json().get("data", {})
            prefixes = data.get("prefixes", [])
            result = {
                "ip": ip,
                "asn": prefixes[0].get("asn") if prefixes else None,
                "name": prefixes[0].get("name") if prefixes else None,
                "country": prefixes[0].get("country_code") if prefixes else None,
                "rir": prefixes[0].get("rir") if prefixes else None,
                "prefix": prefixes[0].get("prefix") if prefixes else None,
                "description": data.get("name"),
                "website": data.get("website"),
                "email_contacts": data.get("email_contacts", []),
                "abuse_contacts": data.get("abuse_contacts", []),
            }
            status["bgp"] = "ok"
            return result
        status["bgp"] = "unavailable"
    except Exception as e:
        status["bgp"] = f"error: {type(e).__name__}"
    return None


def _collect_threat_intel(domain: str, ips: List[str], status: Dict[str, str]) -> Optional[Dict[str, object]]:
    """Check domain/IPs against threat intelligence feeds (abuse.ch ecosystem)."""
    result: Dict[str, object] = {"urlhaus": None, "threatfox": None, "feodo": None, "stopforumspam": None}

    # URLhaus — is this domain serving malware?
    try:
        r = _session.post("https://urlhaus-api.abuse.ch/v1/host/",
                          data={"host": domain}, timeout=8)
        if r.status_code == 200:
            data = r.json()
            result["urlhaus"] = {
                "status": data.get("query_status", ""),
                "url_count": data.get("urls_online", 0),
                "urls": [{"url": u.get("url", ""), "status": u.get("url_status", ""),
                          "threat": u.get("threat", ""), "date_added": u.get("date_added", "")}
                         for u in (data.get("urls", []) or [])[:5]],
            }
            status["urlhaus"] = "ok"
    except Exception as e:
        status["urlhaus"] = f"error: {type(e).__name__}"

    # ThreatFox — IOCs associated with domain
    try:
        r = _session.post("https://threatfox-api.abuse.ch/api/v1/",
                          json={"query": "search_ioc", "search_term": domain}, timeout=8)
        if r.status_code == 200:
            data = r.json()
            result["threatfox"] = {
                "status": data.get("query_status", ""),
                "ioc_count": len(data.get("data", []) or []),
                "iocs": [{"ioc": i.get("ioc", ""), "threat_type": i.get("threat_type", ""),
                          "malware": i.get("malware", ""), "confidence": i.get("confidence_level", 0)}
                         for i in (data.get("data", []) or [])[:5]],
            }
            status["threatfox"] = "ok"
    except Exception as e:
        status["threatfox"] = f"error: {type(e).__name__}"

    # Feodo Tracker — check if IPs are known botnet C2 servers
    try:
        r = _http_get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=8)
        if r.status_code == 200:
            feodo_ips = set()
            for entry in r.json():
                feodo_ips.add(entry.get("ip_address", ""))
            matched = [ip for ip in ips if ip in feodo_ips]
            result["feodo"] = {
                "known_c2": len(matched) > 0,
                "matched_ips": matched,
            }
            status["feodo"] = "ok"
    except Exception as e:
        status["feodo"] = f"error: {type(e).__name__}"

    # StopForumSpam — domain abuse reports
    try:
        r = _http_get("https://api.stopforumspam.org/api", params={"domain": domain, "json": ""}, timeout=6)
        if r.status_code == 200:
            data = r.json()
            result["stopforumspam"] = {
                "appears": data.get("domain", {}).get("appears", 0) > 0,
                "frequency": data.get("domain", {}).get("frequency", 0),
                "confidence": data.get("domain", {}).get("confidence", 0),
            }
            status["stopforumspam"] = "ok"
    except Exception as e:
        status["stopforumspam"] = f"error: {type(e).__name__}"

    return result


def _collect_common_crawl(domain: str, status: Dict[str, str]) -> List[str]:
    """Get historical subdomains from Common Crawl index (auto-detects latest)."""
    historical = []
    try:
        # Auto-detect latest index
        index_url = "https://index.commoncrawl.org/CC-MAIN-2024-40-index"
        try:
            idx_resp = _http_get("https://index.commoncrawl.org/collinfo.json", timeout=6)
            if idx_resp.status_code == 200:
                collections = idx_resp.json()
                if collections:
                    index_url = f"https://index.commoncrawl.org/{collections[0]['id']}-index"
        except Exception:
            pass

        r = _http_get(
            index_url,
            params={"url": f"*.{domain}", "output": "json", "limit": 100},
            timeout=8,
        )
        if r is None:
            status["commoncrawl"] = "error: ConnectionError"
        if r.status_code == 200:
            seen = set()
            for line in r.text.strip().splitlines():
                try:
                    import json as _json
                    entry = _json.loads(line)
                    url = entry.get("url", "")
                    m = re.match(r"https?://([^:/]+)", url)
                    if m:
                        host = m.group(1).lower()
                        if (host.endswith(domain) or domain in host) and host not in seen:
                            seen.add(host)
                            historical.append(host)
                except Exception:
                    pass
            status["commoncrawl"] = f"{len(historical)} found" if historical else "no_results"
        else:
            status["commoncrawl"] = f"http_{r.status_code}"
    except Exception as e:
        status["commoncrawl"] = f"error: {type(e).__name__}"
    return historical


def _collect_dmarc_mx(domain: str, status: Dict[str, str]) -> Optional[Dict[str, object]]:
    """Enhanced email security analysis via dmarc.mx API."""
    try:
        r = _http_get(f"https://dmarc.mx/api/check", params={"domain": domain}, timeout=8)
        if r.status_code == 200:
            data = r.json()
            result = {
                "dmarc_grade": data.get("dmarc_grade", ""),
                "spf_grade": data.get("spf_grade", ""),
                "dkim_grade": data.get("dkim_grade", ""),
                "overall_grade": data.get("overall_grade", ""),
                "bimi": data.get("bimi", None),
                "mta_sts": data.get("mta_sts", None),
                "dmarc_record": data.get("dmarc_record", ""),
                "spf_record": data.get("spf_record", ""),
            }
            status["dmarc-mx"] = "ok"
            return result
    except Exception as e:
        status["dmarc-mx"] = f"error: {type(e).__name__}"
    return None


# --------------------------------------------------------------------------- #
# Company name → domain resolution (Wikidata SPARQL)
# --------------------------------------------------------------------------- #
def _resolve_company_name(raw_query: str) -> Optional[Dict[str, str]]:
    """Resolve a company name to its official domain via Wikidata SPARQL.

    Returns dict with 'company_name' and 'domain' keys, or None.
    """
    q = (raw_query or "").strip()
    if not q or "." in q:
        return None

    sparql = f"""
    SELECT ?companyLabel ?domain WHERE {{
      ?company wdt:P31/wdt:P279* wd:Q43229 .
      ?company rdfs:label "{q}"@en .
      OPTIONAL {{ ?company wdt:P856 ?domain }}
      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en" . }}
    }} LIMIT 5
    """
    try:
        resp = _session.get(
            "https://query.wikidata.org/sparql",
            params={"query": sparql, "format": "json"},
            headers={**_USER_AGENT, "Accept": "application/sparql-results+json"},
            timeout=10,
        )
        if resp.status_code != 200:
            log.debug("Wikidata SPARQL returned %s for %r", resp.status_code, q)
            return None

        data = resp.json().get("results", {}).get("bindings", [])
        for row in data:
            domain_raw = row.get("domain", {}).get("value", "")
            name_raw = row.get("companyLabel", {}).get("value", "")
            if domain_raw:
                domain_clean = domain_raw.lower()
                domain_clean = re.sub(r"^https?://", "", domain_clean)
                domain_clean = domain_clean.split("/")[0]
                if "." in domain_clean:
                    return {"company_name": name_raw or q, "domain": domain_clean}

        # No P856 (website) found — try first result label at least
        if data:
            name_raw = data[0].get("companyLabel", {}).get("value", q)
            return {"company_name": name_raw, "domain": None}

    except Exception as e:
        log.debug("Wikidata resolution failed for %r: %s", q, e)

    return None


# --------------------------------------------------------------------------- #
# Company logo fetching
# --------------------------------------------------------------------------- #
def _fetch_company_logo(domain: str) -> Optional[str]:
    """Fetch company logo URL for a domain.

    Tries Hunter.io logo API (free, no key), falls back to Google favicon.
    """
    if not domain:
        return None

    # Hunter.io logo endpoint (free, no API key needed)
    try:
        resp = _http_get(f"https://logo.clearbit.com/{domain}", timeout=5)
        if resp and resp.status_code == 200 and "image" in resp.headers.get("content-type", ""):
            return resp.url
    except Exception:
        pass

    # Fallback: Google favicon
    try:
        favicon_url = f"https://www.google.com/s2/favicons?domain={domain}&sz=64"
        resp = _session.head(favicon_url, headers=_USER_AGENT, timeout=5, allow_redirects=True)
        if resp.status_code == 200:
            return favicon_url
    except Exception:
        pass

    return None


# --------------------------------------------------------------------------- #
# DNS Zone Transfer (AXFR) — critical misconfiguration detection
# --------------------------------------------------------------------------- #
def _collect_dns_zone_transfer(domain: str, status: Dict[str, str]) -> Optional[Dict[str, object]]:
    """Attempt DNS zone transfer (AXFR) on each NS server.

    If successful, this is a critical finding — the entire DNS zone is exposed.
    """
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.rdatatype

    ns_servers = []
    try:
        answers = dns.resolver.resolve(domain, "NS", lifetime=6)
        ns_servers = [str(r.target).rstrip(".") for r in answers]
    except Exception:
        status["dns-axfr"] = "no_ns"
        return None

    for ns in ns_servers:
        try:
            ns_ip = socket.gethostbyname(ns)
        except Exception:
            continue
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, lifetime=6, relativize=False))
            if zone:
                records = {}
                for name in zone.nodes:
                    for rdataset in zone.nodes[name]:
                        rtype = dns.rdatatype.to_text(rdataset.rdtype)
                        if rtype not in records:
                            records[rtype] = 0
                        records[rtype] += len(rdataset)
                status["dns-axfr"] = f"vulnerable via {ns}"
                return {
                    "vulnerable": True,
                    "nameserver": ns,
                    "nameserver_ip": ns_ip,
                    "record_types": records,
                    "total_records": sum(records.values()),
                }
        except Exception:
            pass

    status["dns-axfr"] = "not_vulnerable"
    return {"vulnerable": False}


# --------------------------------------------------------------------------- #
# Wildcard DNS Detection
# --------------------------------------------------------------------------- #
def _collect_wildcard_dns(domain: str, status: Dict[str, str]) -> Optional[Dict[str, object]]:
    """Detect wildcard DNS by resolving a random non-existent subdomain.

    If it resolves, wildcard DNS is active — potential subdomain takeover risk.
    """
    import random
    import string

    random_sub = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
    test_host = f"{random_sub}.{domain}"

    try:
        answers = socket.getaddrinfo(test_host, None)
        if answers:
            ips = list(set(a[4][0] for a in answers))
            status["wildcard-dns"] = f"active (resolves to {', '.join(ips)})"
            return {"active": True, "test_host": test_host, "resolved_ips": ips}
    except Exception:
        pass

    status["wildcard-dns"] = "not_active"
    return {"active": False}


# --------------------------------------------------------------------------- #
# DNSSEC Validation
# --------------------------------------------------------------------------- #
def _collect_dnssec(domain: str, status: Dict[str, str]) -> Optional[Dict[str, object]]:
    """Check DNSSEC validation status by querying DS and DNSKEY records."""
    import dns.resolver
    import dns.rdatatype

    result: Dict[str, object] = {"ds_records": [], "dnskey_records": [], "signed": False}

    # Check DS records (at parent zone)
    try:
        answers = dns.resolver.resolve(domain, "DS", lifetime=6)
        for rdata in answers:
            result["ds_records"].append(str(rdata))
        result["signed"] = len(result["ds_records"]) > 0
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except Exception:
        pass

    # Check DNSKEY records (at child zone)
    try:
        answers = dns.resolver.resolve(domain, "DNSKEY", lifetime=6)
        for rdata in answers:
            result["dnskey_records"].append(str(rdata)[:80])
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except Exception:
        pass

    status["dnssec"] = "signed" if result["signed"] else "not_signed"
    return result


# --------------------------------------------------------------------------- #
# Public entrypoint
# --------------------------------------------------------------------------- #
def lookup_domain(
    raw_query: str,
    timeout: Optional[int] = None,
    skip_categories: Optional[set] = None,
    on_source_complete: Optional[callable] = None,
) -> IntelResult:
    """Run the full key-free OSINT aggregation for a domain/company.

    Args:
        raw_query: Domain, IP, or company name to investigate.
        timeout: Override overall timeout in seconds (None = use settings default).
        skip_categories: Set of source category constants to skip (e.g. {SKIP_PORTS}).
        on_source_complete: Optional callback(source_name: str, result) called
            when each collector completes, for SSE streaming.
    """
    try:
        from app.config import settings
        effective_timeout = timeout or settings.OVERALL_TIMEOUT
    except Exception:
        effective_timeout = timeout or _OVERALL_TIMEOUT

    skip = skip_categories or set()
    _deadline = time.time() + effective_timeout
    company_name: Optional[str] = None
    logo_url: Optional[str] = None

    # Clear circuit-breaker from previous scans
    _DEAD_HOSTS.clear()

    def _time_left() -> float:
        return max(0.5, _deadline - time.time())

    def _emit(source_name: str, data):
        """Emit partial result to streaming callback if registered."""
        if on_source_complete:
            try:
                on_source_complete(source_name, data)
            except Exception:
                pass

    # ---- Phase 0: Company name resolution + logo (concurrent) ----
    q_stripped = (raw_query or "").strip()
    is_bare_name = "." not in q_stripped and not q_stripped.startswith("http")

    if is_bare_name:
        with cf.ThreadPoolExecutor(max_workers=2) as ex:
            f_company = ex.submit(_resolve_company_name, q_stripped)
            try:
                company_result = f_company.result(timeout=max(1, _deadline - time.time()))
                if company_result and company_result.get("domain"):
                    company_name = company_result["company_name"]
                    raw_query = company_result["domain"]
                elif company_result and company_result.get("company_name"):
                    company_name = company_result["company_name"]
            except Exception:
                pass

    try:
        domain = _normalize_domain(raw_query)
    except Exception as e:
        log.warning("normalize_domain failed for %r: %s", raw_query, e)
        domain = (raw_query or "").strip().lower()
        domain = re.sub(r"^https?://", "", domain).split("/")[0]

    result = IntelResult(query=domain, company_name=company_name)

    logo_future = None
    logo_executor = None

    if not domain:
        result.sources_status["input"] = "empty"
        return result

    result.sources_status["_domain"] = domain
    result.sources_status["_timeout"] = effective_timeout
    result.sources_status["_skip"] = list(skip) if skip else []

    # Fetch logo concurrently with everything else
    logo_executor = cf.ThreadPoolExecutor(max_workers=1)
    logo_future = logo_executor.submit(_fetch_company_logo, domain)

    # ---- Phase 1: DNS intelligence (concurrent) ----
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        f_subdomains = ex.submit(_collect_subdomains, domain, result.sources_status)
        f_dns = ex.submit(_resolve_dns, domain)
        f_certs = ex.submit(_collect_certificates, domain, result.sources_status)
        f_axfr = ex.submit(_collect_dns_zone_transfer, domain, result.sources_status)
        f_wildcard = ex.submit(_collect_wildcard_dns, domain, result.sources_status)
        f_dnssec = ex.submit(_collect_dnssec, domain, result.sources_status)

        try:
            result.dns_records = f_dns.result(timeout=_time_left())
        except Exception:
            result.dns_records = {}
        try:
            result.subdomains = f_subdomains.result(timeout=_time_left())
        except cf.TimeoutError:
            log.warning(
                "collect_subdomains timed out (%ss budget) — partial results dropped; "
                "try a higher --timeout or --profile standard",
                effective_timeout,
            )
            result.subdomains = []
        except Exception as e:
            log.warning("collect_subdomains failed: %s", e)
            result.subdomains = []
        try:
            result.certificates = f_certs.result(timeout=_time_left())
        except Exception:
            result.certificates = []
        try:
            result.dns_zone_transfer = f_axfr.result(timeout=_time_left())
        except Exception:
            result.dns_zone_transfer = None
        try:
            result.wildcard_dns = f_wildcard.result(timeout=_time_left())
        except Exception:
            result.wildcard_dns = None
        try:
            result.dnssec = f_dnssec.result(timeout=_time_left())
        except Exception:
            result.dnssec = None

    _emit("subdomains", {"count": len(result.subdomains)})
    _emit("dns", {"record_types": list(result.dns_records.keys())})
    _emit("certificates", {"count": len(result.certificates)})

    # ---- Subdomain Takeover Check (async) ----
    if result.subdomains:
        try:
            result.subdomain_takeover = check_subdomain_takeover(
                result.subdomains, result.sources_status
            )
        except Exception as e:
            log.warning("Subdomain takeover check failed: %s", e)
            result.sources_status["subdomain-takeover"] = f"error: {type(e).__name__}"
    else:
        result.sources_status["subdomain-takeover"] = "skipped: no subdomains"

    # Collect all IPs for downstream collectors
    all_ips = []
    for s in result.subdomains[:5]:
        for ip in s.ips:
            if ip and ip not in all_ips:
                all_ips.append(ip)

    # ---- Phase 2: Everything else (fully concurrent, flat) ----
    # All remaining collectors launch in a single executor. Dependencies are
    # handled via chained futures (tech→vulns). skip_categories controls which
    # optional collectors are omitted.
    try:
        from app.engine.osint_advanced import (
            _collect_email_security,
            _collect_sensitive_paths,
            _collect_web_intel,
            _collect_web_security,
            compute_risk_score,
        )
    except ImportError:
        # Standalone/CLI mode: local copy first, then the nexora fallback.
        # If both fail, the outer except ImportError skips advanced features.
        try:
            (_collect_email_security, _collect_sensitive_paths, _collect_web_intel,
             _collect_web_security, compute_risk_score) = _load_sibling(
                "osint_advanced.py",
                "_collect_email_security",
                "_collect_sensitive_paths",
                "_collect_web_intel",
                "_collect_web_security",
                "compute_risk_score",
            )
        except Exception:
            from nexora.advanced import (
                _collect_email_security,
                _collect_sensitive_paths,
                _collect_web_intel,
                _collect_web_security,
                compute_risk_score,
            )

        with cf.ThreadPoolExecutor(max_workers=20) as ex:
            # --- Port scan (skippable) ---
            f_ports = None
            if SKIP_PORTS not in skip:
                f_ports = ex.submit(_collect_ports, result.subdomains, result.sources_status)

            # --- Tech inference (chained AFTER ports for accurate detection) ---
            def _tech_after_ports():
                port_list = []
                if f_ports is not None:
                    try:
                        pr = f_ports.result(timeout=_time_left())
                        port_list = pr[0]
                    except Exception:
                        port_list = []
                return _infer_technologies(result.certificates, port_list, result.subdomains, domain)

            f_tech = ex.submit(_tech_after_ports)

            # --- Vulns (chained AFTER tech for relevant CVEs) ---
            f_vulns = ex.submit(
                lambda: _collect_vulns(f_tech.result(timeout=_time_left()), result.sources_status)
            )

            # --- IP reputation ---
            f_ip = ex.submit(_collect_ip_reputation, all_ips[:4], result.sources_status)

            # --- WHOIS ---
            f_whois = ex.submit(_collect_whois, domain, result.sources_status)

            # --- Historical ---
            f_wb = ex.submit(_collect_wayback, domain, result.sources_status)
            f_cc = ex.submit(_collect_common_crawl, domain, result.sources_status)

            # --- Reverse IP + BGP ---
            f_rip = ex.submit(_collect_reverse_ip, all_ips[:3], domain, result.sources_status)
            f_bgp = ex.submit(_collect_bgp_info, all_ips[:1], result.sources_status)

            # --- Email security ---
            f_email = ex.submit(_collect_email_security, domain, result.sources_status)

            # --- Web intel (fingerprint + WAF + headers) ---
            f_webintel = None
            if SKIP_WEB_FINGERPRINT not in skip:
                f_webintel = ex.submit(_collect_web_intel, domain, result.sources_status)

            # --- Sensitive paths (skippable) ---
            f_sp = None
            if SKIP_SENSITIVE_PATHS not in skip:
                f_sp = ex.submit(_collect_sensitive_paths, domain, result.sources_status)

            # --- Threat intel (skippable) ---
            f_threat = None
            if SKIP_THREAT_INTEL not in skip:
                f_threat = ex.submit(_collect_threat_intel, domain, all_ips[:3], result.sources_status)

            # --- DMARC/MX ---
            f_dmarc = ex.submit(_collect_dmarc_mx, domain, result.sources_status)

            # --- Web security (CORS + cookies + redirect) ---
            f_websec_http = ex.submit(_collect_web_security, domain, result.sources_status)

            # ---- Collect results ----

            # Port scan
            shodan_techs = []
            if f_ports is not None:
                try:
                    ports_result = f_ports.result(timeout=_time_left())
                    result.ports = ports_result[0]
                    shodan_techs = ports_result[1]
                except Exception:
                    result.ports = []
                _emit("ports", {"count": len(result.ports)})
            else:
                result.ports = []
                result.sources_status["port-scan"] = "skipped"

            # Tech inference
            try:
                result.technologies = f_tech.result(timeout=_time_left())
            except Exception:
                result.technologies = []
            # Merge Shodan CPEs into technologies
            if shodan_techs:
                existing = {t.lower() for t in result.technologies}
                for tech in shodan_techs:
                    parts = tech.split(":")
                    if len(parts) >= 5:
                        product = parts[4].lower()
                        if product and product not in existing:
                            result.technologies.append(product)
                            existing.add(product)
            _emit("technologies", {"count": len(result.technologies)})

            # Vulnerabilities
            try:
                result.vulnerabilities = f_vulns.result(timeout=_time_left())
            except Exception:
                result.vulnerabilities = []
            _emit("vulnerabilities", {"count": len(result.vulnerabilities)})

            # IP reputation
            try:
                result.ip_reputation = f_ip.result(timeout=_time_left())
            except Exception:
                result.ip_reputation = []
            _emit("ip_reputation", {"count": len(result.ip_reputation)})

            # WHOIS
            try:
                result.whois = f_whois.result(timeout=_time_left())
            except Exception:
                result.whois = None
            _emit("whois", {"found": result.whois is not None})

            # Historical
            try:
                result.historical_subdomains = f_wb.result(timeout=_time_left())
            except Exception:
                result.historical_subdomains = []
            try:
                result.common_crawl_subdomains = f_cc.result(timeout=_time_left())
            except Exception:
                result.common_crawl_subdomains = []

            # Reverse IP + BGP
            try:
                result.reverse_ip = f_rip.result(timeout=_time_left())
            except Exception:
                result.reverse_ip = []
            try:
                result.bgp_info = f_bgp.result(timeout=_time_left())
            except Exception:
                result.bgp_info = None

            # Email security
            try:
                result.email_security = f_email.result(timeout=_time_left())
            except Exception as exc:
                log.debug("email_security failed for %s: %s", domain, exc)
            _emit("email_security", {"found": result.email_security is not None})

            # Web intel (consolidated — WAF + headers + fingerprint + CORS)
            if f_webintel is not None:
                try:
                    webintel = f_webintel.result(timeout=_time_left())
                    if webintel:
                        result.waf_cdn, result.security_headers, result.web_fingerprint, websec_cors = webintel
                        if result.waf_cdn and websec_cors:
                            result.waf_cdn.cors_origin = websec_cors.get("cors_origin")
                            result.waf_cdn.cors_wildcard = websec_cors.get("cors_wildcard", False)
                            result.waf_cdn.cookies_secure = websec_cors.get("cookies_secure")
                            result.waf_cdn.cookies_httponly = websec_cors.get("cookies_httponly")
                            result.waf_cdn.cookies_samesite = websec_cors.get("cookies_samesite")
                except Exception as exc:
                    log.debug("web_intel consolidated failed for %s: %s", domain, exc)
            else:
                result.sources_status["web-fingerprint"] = "skipped"
            _emit("web_intel", {"found": result.waf_cdn is not None})

            # Sensitive paths
            if f_sp is not None:
                try:
                    result.sensitive_paths = f_sp.result(timeout=_time_left())
                except Exception as exc:
                    log.debug("sensitive_paths failed for %s: %s", domain, exc)
            else:
                result.sources_status["sensitive-paths"] = "skipped"
            _emit("sensitive_paths", {"count": len(result.sensitive_paths)})

            # Threat intel
            if f_threat is not None:
                try:
                    result.threat_intel = f_threat.result(timeout=_time_left())
                except Exception as exc:
                    log.debug("threat_intel failed for %s: %s", domain, exc)
            else:
                result.sources_status["threat-intel"] = "skipped"
            _emit("threat_intel", {"found": result.threat_intel is not None})

            # DMARC/MX
            try:
                result.dmarc_mx_result = f_dmarc.result(timeout=_time_left())
            except Exception as exc:
                log.debug("dmarc_mx failed for %s: %s", domain, exc)

            # Web security (HTTP redirect)
            try:
                websec = f_websec_http.result(timeout=_time_left())
                if websec and result.waf_cdn:
                    result.waf_cdn.http_to_https_redirect = websec.get("http_to_https_redirect")
                    result.waf_cdn.redirect_url = websec.get("redirect_url")
            except Exception as exc:
                log.debug("web_security http redirect failed for %s: %s", domain, exc)

        # ---- Risk scoring (after all collectors) ----
        try:
            result.risk_score = compute_risk_score(
                domain,
                result.email_security,
                result.waf_cdn,
                result.security_headers,
                result.sensitive_paths,
                result.web_fingerprint,
                len(result.subdomains),
                len(result.ports),
                len(result.vulnerabilities),
                result.whois,
                result.sources_status,
                result.subdomain_takeover,
            )
        except Exception as e:
            log.warning("risk_score failed: %s", e)
    except ImportError:
        pass

    # Collect logo result (started at top, runs concurrently with everything)
    if logo_future is not None:
        try:
            result.logo_url = logo_future.result(timeout=max(0.5, _deadline - time.time()))
        except Exception:
            result.logo_url = None
    if logo_executor is not None:
        try:
            logo_executor.shutdown(wait=False)
        except Exception:
            pass

    _emit("complete", {"domain": domain})
    return result


def intel_to_dict(result: IntelResult) -> dict:
    return {
        "query": result.query,
        "company_name": result.company_name,
        "logo_url": result.logo_url,
        "subdomains": [
            {"hostname": s.hostname, "ips": s.ips, "sources": s.sources}
            for s in result.subdomains
        ],
        "dns_records": result.dns_records,
        "certificates": [
            {
                "issuer": c.issuer,
                "subject": c.subject,
                "san": c.san,
                "not_before": c.not_before,
                "not_after": c.not_after,
                "serial": c.serial,
                "source": c.source,
            }
            for c in result.certificates
        ],
        "ports": [
            {
                "port": p.port,
                "state": p.state,
                "service": p.service,
                "banner": p.banner,
                "tls": p.tls,
                "title": p.title,
            }
            for p in result.ports
        ],
        "technologies": result.technologies,
        "vulnerabilities": [
            {
                "cve_id": v.cve_id,
                "description": v.description,
                "severity": v.severity,
                "cvss": v.cvss,
                "published": v.published,
                "is_kev": v.is_kev,
                "source": v.source,
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{v.cve_id}",
            }
            for v in result.vulnerabilities
        ],
        "sources_status": result.sources_status,
        "ip_reputation": result.ip_reputation,
        "whois": result.whois,
        "historical_subdomains": result.historical_subdomains,
        "reverse_ip": result.reverse_ip,
        # Advanced intelligence
        "email_security": _dc_to_dict(result.email_security) if result.email_security else None,
        "waf_cdn": _dc_to_dict(result.waf_cdn) if result.waf_cdn else None,
        "security_headers": _dc_to_dict(result.security_headers) if result.security_headers else None,
        "sensitive_paths": [_dc_to_dict(p) for p in result.sensitive_paths] if result.sensitive_paths else [],
        "web_fingerprint": _dc_to_dict(result.web_fingerprint) if result.web_fingerprint else None,
        "reverse_dns_range": result.reverse_dns_range,
        "risk_score": _dc_to_dict(result.risk_score) if result.risk_score else None,
        # Nexora v2 additions
        "threat_intel": result.threat_intel,
        "bgp_info": result.bgp_info,
        "osv_vulns": result.osv_vulns,
        "dmarc_mx_result": result.dmarc_mx_result,
        "common_crawl_subdomains": result.common_crawl_subdomains,
        # New intelligence fields
        "dns_zone_transfer": result.dns_zone_transfer,
        "wildcard_dns": result.wildcard_dns,
        "dnssec": result.dnssec,
        "subdomain_takeover": result.subdomain_takeover,
    }


def intel_to_dict_redacted(result: IntelResult) -> dict:
    """Redacted version of intel_to_dict for browser responses.

    Sensitive raw data (emails, phones, comments text, banners, paths,
    WHOIS personal info) is replaced with counts/summaries only.
    Full data stays server-side in cache/DB.
    """
    d = intel_to_dict(result)

    # ── Web fingerprint: redact scraped PII ──
    fp = d.get("web_fingerprint")
    if fp:
        fp["email_addresses_count"] = len(fp.get("email_addresses", []))
        fp["email_addresses"] = []
        fp["phone_numbers_count"] = len(fp.get("phone_numbers", []))
        fp["phone_numbers"] = []
        fp["social_links_count"] = len(fp.get("social_links", []))
        fp["social_links"] = []
        # HTML comments: keep categories only, strip text
        comments = fp.get("html_comments", [])
        fp["html_comments_count"] = len(comments)
        fp["html_comments_categories"] = list({c.get("category", "") for c in comments if c.get("category")})
        fp["html_comments"] = []

    # ── Sensitive paths: redact exact locations ──
    paths = d.get("sensitive_paths", [])
    d["sensitive_paths_count"] = len(paths)
    d["sensitive_paths_categories"] = list({p.get("category", "") for p in paths if p.get("category")})
    d["sensitive_paths"] = []

    # ── WHOIS: redact personal registrant info ──
    whois = d.get("whois")
    if whois:
        whois.pop("registrant_name", None)
        whois.pop("registrant_email", None)
        whois.pop("registrant_organization", None)
        whois.pop("registrant_country", None)

    # ── Ports: redact service banners ──
    for p in d.get("ports", []):
        if p.get("banner"):
            p["banner"] = "[redacted]"

    # ── Email security: redact discovered email addresses ──
    email_sec = d.get("email_security")
    if email_sec:
        email_sec["emails_found_count"] = len(email_sec.get("emails_found", []))
        email_sec["emails_found"] = []

    # ── Reverse IP: show count only ──
    rip = d.get("reverse_ip", [])
    d["reverse_ip_count"] = len(rip)
    d["reverse_ip"] = []

    # ── Common Crawl: show count only ──
    cc = d.get("common_crawl_subdomains", [])
    d["common_crawl_subdomains_count"] = len(cc)
    d["common_crawl_subdomains"] = []

    # ── Historical subdomains: show count only ──
    hist = d.get("historical_subdomains", [])
    d["historical_subdomains_count"] = len(hist)
    d["historical_subdomains"] = []

    # ── Threat intel: redact raw details ──
    ti = d.get("threat_intel")
    if ti:
        ti.pop("abuse_contacts", None)
        ti.pop("raw", None)

    # ── IP reputation: redact abuse contact info ──
    for ip_entry in d.get("ip_reputation", []):
        if isinstance(ip_entry, dict):
            ip_entry.pop("abuse_contact", None)
            ip_entry.pop("owner", None)

    return d


def _dc_to_dict(obj) -> dict:
    """Convert a dataclass to a plain dict, handling nested objects."""
    if hasattr(obj, "__dataclass_fields__"):
        d = {}
        for f in obj.__dataclass_fields__:
            val = getattr(obj, f)
            if hasattr(val, "__dataclass_fields__"):
                d[f] = _dc_to_dict(val)
            elif isinstance(val, list) and val and hasattr(val[0], "__dataclass_fields__"):
                d[f] = [_dc_to_dict(v) for v in val]
            else:
                d[f] = val
        return d
    return obj


# --------------------------------------------------------------------------- #
# Command-line interface
# --------------------------------------------------------------------------- #
_COLORS = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "gray": "\033[90m",
}
_COLOR_ENABLED = False


def _c(name: str) -> str:
    """Return an ANSI color code, or '' when colors are disabled."""
    return _COLORS.get(name, "") if _COLOR_ENABLED else ""


def _enable_windows_ansi() -> None:
    """Enable ANSI escape processing on Windows 10+ consoles."""
    if os.name != "nt":
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        k32.SetConsoleMode(k32.GetStdHandle(-11), 7)
    except Exception:
        pass


def _header(title: str) -> None:
    width = 66
    print(f"\n{_c('bold')}{_c('cyan')}== {title} "
          + "=" * max(1, width - len(title) - 3)
          + f"{_c('reset')}")


def _sev_color(sev: Optional[str]) -> str:
    s = (sev or "").upper()
    if s in ("CRITICAL", "HIGH"):
        return _c("red")
    if s == "MEDIUM":
        return _c("yellow")
    if s == "LOW":
        return _c("green")
    return _c("gray")


def _status_color(value: object) -> str:
    s = str(value).lower()
    if s.startswith("error") or "vulnerable" in s and not s.startswith("not"):
        return _c("red")
    if s.startswith("ok") or "found" in s or "open" in s or "signed" in s and not s.startswith("not"):
        return _c("green")
    if "rate_limit" in s or "http_" in s:
        return _c("yellow")
    return _c("gray")


def _render_text(result: IntelResult, limit: int = 50) -> None:
    """Pretty-print an IntelResult to the terminal."""

    # ── Summary ──
    _header("SUMMARY")
    if result.company_name:
        print(f"  Company:      {result.company_name}")
    print(f"  Domain:       {_c('bold')}{result.query}{_c('reset')}")
    if result.logo_url:
        print(f"  Logo:         {result.logo_url}")
    risk = result.risk_score
    if risk is not None:
        rd = _dc_to_dict(risk)
        if isinstance(rd, dict):
            score = rd.get("score")
            grade = rd.get("grade") or rd.get("level")
            if score is not None:
                try:
                    sv = float(score)
                    col = _c("red") if sv >= 70 else _c("yellow") if sv >= 40 else _c("green")
                except (TypeError, ValueError):
                    col = _c("yellow")
                label = f"{score}" + (f" ({grade})" if grade else "")
                print(f"  Risk score:   {col}{_c('bold')}{label}{_c('reset')}")
            for fnd in (rd.get("findings") or rd.get("issues") or [])[:14]:
                if isinstance(fnd, dict):
                    sev = str(fnd.get("severity", "info"))
                    detail = fnd.get("detail") or fnd.get("message") or str(fnd)
                    col = _sev_color(sev.upper())
                    print(f"      {col}{sev.upper():<9}{_c('reset')} {detail}")
                else:
                    print(f"      {_c('yellow')}*{_c('reset')} {fnd}")

    # ── DNS records ──
    if result.dns_records:
        _header("DNS RECORDS")
        for rtype, values in result.dns_records.items():
            for i, v in enumerate(values):
                label = rtype if i == 0 else ""
                print(f"  {label:<7} {v}")

    # ── DNS security (AXFR / wildcard / DNSSEC) ──
    axfr, wc, dsec = result.dns_zone_transfer, result.wildcard_dns, result.dnssec
    if axfr or wc or dsec:
        _header("DNS SECURITY")
        if axfr:
            if axfr.get("vulnerable"):
                print(f"  {_c('red')}{_c('bold')}Zone transfer (AXFR): VULNERABLE via "
                      f"{axfr.get('nameserver')} — {axfr.get('total_records')} records exposed{_c('reset')}")
            else:
                print(f"  {_c('green')}Zone transfer (AXFR): not vulnerable{_c('reset')}")
        if wc:
            if wc.get("active"):
                print(f"  {_c('yellow')}Wildcard DNS: active "
                      f"(resolves {wc.get('test_host')} -> {', '.join(wc.get('resolved_ips', []))}){_c('reset')}")
            else:
                print(f"  {_c('green')}Wildcard DNS: not active{_c('reset')}")
        if dsec:
            col = _c("green") if dsec.get("signed") else _c("yellow")
            n_ds = len(dsec.get("ds_records", []))
            print(f"  {col}DNSSEC: {'signed' if dsec.get('signed') else 'not signed'} "
                  f"({n_ds} DS records){_c('reset')}")

    # ── Subdomains ──
    if result.subdomains:
        _header(f"SUBDOMAINS ({len(result.subdomains)} discovered)")
        for s in result.subdomains[:limit]:
            ips = ", ".join(s.ips) if s.ips else "-"
            src = ",".join(s.sources)
            print(f"  {s.hostname:<42} {ips:<16} {_c('gray')}{src}{_c('reset')}")
        if len(result.subdomains) > limit:
            print(f"  {_c('gray')}... and {len(result.subdomains) - limit} more (use --limit to show){_c('reset')}")

    # ── Subdomain takeover ──
    if result.subdomain_takeover:
        _header("SUBDOMAIN TAKEOVER")
        for t in result.subdomain_takeover:
            td = t if isinstance(t, dict) else _dc_to_dict(t)
            host = td.get("subdomain") or td.get("hostname") or td.get("host") or "?"
            svc = td.get("service") or td.get("provider") or ""
            cname = td.get("cname") or ""
            conf = str(td.get("confidence") or "")
            vuln = td.get("vulnerable", td.get("is_vulnerable"))
            if vuln:
                mark = f"{_c('red')}{_c('bold')}VULNERABLE{_c('reset')}"
            elif conf == "medium":
                mark = f"{_c('yellow')}dangling (unconfirmed){_c('reset')}"
            else:
                mark = f"{_c('green')}safe{_c('reset')}"
            line = f"  {host} {svc} — {mark}"
            if cname:
                line += f" {_c('gray')}CNAME→{cname}{_c('reset')}"
            print(line)
            if td.get("evidence"):
                print(f"      {_c('gray')}evidence: {str(td['evidence'])[:120]}{_c('reset')}")

    # ── Certificates ──
    if result.certificates:
        _header("TLS CERTIFICATES")
        for cert in result.certificates:
            print(f"  Source: {_c('bold')}{cert.source}{_c('reset')}   Issuer: {cert.issuer}")
            print(f"  Valid:  {cert.not_before} -> {cert.not_after}")
            if cert.serial:
                print(f"  Serial: {cert.serial}")
            if cert.san:
                shown = ", ".join(cert.san[:15])
                more = f" ... (+{len(cert.san) - 15})" if len(cert.san) > 15 else ""
                print(f"  SANs:   {shown}{more}")
            print()

    # ── Open ports ──
    if result.ports:
        _header(f"OPEN PORTS ({len(result.ports)})")
        for p in result.ports:
            tls_mark = f" {_c('cyan')}[tls]{_c('reset')}" if p.tls else ""
            title = f" {_c('gray')}{p.title}{_c('reset')}" if p.title else ""
            print(f"  {p.port:<6} {(p.service or ''):<12}{tls_mark}{title}")

    # ── Technologies ──
    if result.technologies:
        _header(f"TECHNOLOGIES ({len(result.technologies)})")
        print("  " + ", ".join(result.technologies))

    # ── Vulnerabilities ──
    if result.vulnerabilities:
        _header(f"VULNERABILITIES ({len(result.vulnerabilities)})")
        for v in result.vulnerabilities[:limit]:
            sev = (v.severity or "UNKNOWN").upper()
            kev = f" {_c('magenta')}[KEV: exploited in the wild]{_c('reset')}" if v.is_kev else ""
            cvss = v.cvss if v.cvss is not None else "-"
            print(f"  {v.cve_id}  {_sev_color(sev)}{sev:<9}{_c('reset')} CVSS {cvss} "
                  f"{_c('gray')}({v.source}){_c('reset')}{kev}")
            if v.description:
                print(f"      {v.description[:200]}")
        if len(result.vulnerabilities) > limit:
            print(f"  {_c('gray')}... and {len(result.vulnerabilities) - limit} more (use --limit to show){_c('reset')}")

    # ── IP reputation ──
    if result.ip_reputation:
        _header("IP REPUTATION")
        for rep in result.ip_reputation:
            if not isinstance(rep, dict):
                continue
            org = rep.get("org") or rep.get("isp") or ""
            country = rep.get("country") or rep.get("country_code") or "?"
            print(f"  {_c('bold')}{rep.get('ip')}{_c('reset')}  {org} ({country})")
            extras = []
            abuse = rep.get("abuse_confidence")
            if abuse:
                extras.append(f"abuse {_c('red') if int(abuse) >= 50 else _c('yellow')}{abuse}%{_c('reset')}")
            for flag, label, col in (
                ("is_tor", "tor", "red"), ("is_vpn", "vpn", "yellow"),
                ("is_proxy", "proxy", "yellow"), ("is_hosting", "hosting", "gray"),
                ("is_datacenter", "datacenter", "gray"), ("is_mobile", "mobile", "gray"),
            ):
                if rep.get(flag):
                    extras.append(_c(col) + label + _c("reset"))
            if rep.get("asn"):
                extras.append(str(rep["asn"]))
            if extras:
                print(f"      " + "  ".join(extras))

    # ── WHOIS / RDAP ──
    if result.whois:
        _header("WHOIS / RDAP")
        w = result.whois
        for key in ("name", "registrar", "registration_date", "expiration_date", "last_changed", "handle"):
            if w.get(key):
                print(f"  {key.replace('_', ' ').title():<20} {w[key]}")
        if w.get("status"):
            print(f"  {'Status':<20} {', '.join(w['status'])}")
        if w.get("nameservers"):
            print(f"  {'Nameservers':<20} {', '.join(w['nameservers'])}")

    # ── BGP / ASN ──
    if result.bgp_info:
        _header("BGP / ASN")
        b = result.bgp_info
        mapping = [
            ("ip", "IP"), ("asn", "ASN"), ("name", "Name"), ("prefix", "Prefix"),
            ("country", "Country"), ("rir", "RIR"), ("description", "Description"),
            ("website", "Website"),
        ]
        for key, label in mapping:
            if b.get(key):
                print(f"  {label:<14} {b[key]}")
        for key in ("email_contacts", "abuse_contacts"):
            if b.get(key):
                print(f"  {key.replace('_', ' ').title():<14} {', '.join(b[key])}")

    # ── Email security ──
    email_sec = _dc_to_dict(result.email_security) if result.email_security else None
    dmarc = result.dmarc_mx_result
    if email_sec or dmarc:
        _header("EMAIL SECURITY")
        if dmarc:
            def _grade(key: str) -> str:
                g = str(dmarc.get(key) or "").upper() or "-"
                col = _c("green") if g in ("A", "B") else _c("yellow") if g in ("C", "D") else _c("red") if g == "F" else _c("gray")
                return f"{col}{g}{_c('reset')}"
            print(f"  DMARC: {_grade('dmarc_grade')}   SPF: {_grade('spf_grade')}   "
                  f"DKIM: {_grade('dkim_grade')}   Overall: {_grade('overall_grade')}")
            if dmarc.get("dmarc_record"):
                print(f"  Record: {_c('gray')}{dmarc['dmarc_record']}{_c('reset')}")
        if email_sec:
            mx = email_sec.get("mx_records") or email_sec.get("mx_hosts") or []
            if mx and isinstance(mx[0], dict):
                mx_str = ", ".join(
                    f"{m.get('host', '?')} (prio {m.get('priority', '?')})" for m in mx[:4])
                print(f"  {'MX':<20} {mx_str}")
            elif mx:
                print(f"  {'MX':<20} {', '.join(str(x) for x in mx[:4])}")
            prov = email_sec.get("provider")
            if prov:
                print(f"  {'Provider':<20} {prov}")
            dmarc_rec = email_sec.get("dmarc_record")
            pol = (email_sec.get("dmarc_policy") or "").upper()
            if dmarc_rec:
                col = _c("green") if pol in ("QUARANTINE", "REJECT") else _c("yellow")
                print(f"  {'DMARC':<20} {col}p={pol or '?'}{_c('reset')} "
                      f"{_c('gray')}{str(dmarc_rec)[:90]}{_c('reset')}")
            else:
                print(f"  {'DMARC':<20} {_c('red')}missing{_c('reset')}")
            spf_rec = email_sec.get("spf_record")
            if spf_rec:
                ok = email_sec.get("spf_valid")
                col = _c("red") if ok is False else _c("green")
                print(f"  {'SPF':<20} {col}{'valid' if ok else 'invalid'}{_c('reset')} "
                      f"{_c('gray')}{str(spf_rec)[:90]}{_c('reset')}")
            else:
                print(f"  {'SPF':<20} {_c('red')}missing{_c('reset')}")
            dkim_found = (email_sec.get("dkim_found")
                          or email_sec.get("dkim_selectors_found") or [])
            col = _c("green") if dkim_found else _c("yellow")
            dkim_txt = ", ".join(dkim_found[:6]) if dkim_found else "none found"
            print(f"  {'DKIM':<20} {col}{dkim_txt}{_c('reset')}")
            for key, label in (("mta_sts", "MTA-STS"), ("tls_rpt", "TLS-RPT"),
                               ("smtp_banner", "SMTP banner")):
                val = email_sec.get(key)
                if val:
                    print(f"  {label:<20} {_c('gray')}{str(val)[:90]}{_c('reset')}")
            if email_sec.get("score") is not None:
                sc = email_sec["score"]
                col = _c("green") if sc >= 80 else _c("yellow") if sc >= 50 else _c("red")
                print(f"  {'Posture score':<20} {col}{sc}/100{_c('reset')}")
            for issue in (email_sec.get("issues") or [])[:8]:
                print(f"      {_c('yellow')}!{_c('reset')} {issue}")

    # ── Web / WAF / headers / fingerprint ──
    waf = _dc_to_dict(result.waf_cdn) if result.waf_cdn else None
    headers = _dc_to_dict(result.security_headers) if result.security_headers else None
    fingerprint = _dc_to_dict(result.web_fingerprint) if result.web_fingerprint else None
    if waf or headers or fingerprint:
        _header("WEB PROFILE")
        for blob, title in ((waf, "WAF / CDN"), (headers, "Security headers"), (fingerprint, "Fingerprint")):
            if not blob:
                continue
            printed = False
            for k, v in blob.items():
                if k in ("email_addresses", "phone_numbers", "social_links", "html_comments"):
                    if isinstance(v, list) and v:
                        if not printed:
                            print(f"  {_c('bold')}{title}:{_c('reset')}")
                            printed = True
                        print(f"      {k.replace('_', ' ').title():<24} {len(v)} found")
                elif isinstance(v, list) and k in ("issues", "missing") and v:
                    if not printed:
                        print(f"  {_c('bold')}{title}:{_c('reset')}")
                        printed = True
                    for item in v:
                        print(f"      {_c('yellow')}!{_c('reset')} {item}")
                elif isinstance(v, (str, bool, int, float)) and v not in ("", False):
                    if not printed:
                        print(f"  {_c('bold')}{title}:{_c('reset')}")
                        printed = True
                    print(f"      {k.replace('_', ' ').title():<24} {v}")

    # ── Sensitive paths ──
    if result.sensitive_paths:
        _header(f"SENSITIVE PATHS ({len(result.sensitive_paths)})")
        for p in result.sensitive_paths[:20]:
            pd = p if isinstance(p, dict) else _dc_to_dict(p)
            path = pd.get("path") or pd.get("url") or "?"
            cat = pd.get("category") or ""
            st = pd.get("status", "?")
            restricted = bool(pd.get("restricted")) or st in (401, 403)
            sev = str(pd.get("severity") or "").upper()
            if sev:
                tag = f"{_sev_color(sev)}{sev}{_c('reset')}"
            elif restricted:
                tag = f"{_c('yellow')}restricted{_c('reset')}"
            else:
                tag = f"{_c('red')}exposed{_c('reset')}"
            print(f"  {path:<44} {tag} {_c('gray')}HTTP {st} · {cat}{_c('reset')}")
        if len(result.sensitive_paths) > 20:
            print(f"  {_c('gray')}... and {len(result.sensitive_paths) - 20} more{_c('reset')}")

    # ── Threat intel ──
    ti = result.threat_intel
    if ti:
        _header("THREAT INTEL")
        uh = ti.get("urlhaus")
        if uh:
            cnt = uh.get("url_count", 0) or 0
            if cnt:
                print(f"  {_c('red')}URLhaus:  {cnt} malicious URLs online{_c('reset')}")
                for u in (uh.get("urls") or [])[:5]:
                    print(f"      {u.get('url')} [{u.get('threat', '')}]")
            else:
                print(f"  {_c('green')}URLhaus:  clean{_c('reset')}")
        tf = ti.get("threatfox")
        if tf:
            cnt = tf.get("ioc_count", 0) or 0
            if cnt:
                print(f"  {_c('red')}ThreatFox: {cnt} matching IOCs{_c('reset')}")
                for i in (tf.get("iocs") or [])[:5]:
                    print(f"      {i.get('ioc')} — {i.get('malware', '')} (confidence {i.get('confidence', 0)})")
            else:
                print(f"  {_c('green')}ThreatFox: no IOCs{_c('reset')}")
        feodo = ti.get("feodo")
        if feodo:
            if feodo.get("known_c2"):
                print(f"  {_c('red')}Feodo:    IP matches known botnet C2: {', '.join(feodo.get('matched_ips', []))}{_c('reset')}")
            else:
                print(f"  {_c('green')}Feodo:    no known C2 matches{_c('reset')}")
        sfs = ti.get("stopforumspam")
        if sfs:
            if sfs.get("appears"):
                print(f"  {_c('yellow')}StopForumSpam: domain reported (confidence {sfs.get('confidence', 0)}){_c('reset')}")
            else:
                print(f"  {_c('green')}StopForumSpam: no reports{_c('reset')}")

    # ── Historical / reverse IP ──
    if result.historical_subdomains or result.common_crawl_subdomains or result.reverse_ip:
        _header("HISTORICAL / REVERSE")
        if result.historical_subdomains:
            print(f"  Wayback Machine:  {len(result.historical_subdomains)} hostnames "
                  f"{_c('gray')}({', '.join(result.historical_subdomains[:4])}){_c('reset')}")
        if result.common_crawl_subdomains:
            print(f"  Common Crawl:     {len(result.common_crawl_subdomains)} hostnames "
                  f"{_c('gray')}({', '.join(result.common_crawl_subdomains[:4])}){_c('reset')}")
        if result.reverse_ip:
            print(f"  Reverse IP:       {len(result.reverse_ip)} hosts on same IP")
            for h in result.reverse_ip[:10]:
                print(f"      {h}")

    # ── Source status ──
    status = {k: v for k, v in result.sources_status.items() if not k.startswith("_")}
    if status:
        _header(f"SOURCE STATUS ({len(status)} sources)")
        for k, v in sorted(status.items()):
            print(f"  {k:<22} {_status_color(v)}{v}{_c('reset')}")


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint. Returns a process exit code."""
    global _COLOR_ENABLED

    # Windows pipes default to cp1252 — force UTF-8 so ✓/→/· don't crash
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            pass

    parser = argparse.ArgumentParser(
        prog="nexora",
        description="Nexora — Advanced Internet Intelligence Engine. "
                    "Aggregates public OSINT for any domain / company from 25+ key-free sources.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  nexora example.com                     # full suite, auto-detects subcommand\n"
            "  nexora domain stripe                   # company name -> domain auto-resolved\n"
            "  nexora domain example.com -j -o report.json\n"
            "  python osint.py example.com            # legacy single-file engine CLI\n"
            "  python osint.py example.com -t 60 -v --limit 100\n"
        ),
    )
    parser.add_argument("target", help="Domain, URL, IP, or company name to investigate")
    parser.add_argument("-t", "--timeout", type=int, default=None,
                        help=f"Overall timeout in seconds (default: {_OVERALL_TIMEOUT})")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Print the full result as JSON to stdout")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Write the full JSON report to a file")
    parser.add_argument("--skip", action="append", choices=sorted(ALL_SKIPPABLE), default=[],
                        help="Skip a source category (repeatable): " + ", ".join(sorted(ALL_SKIPPABLE)))
    parser.add_argument("-n", "--limit", type=int, default=50, metavar="N",
                        help="Max subdomains/vulns to display in text mode (default: 50)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress the startup banner")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show per-source progress on stderr")
    parser.add_argument("--version", action="version", version="Nexora 2.1.0")
    args = parser.parse_args(argv)

    # Dependency check with a friendly message.
    missing = []
    for mod, pip_name in (("requests", "requests"), ("dns", "dnspython")):
        try:
            __import__(mod)
        except ImportError:
            missing.append(pip_name)
    if missing:
        print(f"{_c('red')}Missing dependencies: {', '.join(missing)}{_c('reset')}", file=sys.stderr)
        print(f"Install them with:  pip install {' '.join(missing)}", file=sys.stderr)
        return 2

    _enable_windows_ansi()
    _COLOR_ENABLED = (
        not args.no_color
        and not os.environ.get("NO_COLOR")
        and sys.stdout.isatty()
    )

    _banner_shown = False
    if not args.json and not args.no_banner and not os.environ.get("NEXORA_NO_BANNER"):
        try:
            from nexora.banner import print_banner
            print_banner()
            _banner_shown = True
        except Exception:
            pass

    progress_cb = None
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)
        def _on_source(source_name: str, data) -> None:
            print(f"  {_c('green')}[+]{_c('reset')} {source_name}: {data}", file=sys.stderr)
        progress_cb = _on_source

    if not _banner_shown:
        print(f"{_c('bold')}{_c('magenta')}Nexora OSINT Engine{_c('reset')} — key-free internet intelligence",
              file=sys.stderr)
    print(f"{_c('gray')}Target: {args.target} | timeout: {args.timeout or _OVERALL_TIMEOUT}s"
          f"{f' | skipped: {chr(44).join(args.skip)}' if args.skip else ''}{_c('reset')}\n",
          file=sys.stderr)

    started = time.time()
    try:
        result = lookup_domain(
            args.target,
            timeout=args.timeout,
            skip_categories=set(args.skip) if args.skip else None,
            on_source_complete=progress_cb,
        )
    except KeyboardInterrupt:
        print(f"\n{_c('yellow')}Interrupted.{_c('reset')}", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"{_c('red')}Lookup failed: {type(e).__name__}: {e}{_c('reset')}", file=sys.stderr)
        return 1
    elapsed = time.time() - started

    payload = intel_to_dict(result)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
            print(f"{_c('green')}JSON report written to {args.output}{_c('reset')}", file=sys.stderr)
        except OSError as e:
            print(f"{_c('red')}Could not write {args.output}: {e}{_c('reset')}", file=sys.stderr)
            return 1

    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    else:
        if not result.query or result.sources_status.get("input") == "empty":
            print(f"{_c('red')}No valid domain could be derived from {args.target!r}.{_c('reset')}",
                  file=sys.stderr)
            return 1
        _render_text(result, limit=max(1, args.limit))
        print(f"\n{_c('gray')}Completed in {elapsed:.1f}s{_c('reset')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
