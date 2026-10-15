"""Subdomain takeover detection via dangling CNAMEs.

Checks every discovered subdomain for CNAME records pointing to
unclaimed third-party services (GitHub Pages, S3, Heroku, etc.).
Uses asyncio + aiohttp + dns.asyncresolver for maximum concurrency.

Reference: EdOverflow/can-i-take-over-xyz
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Dict, List

import aiohttp
import dns.asyncresolver
import dns.resolver
import dns.rdatatype

log = logging.getLogger("osint.takeover")


# ── Fingerprint dictionary ────────────────────────────────────────── #
# Each entry: service name, CNAME suffixes to match, HTTP body
# substrings indicating an unclaimed state, and whether confirmed vulnerable.

TAKEOVER_FINGERPRINTS: List[Dict] = [
    # ── Confirmed vulnerable ──────────────────────────────────────── #
    {
        "service": "AWS S3",
        "cnames": ["s3.amazonaws.com"],
        "fingerprints": [
            "The specified bucket does not exist",
            "NoSuchBucket",
            "Access Denied",
        ],
        "vulnerable": True,
    },
    {
        "service": "GitHub Pages",
        "cnames": ["github.io"],
        "fingerprints": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "vulnerable": True,
    },
    {
        "service": "Heroku",
        "cnames": ["herokuapp.com", "herokudns.com"],
        "fingerprints": ["No such app"],
        "vulnerable": True,
    },
    {
        "service": "Netlify",
        "cnames": ["netlify.app", "netlify.com"],
        "fingerprints": [
            "Not Found - Request ID:",
            "netlify-dns-custom",
        ],
        "vulnerable": True,
    },
    {
        "service": "Vercel",
        "cnames": ["vercel-dns.com", "cname.vercel-dns.com"],
        "fingerprints": [
            "DEPLOYMENT_NOT_FOUND",
            "The deployment could not be found",
        ],
        "vulnerable": True,
    },
    {
        "service": "AWS Elastic Beanstalk",
        "cnames": ["elasticbeanstalk.com"],
        "fingerprints": [],
        "vulnerable": True,
        "nxdomain_only": True,
    },
    {
        "service": "Microsoft Azure",
        "cnames": [
            "azurewebsites.net",
            "cloudapp.net",
            "cloudapp.azure.com",
            "blob.core.windows.net",
            "azureedge.net",
            "azurecr.io",
            "visualstudio.com",
        ],
        "fingerprints": [],
        "vulnerable": True,
        "nxdomain_only": True,
    },
    {
        "service": "Bitbucket",
        "cnames": ["bitbucket.io"],
        "fingerprints": ["Repository not found"],
        "vulnerable": True,
    },
    {
        "service": "Shopify",
        "cnames": ["myshopify.com"],
        "fingerprints": [
            "Sorry, this shop is currently unavailable",
            "Only one step left!",
        ],
        "vulnerable": True,
    },
    {
        "service": "Ngrok",
        "cnames": ["ngrok.io"],
        "fingerprints": [
            "Tunnel *.ngrok.io not found",
            "ngrok.com/dns",
        ],
        "vulnerable": True,
    },
    {
        "service": "Pantheon",
        "cnames": ["pantheonsite.io"],
        "fingerprints": ["404 error unknown site!"],
        "vulnerable": True,
    },
    {
        "service": "Surge.sh",
        "cnames": ["surge.sh"],
        "fingerprints": ["project not found"],
        "vulnerable": True,
    },
    {
        "service": "WordPress.com",
        "cnames": ["wordpress.com"],
        "fingerprints": ["Do you want to register"],
        "vulnerable": True,
    },
    {
        "service": "Cargo Collective",
        "cnames": ["cargocollective.com"],
        "fingerprints": ["404 Not Found"],
        "vulnerable": True,
    },
    {
        "service": "Strikingly",
        "cnames": ["strikinglydns.com"],
        "fingerprints": ["PAGE NOT FOUND"],
        "vulnerable": True,
    },
    {
        "service": "Ghost",
        "cnames": ["ghost.io"],
        "fingerprints": [
            "Site unavailable",
            "Failed to resolve DNS path for this host",
        ],
        "vulnerable": True,
    },
    {
        "service": "Readme.io",
        "cnames": ["readme.io"],
        "fingerprints": [
            "still working on making everything perfect",
            "Project does not exist",
        ],
        "vulnerable": True,
    },
    {
        "service": "Pingdom",
        "cnames": ["stats.pingdom.com"],
        "fingerprints": ["Sorry, couldn't find the status page"],
        "vulnerable": True,
    },
    {
        "service": "UptimeRobot",
        "cnames": ["stats.uptimerobot.com"],
        "fingerprints": ["page not found"],
        "vulnerable": True,
    },
    {
        "service": "Help Scout",
        "cnames": ["helpscoutdocs.com"],
        "fingerprints": ["No settings were found for this company"],
        "vulnerable": True,
    },
    {
        "service": "Help Juice",
        "cnames": ["helpjuice.com"],
        "fingerprints": ["We could not find what you're looking for"],
        "vulnerable": True,
    },
    {
        "service": "Anima",
        "cnames": ["animaapp.io"],
        "fingerprints": ["The page you were looking for does not exist"],
        "vulnerable": True,
    },
    {
        "service": "Gemfury",
        "cnames": ["furyns.com"],
        "fingerprints": ["404: This page could not be found"],
        "vulnerable": True,
    },
    {
        "service": "Agile CRM",
        "cnames": ["agilecrm.com"],
        "fingerprints": ["Sorry, this page is no longer available"],
        "vulnerable": True,
    },
    {
        "service": "JetBrains YouTrack",
        "cnames": ["youtrack.cloud"],
        "fingerprints": ["is not a registered InCloud YouTrack"],
        "vulnerable": True,
    },
    {
        "service": "Tumblr",
        "cnames": ["domains.tumblr.com"],
        "fingerprints": [
            "Whatever you were looking for doesn't currently exist at this address",
        ],
        "vulnerable": True,
    },
    {
        "service": "Webflow",
        "cnames": ["proxy.webflow.com", "proxy-ssl.webflow.com"],
        "fingerprints": [
            "The page you are looking for doesn't exist or has been moved",
        ],
        "vulnerable": True,
    },
    {
        "service": "Wix",
        "cnames": ["redirector.wix.com"],
        "fingerprints": [
            "Looks Like This Domain Isn't Connected To A Website Yet",
        ],
        "vulnerable": True,
    },
    {
        "service": "Campaign Monitor",
        "cnames": ["createsend.com"],
        "fingerprints": ["Trying to access your account"],
        "vulnerable": True,
    },
    {
        "service": "HatenaBlog",
        "cnames": ["hatenablog.com"],
        "fingerprints": ["404 Blog is not found"],
        "vulnerable": True,
    },
]

# Build a fast lookup: CNAME suffix → list of fingerprint entries
_CNAME_MAP: Dict[str, List[Dict]] = {}
for _entry in TAKEOVER_FINGERPRINTS:
    for _suffix in _entry["cnames"]:
        _CNAME_MAP.setdefault(_suffix, []).append(_entry)


# ── Async implementation ──────────────────────────────────────────── #

DNS_TIMEOUT = 3.0   # seconds per CNAME lookup
HTTP_TIMEOUT = 5.0  # seconds per HTTP check
DNS_SEMAPHORE = 100  # max concurrent DNS lookups
HTTP_SEMAPHORE = 50   # max concurrent HTTP checks


def _match_fingerprint(cname_target: str) -> List[Dict]:
    """Return all fingerprint entries whose CNAME suffix matches the target."""
    matches = []
    target_lower = cname_target.lower().rstrip(".")
    for suffix, entries in _CNAME_MAP.items():
        if target_lower.endswith(suffix) or target_lower == suffix:
            matches.extend(entries)
    return matches


async def _resolve_cname(
    resolver: dns.asyncresolver.Resolver,
    hostname: str,
    sem: asyncio.Semaphore,
) -> str | None:
    """Resolve the CNAME for a hostname. Returns target or None."""
    async with sem:
        try:
            answer = await resolver.resolve(hostname, "CNAME", lifetime=DNS_TIMEOUT)
            for rdata in answer:
                return str(rdata.target).rstrip(".")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers,
                dns.exception.DNSException):
            return None
    return None


async def _check_nxdomain(
    resolver: dns.asyncresolver.Resolver,
    hostname: str,
) -> bool:
    """Check if the hostname itself returns NXDOMAIN (indicates dangling CNAME)."""
    try:
        await resolver.resolve(hostname, "A", lifetime=DNS_TIMEOUT)
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:
        return False


async def _http_fingerprint(
    session: aiohttp.ClientSession,
    subdomain: str,
    fingerprints: List[str],
    sem: asyncio.Semaphore,
) -> str | None:
    """HTTP GET the subdomain and check for fingerprint strings. Returns match or None."""
    if not fingerprints:
        return None
    async with sem:
        for scheme in ("https", "http"):
            try:
                url = f"{scheme}://{subdomain}/"
                async with session.get(url, allow_redirects=True, ssl=False) as resp:
                    if resp.status == 404:
                        # Some services return 404 on unclaimed — still check body
                        pass
                    body = await resp.text(errors="replace")
                    body_lower = body[:50000].lower()  # limit read for performance
                    for fp in fingerprints:
                        if fp.lower() in body_lower:
                            return fp
            except Exception:
                continue
    return None


async def _async_check_takeover(
    subdomains: list,
    status: Dict[str, str],
) -> List[Dict[str, object]]:
    """Core async implementation: CNAME resolution + HTTP fingerprinting."""
    start = time.time()
    total = len(subdomains)

    # Deduplicate hostnames
    hostnames = list({s.hostname for s in subdomains if s.hostname})

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT

    dns_sem = asyncio.Semaphore(DNS_SEMAPHORE)
    http_sem = asyncio.Semaphore(HTTP_SEMAPHORE)

    # Step 1: Resolve CNAMEs concurrently
    cname_pairs = [(h, asyncio.create_task(_resolve_cname(resolver, h, dns_sem))) for h in hostnames]

    # hostname → CNAME target
    cname_map: Dict[str, str] = {}
    results = await asyncio.gather(*[t for _, t in cname_pairs], return_exceptions=True)
    for (hostname, _), result in zip(cname_pairs, results):
        if not isinstance(result, Exception) and result:
            cname_map[hostname] = result

    # Step 2: Match CNAMEs against fingerprint dictionary
    matched = []  # (hostname, cname_target, fingerprint_entries)
    for hostname, cname_target in cname_map.items():
        entries = _match_fingerprint(cname_target)
        if entries:
            matched.append((hostname, cname_target, entries))

    # Step 3: HTTP fingerprint check (only on matched subdomains)
    results: List[Dict[str, object]] = []
    http_check_tasks = []

    if matched:
        connector = aiohttp.TCPConnector(limit=HTTP_SEMAPHORE, ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
        ) as session:
            for hostname, cname_target, entries in matched:
                # Collect all unique fingerprints for this CNAME target
                all_fps = list({fp for e in entries for fp in e["fingerprints"]})
                services = [e["service"] for e in entries]
                any_vulnerable = any(e["vulnerable"] for e in entries)
                nxdomain_only = any(e.get("nxdomain_only") for e in entries)

                task = asyncio.create_task(
                    _http_fingerprint(session, hostname, all_fps, http_sem)
                )
                http_check_tasks.append({
                    "task": task,
                    "hostname": hostname,
                    "cname": cname_target,
                    "services": services,
                    "fingerprints": all_fps,
                    "vulnerable": any_vulnerable,
                    "nxdomain_only": nxdomain_only,
                })

            # Collect HTTP results
            for item in http_check_tasks:
                task = item["task"]
                hostname = item["hostname"]
                try:
                    fp_match = await task
                except Exception:
                    fp_match = None

                if fp_match:
                    # Fingerprint matched — confirmed vulnerable
                    results.append({
                        "subdomain": hostname,
                        "cname": item["cname"],
                        "service": ", ".join(item["services"]),
                        "vulnerable": item["vulnerable"],
                        "confidence": "high",
                        "evidence": fp_match,
                    })
                elif item["nxdomain_only"]:
                    # NXDOMAIN-only service — check if hostname is actually dead
                    is_nxdomain = await _check_nxdomain(resolver, hostname)
                    if is_nxdomain:
                        results.append({
                            "subdomain": hostname,
                            "cname": item["cname"],
                            "service": ", ".join(item["services"]),
                            "vulnerable": item["vulnerable"],
                            "confidence": "high",
                            "evidence": "NXDOMAIN",
                        })
                    else:
                        results.append({
                            "subdomain": hostname,
                            "cname": item["cname"],
                            "service": ", ".join(item["services"]),
                            "vulnerable": False,
                            "confidence": "low",
                            "evidence": "CNAME matches but hostname resolves",
                        })
                else:
                    # CNAME matches but HTTP fingerprint inconclusive
                    results.append({
                        "subdomain": hostname,
                        "cname": item["cname"],
                        "service": ", ".join(item["services"]),
                        "vulnerable": False,
                        "confidence": "medium",
                        "evidence": "CNAME matches but no fingerprint found",
                    })

    elapsed = time.time() - start
    vulnerable_count = sum(1 for r in results if r.get("vulnerable"))

    log.info(
        "Takeover check: %d subdomains → %d CNAME matches → %d vulnerable (%.1fs)",
        total, len(matched), vulnerable_count, elapsed,
    )

    if results:
        status["subdomain-takeover"] = (
            f"{vulnerable_count} vulnerable" if vulnerable_count
            else f"{len(results)} dangling CNAMEs"
        )
    else:
        status["subdomain-takeover"] = "ok"

    return results


# ── Sync entry point ──────────────────────────────────────────────── #

def check_subdomain_takeover(
    subdomains: list,
    status: Dict[str, str],
) -> List[Dict[str, object]]:
    """Check all subdomains for takeover vulnerabilities.

    This is a sync wrapper that creates its own event loop to run
    the async implementation. Safe to call from the sync ThreadPoolExecutor.

    Args:
        subdomains: List of SubdomainResult from Phase 1 enumeration.
        status: sources_status dict to update with results.

    Returns:
        List of dicts with takeover findings.
    """
    if not subdomains:
        status["subdomain-takeover"] = "no_targets"
        return []

    try:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_async_check_takeover(subdomains, status))
        finally:
            loop.close()
    except Exception as e:
        log.warning("Subdomain takeover check failed: %s", e)
        status["subdomain-takeover"] = f"error: {type(e).__name__}"
        return []
