"""Brand protection: official-account discovery + impersonation detection.

``lookup_brand(domain)`` parses the homepage for rel=me / platform links,
then probes username variants (stem, stem+official/support/help/hq/corp,
stem-team) against a relevant subset of the SITES catalogue. Handles that
are active on a platform where the brand does NOT link an official
account become impersonation candidates with a severity.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from ..net import http_get, reset_circuit_breaker
from ..output import c, header, sev_color
from ..username import SITES

_HOMEPAGE_CAP = 512 * 1024

# host fragment -> platform label
_PLATFORM_HOSTS = (
    ("twitter.com", "twitter"), ("x.com", "twitter"),
    ("mobile.twitter.com", "twitter"),
    ("github.com", "github"), ("gitlab.com", "gitlab"),
    ("linkedin.com", "linkedin"), ("instagram.com", "instagram"),
    ("facebook.com", "facebook"), ("youtube.com", "youtube"),
    ("youtu.be", "youtube"), ("tiktok.com", "tiktok"),
    ("threads.net", "threads"), ("reddit.com", "reddit"),
    ("t.me", "telegram"), ("telegram.me", "telegram"),
    ("discord.gg", "discord"), ("discord.com", "discord"),
    ("medium.com", "medium"), ("bsky.social", "bluesky"),
    ("bsky.app", "bluesky"), ("twitch.tv", "twitch"),
    ("linktr.ee", "linktree"), ("about.me", "aboutme"),
    ("mastodon.social", "mastodon"), ("hachyderm.io", "mastodon"),
)

# platforms whose official presence we report gaps for
_COVERAGE_PLATFORMS = ("twitter", "instagram", "facebook", "youtube",
                       "linkedin", "github", "tiktok", "threads")

# subset of ..username.SITES used for impersonation probing
_PROBE_SITES = ("GitHub", "Reddit", "Linktree", "About.me", "Keybase",
                "Medium", "Substack")

# hostnames that are "mastodon-like" (any host with a @handle path)
_MASTODON_HOST_RE = re.compile(r"mastodon|hachyderm|social\.club", re.I)


def _normalize_domain(domain: str) -> str:
    d = (domain or "").strip()
    if not d:
        raise ValueError("empty domain")
    if "://" in d:
        host = urlparse(d).hostname or ""
    else:
        host = d.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    host = (host or "").strip().lower().rstrip(".")
    if "." not in host or host.startswith(".") or host.endswith("."):
        raise ValueError("invalid domain: %r" % (domain,))
    return host


def _platform_for_url(url: str) -> Optional[str]:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return None
    for frag, label in _PLATFORM_HOSTS:
        if host == frag or host.endswith("." + frag):
            return label
    return None


def _handle_from_url(url: str, platform: str) -> Optional[str]:
    """Extract the account handle from a profile URL path."""
    try:
        path = unquote(urlparse(url).path or "")
    except Exception:
        return None
    parts = [p for p in path.split("/") if p]
    if not parts:
        return None
    if platform == "linkedin":
        if len(parts) >= 2 and parts[0].lower() == "in":
            return parts[1]
        return None
    if platform == "reddit":
        if len(parts) >= 2 and parts[0].lower() in ("user", "u"):
            return parts[1]
        return None
    if platform == "youtube":
        first = parts[0]
        if first.startswith("@"):
            return first[1:]
        if len(parts) >= 2 and first.lower() in ("c", "channel"):
            return parts[1]
        return None
    if platform == "telegram" and parts[0].lower() in ("joinchat", "s",
                                                       "share"):
        return None
    if platform == "discord" and parts[0].lower() in ("invite", "channels",
                                                      "login"):
        return None
    if platform == "facebook" and parts[0].lower() in ("pages", "people",
                                                       "groups", "share",
                                                       "profile.php"):
        return None
    if platform == "twitch" and parts[0].lower() in ("directory", "videos"):
        return None
    handle = parts[0]
    if handle.startswith("@"):
        handle = handle[1:]
    if platform == "mastodon":
        # '@user@host' is a valid acct — keep internal @
        if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,60}@[A-Za-z0-9.\-]+",
                            handle) and not re.fullmatch(
                r"[A-Za-z0-9_.\-]{1,60}", handle):
            return None
        return handle
    handle = handle.strip("@")
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,60}", handle):
        return None
    return handle


# --------------------------------------------------------------------------- #
# Pure HTML parsing
# --------------------------------------------------------------------------- #
def _extract_official(html: str, domain: str) -> List[Dict[str, str]]:
    """Pull official social accounts out of a homepage (PURE).

    Returns [{platform, handle, url, source}] — relative links and
    non-social links are ignored; ``<a rel="me">`` links are preferred.
    """
    out: List[Dict[str, str]] = []
    seen: set = set()

    def _add(url: str, source: str) -> None:
        url = (url or "").strip()
        if not url or url.startswith(("#", "javascript:", "mailto:",
                                      "/")):
            return
        if url.startswith("//"):
            url = "https:" + url
        if not url.startswith("http"):
            return
        platform = _platform_for_url(url)
        if platform is None:
            host = (urlparse(url).hostname or "").lower()
            # webfinger-style mastodon links (@user@host)
            if _MASTODON_HOST_RE.search(host):
                platform = "mastodon"
            else:
                return
        handle = _handle_from_url(url, platform)
        if not handle:
            return
        key = (platform, handle.lower())
        if key in seen:
            return
        seen.add(key)
        out.append({"platform": platform, "handle": handle, "url": url,
                    "source": source})

    # 1. anchors/links with rel="me" (strongest signal; XFN may use <a>
    #    or <link> tags in <head>)
    for m in re.finditer(r"<(?:a|link)\b[^>]+>", html, re.I):
        tag = m.group(0)
        rel_m = re.search(r"rel=[\"']([^\"']*)[\"']", tag, re.I)
        if not rel_m or not re.search(r"\bme\b", rel_m.group(1), re.I):
            continue
        href_m = re.search(r"href=[\"']([^\"']+)[\"']", tag, re.I)
        if href_m:
            _add(href_m.group(1), "rel=me")

    # 2. every anchor href that points at a known platform
    for m in re.finditer(r"href=[\"']([^\"']+)[\"']", html, re.I):
        _add(m.group(1), "homepage")

    # 3. webfinger link tag (mastodon)
    for m in re.finditer(
            r"<link\b[^>]*href=[\"']([^\"']*webfinger[^\"']*)[\"'][^>]*>",
            html, re.I):
        href = m.group(1)
        res_m = re.search(r"resource=acct:([^&\"']+)", href)
        if res_m:
            acct = res_m.group(1)
            host_m = re.search(r"@([A-Za-z0-9.\-]+)$", acct)
            if host_m:
                url = "https://%s/@%s" % (host_m.group(1),
                                          acct.split("@")[0])
                platform = "mastodon"
                handle = acct
                key = (platform, handle.lower())
                if key not in seen:
                    seen.add(key)
                    out.append({"platform": platform, "handle": handle,
                                "url": url, "source": "webfinger"})

    return out


def _build_variants(domain: str) -> List[str]:
    """Impersonation-handle variants for a brand stem (PURE).

    stem = second-level label ('stripe' from stripe.com, or 'acme' from
    acme.co.uk). Returns up to 7 variants, each <=40 chars, deduped.
    """
    labels = [l for l in domain.split(".") if l]
    if len(labels) >= 3 and labels[-2] in ("co", "com", "net", "org",
                                           "gov", "edu", "ac"):
        stem = labels[-3]
    else:
        stem = labels[-2] if len(labels) >= 2 else labels[0]
    candidates = [
        stem,
        stem + "official",
        stem + "support",
        stem + "help",
        stem + "hq",
        stem + "corp",
        stem + "-team",
    ]
    out: List[str] = []
    for cand in candidates:
        if len(cand) <= 40 and cand not in out:
            out.append(cand)
    return out


def _candidate_reason(variant: str, platform: str, domain: str
                      ) -> Tuple[str, str]:
    """(reason, severity) for an impersonation candidate (PURE).

    high   -> variant contains official/support/help
    medium -> other decorated variants (hq, corp, -team)
    low    -> stem-only mismatch
    """
    stem = variant.split("official")[0].split("support")[0] \
        .split("help")[0].split("hq")[0].split("corp")[0] \
        .split("-team")[0]
    if any(token in variant for token in ("official", "support", "help")):
        severity = "high"
    elif variant == stem:
        severity = "low"
    else:
        severity = "medium"
    reason = ("handle '%s' active on %s but not linked from %s"
              % (variant, platform, domain))
    return reason, severity


# --------------------------------------------------------------------------- #
# Homepage fetch
# --------------------------------------------------------------------------- #
def _fetch_homepage(domain: str) -> Tuple[Optional[int], str]:
    for scheme in ("https", "http"):
        url = "%s://%s/" % (scheme, domain)
        resp = None
        try:
            resp = http_get(url, timeout=10, stream=True)
            if resp is None:
                continue
            code = int(resp.status_code)
            if code != 200:
                try:
                    resp.close()
                except Exception:
                    pass
                return code, ""
            buf = bytearray()
            try:
                for chunk in resp.iter_content(8192):
                    if chunk:
                        buf.extend(chunk)
                    if len(buf) >= _HOMEPAGE_CAP:
                        break
            except Exception:
                pass
            return 200, bytes(buf[:_HOMEPAGE_CAP]).decode("utf-8", "ignore")
        except Exception:
            continue
        finally:
            if resp is not None:
                try:
                    resp.close()
                except Exception:
                    pass
    return None, ""


# --------------------------------------------------------------------------- #
# Impersonation probe
# --------------------------------------------------------------------------- #
_AMBIGUOUS = (401, 403, 405, 429, 999, 301, 302, 303, 307, 308)


def _probe_site(site: Dict[str, Any], variant: str) -> str:
    """Check one (site, variant). Returns found/not_found/maybe/unknown."""
    url = site["url"].format(u=variant)
    unreliable = bool(site.get("unreliable"))
    resp = None
    try:
        resp = http_get(url, timeout=6, stream=True)
        if resp is None:
            return "unknown"
        code = int(resp.status_code)
        if code == 200:
            return "unknown" if unreliable else "found"
        if code in (404, 410):
            return "not_found"
        if code in _AMBIGUOUS:
            return "unknown" if unreliable else "maybe"
        return "unknown"
    except Exception:
        return "unknown"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #
def lookup_brand(domain: str, *,
                 status_cb: Optional[Callable[[str, dict], None]] = None
                 ) -> dict:
    """Discover official accounts + impersonation candidates for ``domain``.

    Returns {domain, official, official_count, candidates,
    variants_checked, coverage_notes, sources_status}.
    Raises ValueError for malformed domains.
    """
    d = _normalize_domain(domain)
    reset_circuit_breaker()

    sources_status: Dict[str, str] = {}

    # ---- 1. official accounts from the homepage --------------------------- #
    code, html = _fetch_homepage(d)
    official: List[Dict[str, str]] = []
    if code is None:
        sources_status["homepage"] = "error: no_response"
    elif code == 200:
        sources_status["homepage"] = "ok"
        official = _extract_official(html, d)
        if not official:
            sources_status["homepage"] = "no_results"
    else:
        sources_status["homepage"] = "blocked" if code in (401, 403, 429) \
            else "http_%d" % code
    if status_cb is not None:
        try:
            status_cb("homepage", {"status": sources_status["homepage"],
                                   "official": len(official), "domain": d})
        except Exception:
            pass

    official_by_platform: Dict[str, set] = {}
    for acc in official:
        official_by_platform.setdefault(acc["platform"], set()).add(
            acc["handle"].lower())

    # ---- 2. impersonation probes ------------------------------------------- #
    variants = _build_variants(d)
    probe_sites = [s for s in SITES if s["name"] in _PROBE_SITES]
    candidates: List[Dict[str, str]] = []
    checked_official = 0
    checks = [(site, variant) for site in probe_sites for variant in variants]
    workers = max(1, min(25, len(checks)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_probe_site, site, variant): (site, variant)
            for site, variant in checks
        }
        for fut in as_completed(futures):
            site, variant = futures[fut]
            try:
                verdict = fut.result()
            except Exception:
                verdict = "unknown"
            if verdict != "found":
                continue
            platform = site["name"].lower().replace(".", "")
            if platform == "aboutme":
                platform = "aboutme"
            handles = official_by_platform.get(platform, set())
            if variant.lower() in handles:
                checked_official += 1
                continue
            reason, severity = _candidate_reason(variant, platform, d)
            cand = {
                "platform": platform,
                "handle": variant,
                "url": site["url"].format(u=variant),
                "reason": reason,
                "severity": severity,
            }
            candidates.append(cand)
            if status_cb is not None:
                try:
                    status_cb("impersonation", cand)
                except Exception:
                    pass

    # dedupe candidates on (platform, handle)
    deduped: List[Dict[str, str]] = []
    seen: set = set()
    for cand in candidates:
        key = (cand["platform"], cand["handle"].lower())
        if key not in seen:
            seen.add(key)
            deduped.append(cand)
    # severity order: high, medium, low
    order = {"high": 0, "medium": 1, "low": 2}
    deduped.sort(key=lambda x: order.get(x.get("severity", ""), 3))

    sources_status["impersonation"] = "%d checks, %d candidates" % (
        len(checks), len(deduped))
    if checked_official:
        sources_status["official-matches"] = "%d variants match linked" \
            % checked_official

    # ---- 3. coverage notes (info only) ------------------------------------- #
    coverage_notes: List[Dict[str, str]] = []
    if official:
        present = set(official_by_platform.keys())
        for platform in _COVERAGE_PLATFORMS:
            if platform not in present:
                coverage_notes.append({
                    "note": "no official %s linked" % platform.capitalize(),
                    "severity": "info",
                })
    sources_status["coverage"] = "ok"

    return {
        "domain": d,
        "official": official,
        "official_count": len(official),
        "candidates": deduped,
        "variants_checked": variants,
        "coverage_notes": coverage_notes,
        "sources_status": sources_status,
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render_text(result: dict) -> None:
    """Print a colored human-readable brand-protection report."""
    domain = result.get("domain", "")
    official = result.get("official") or []
    candidates = result.get("candidates") or []
    variants = result.get("variants_checked") or []
    coverage = result.get("coverage_notes") or []
    sources_status = result.get("sources_status") or {}

    header("SUMMARY")
    print(f"  Domain: {c('bold')}{c('cyan')}{domain}{c('reset')}")
    tone = c("green") if official else c("yellow")
    print(f"  {tone}{len(official)} official accounts found{c('reset')}")
    if candidates:
        print(f"  {c('red')}{len(candidates)} impersonation candidates"
              f"{c('reset')}")
    else:
        print(f"  {c('green')}no impersonation candidates{c('reset')}")

    header("OFFICIAL ACCOUNTS")
    if official:
        for acc in official:
            print(f"  {c('green')}✓ {acc.get('platform'):<10}{c('reset')} "
                  f"{acc.get('handle')} {c('dim')}{acc.get('url')}"
                  f"{c('reset')}")
    else:
        print(f"  {c('gray')}none found{c('reset')}")

    header("IMPERSONATION CANDIDATES")
    if candidates:
        for cand in candidates:
            sev = str(cand.get("severity", "medium"))
            print(f"  {sev_color(sev)}[{sev.upper():<6}]{c('reset')} "
                  f"{c('bold')}{cand.get('platform')}/"
                  f"{cand.get('handle')}{c('reset')}")
            print(f"      {c('dim')}{cand.get('url')}{c('reset')}")
            print(f"      {c('gray')}{cand.get('reason')}{c('reset')}")
    else:
        print(f"  {c('green')}none{c('reset')}")

    if coverage:
        header("COVERAGE")
        for note in coverage:
            text = note.get("note") if isinstance(note, dict) else str(note)
            print(f"  {c('gray')}ℹ {text}{c('reset')}")

    header("VARIANTS CHECKED")
    print(f"  {c('gray')}{', '.join(variants) or 'n/a'}{c('reset')}")

    header("SOURCE STATUS")
    line = ", ".join(f"{k}: {v}" for k, v in sorted(sources_status.items()))
    print(f"  {c('gray')}{line or 'n/a'}{c('reset')}")
