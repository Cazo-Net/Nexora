"""Deeper passive recon for domains.

Key-free, graceful-degrading collectors:

* robots.txt            — disallow/allow counts, sitemap URLs, rule sample
* sitemap.xml           — index vs url-list, entry count, sample URLs
* security.txt          — contacts / expiry / policy (flags expired files)
* homepage intel        — page title, harvested emails, tracker detection
* Wayback history       — oldest + newest snapshot via the CDX API
* document metadata     — PDF /Author /Title /Creator /Producer /CreationDate
                          (pypdf when installed, raw-regex fallback)
* dork helpers          — ready-made GitHub/Google/GitLab/Shodan/crt.sh
                          queries + clickable search links (no scraping)

``collect_deep()`` returns a plain JSON-serializable dict; ``render_text()``
prints a colored human-readable report that also reads fine with colors off.
"""
from __future__ import annotations

import io
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urljoin

from .net import http_get, reset_circuit_breaker
from .output import c, header

# --------------------------------------------------------------------------- #
# Constants / regexes
# --------------------------------------------------------------------------- #
_TRACKERS: Dict[str, List[str]] = {
    "Google Analytics": ["google-analytics.com", "ga.js", "gtag("],
    "Google Tag Manager": ["googletagmanager.com"],
    "Facebook Pixel": ["connect.facebook.net", "fbq("],
    "Hotjar": ["hotjar.com"],
    "Matomo/Piwik": ["matomo.js", "piwik.js"],
    "Plausible": ["plausible.io/js"],
    "Fathom": ["cdn.usefathom.com"],
    "Segment": ["cdn.segment.com"],
    "Mixpanel": ["mixpanel.com"],
    "Microsoft Clarity": ["clarity.ms"],
    "Intercom": ["intercomcdn.com", "js.intercomcdn.com"],
    "Drift": ["js.driftt.com"],
    "HubSpot": ["js.hs-scripts.com"],
    "Mailchimp": ["list-manage.com"],
    "reCAPTCHA": ["google.com/recaptcha", "recaptcha.net"],
    "Stripe": ["js.stripe.com"],
    "Sentry": ["browser.sentry-cdn.com"],
    "New Relic": ["nr-data.net"],
    "Datadog": ["datadoghq.com"],
    "TikTok Pixel": ["analytics.tiktok.com"],
    "LinkedIn Insight": ["snap.licdn.com"],
    "Pinterest Tag": ["ct.pinterest.com"],
}

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_MAILTO_RE = re.compile(r"mailto:([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.I)
_EMAIL_EXTS = (".png", ".jpg", ".gif", ".svg", ".css", ".js")
_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.I | re.S)

_PDF_STR_FIELDS = (
    ("author", rb"/Author\s*\(([^)]{1,300})\)"),
    ("title", rb"/Title\s*\(([^)]{1,300})\)"),
    ("creator", rb"/Creator\s*\(([^)]{1,300})\)"),
    ("producer", rb"/Producer\s*\(([^)]{1,300})\)"),
)
_PDF_DATE_RE = re.compile(rb"/CreationDate\s*\(([^)]{1,60})")
_META_FIELDS = ("title", "author", "creator", "producer", "creation_date")

_HOMEPAGE_CAP = 512 * 1024
_SITEMAP_CAP = 1024 * 1024
_ROBOTS_CAP = 128 * 1024
_PDF_CAP = 5 * 1024 * 1024


# --------------------------------------------------------------------------- #
# Low-level fetch helpers (never raise; always close streamed responses)
# --------------------------------------------------------------------------- #
def _read_body(url: str, timeout: int = 8, cap: int = _HOMEPAGE_CAP) -> Tuple[Optional[int], bytes]:
    """GET ``url`` with streaming; returns (status_code, body_bytes).

    status_code is None when the request failed entirely; the body is
    truncated to ``cap`` bytes.
    """
    resp = http_get(url, timeout=timeout, stream=True)
    if resp is None:
        return None, b""
    code: Optional[int] = None
    body = b""
    try:
        code = int(resp.status_code)
        if code == 200:
            buf = bytearray()
            for chunk in resp.iter_content(8192):
                if chunk:
                    buf.extend(chunk)
                if len(buf) >= cap:
                    break
            body = bytes(buf[:cap])
    except Exception:
        pass
    finally:
        try:
            resp.close()
        except Exception:
            pass
    return code, body


def _read_text(url: str, timeout: int = 8, cap: int = _HOMEPAGE_CAP) -> Tuple[Optional[int], str]:
    code, body = _read_body(url, timeout=timeout, cap=cap)
    return code, body.decode("utf-8", "ignore")


def _status_for(code: Optional[int]) -> str:
    """Map an HTTP status to a sources_status value."""
    if code is None:
        return "error: no_response"
    if code == 200:
        return "ok"
    if code in (404, 410):
        return "not_found"
    return f"http_{code}"


# --------------------------------------------------------------------------- #
# 1. robots.txt
# --------------------------------------------------------------------------- #
def _collect_robots(domain: str) -> Tuple[dict, str]:
    data: Dict[str, Any] = {"found": False, "disallow_count": 0,
                            "allow_count": 0, "sitemaps": [], "rules_sample": []}
    code: Optional[int] = None
    text = ""
    for scheme in ("https", "http"):
        code, text = _read_text(f"{scheme}://{domain}/robots.txt",
                                timeout=8, cap=_ROBOTS_CAP)
        if code is not None:
            break
    if code != 200:
        return data, _status_for(code)

    disallow = allow = 0
    sitemaps: List[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        low = stripped.lower()
        if low.startswith("disallow:"):
            disallow += 1
        elif low.startswith("allow:"):
            allow += 1
        elif low.startswith("sitemap:"):
            value = stripped.split(":", 1)[1].strip()
            if value:
                sitemaps.append(value)
    data = {
        "found": True,
        "disallow_count": disallow,
        "allow_count": allow,
        "sitemaps": sitemaps[:20],
        "rules_sample": [ln.strip() for ln in text.splitlines() if ln.strip()][:8],
    }
    if not (disallow or allow or sitemaps):
        return data, "no_results"
    return data, "ok"


# --------------------------------------------------------------------------- #
# 2. sitemap (depends on robots sitemap URLs)
# --------------------------------------------------------------------------- #
def _collect_sitemap(domain: str, robots_sitemaps: List[str]) -> Tuple[dict, str]:
    url = robots_sitemaps[0] if robots_sitemaps else f"https://{domain}/sitemap.xml"
    data: Dict[str, Any] = {"url": url, "is_index": False,
                            "entry_count": 0, "sample": []}
    code, text = _read_text(url, timeout=10, cap=_SITEMAP_CAP)
    if code != 200:
        return data, _status_for(code)

    body = text.lstrip("\ufeff \t\r\n")
    is_index = body.startswith("<?xml") and "<sitemapindex" in body
    locs = [m.strip() for m in _LOC_RE.findall(text) if m.strip()]
    if is_index:
        data["is_index"] = True
        data["entry_count"] = min(len(locs), 10000)  # children are NOT fetched
        return data, "ok"
    data["is_index"] = False
    data["entry_count"] = min(len(locs), 500)
    data["sample"] = locs[:10]
    if not locs:
        return data, "no_results"
    return data, "ok"


# --------------------------------------------------------------------------- #
# 3. security.txt
# --------------------------------------------------------------------------- #
def _collect_security_txt(domain: str) -> Tuple[dict, str]:
    data: Dict[str, Any] = {"found": False, "url": None, "contacts": [],
                            "expires": None, "policy": None,
                            "acknowledgments": []}
    saw_200 = False
    last_code: Optional[int] = None
    for path in ("/.well-known/security.txt", "/security.txt"):
        url = f"https://{domain}{path}"
        code, text = _read_text(url, timeout=8, cap=64 * 1024)
        if code is not None:
            last_code = code
        if code != 200:
            continue
        saw_200 = True
        if not text.strip():
            continue
        contacts: List[str] = []
        acks: List[str] = []
        expires: Optional[str] = None
        policy: Optional[str] = None
        for line in text.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            value = value.strip()
            field = key.strip().lower()
            if not value:
                continue
            if field == "contact":
                contacts.append(value)
            elif field == "expires":
                expires = value
            elif field == "policy":
                policy = value
            elif field == "acknowledgments":
                acks.append(value)
        data = {"found": True, "url": url, "contacts": contacts,
                "expires": expires, "policy": policy, "acknowledgments": acks}
        return data, "ok"
    if saw_200:
        return data, "no_results"
    if last_code is None:
        return data, "error: no_response"
    return data, _status_for(last_code)


# --------------------------------------------------------------------------- #
# 4. homepage intel (title / emails / trackers) — keeps raw HTML for PDFs
# --------------------------------------------------------------------------- #
def _collect_homepage(domain: str) -> Tuple[dict, str]:
    url = f"https://{domain}/"
    code, body = _read_body(url, timeout=10, cap=_HOMEPAGE_CAP)
    if code is None:
        url = f"http://{domain}/"
        code, body = _read_body(url, timeout=10, cap=_HOMEPAGE_CAP)
    data: Dict[str, Any] = {"url": url, "title": None, "emails": [],
                            "trackers": [], "_html": ""}
    if code != 200:
        return data, _status_for(code)

    html = body.decode("utf-8", "ignore")
    data["_html"] = html

    title_match = _TITLE_RE.search(html)
    if title_match:
        title = re.sub(r"\s+", " ", title_match.group(1)).strip()
        data["title"] = title[:200] or None

    emails: List[str] = []
    seen: set = set()
    candidates = _MAILTO_RE.findall(html) + _EMAIL_RE.findall(html)
    for match in candidates:
        email = match.strip().rstrip(".,;:)>")
        low = email.lower()
        if any(low.endswith(ext) for ext in _EMAIL_EXTS):
            continue
        if low in seen:
            continue
        seen.add(low)
        emails.append(email)
        if len(emails) >= 20:
            break
    data["emails"] = emails

    lowered = html.lower()
    data["trackers"] = [
        name for name, needles in _TRACKERS.items()
        if any(n.lower() in lowered for n in needles)
    ][:30]
    return data, "ok"


# --------------------------------------------------------------------------- #
# 5. Wayback (CDX) — oldest + newest snapshot
# --------------------------------------------------------------------------- #
def _collect_wayback(domain: str) -> Tuple[dict, str]:
    empty: Dict[str, Any] = {"timestamp": None, "url": None,
                             "status": None, "archive_link": None}

    def _cdx(limit: str) -> Tuple[Optional[int], Any]:
        resp = None
        try:
            resp = http_get(
                "https://web.archive.org/cdx/search/cdx",
                params={"url": domain, "output": "json",
                        "fl": "timestamp,original,statuscode",
                        "limit": limit, "from": "1996"},
                timeout=15,
            )
            if resp is None:
                return None, None
            code = int(resp.status_code)
            if code != 200:
                return code, None
            try:
                return code, resp.json()
            except Exception:
                return code, None
        except Exception:
            return None, None
        finally:
            if resp is not None:
                try:
                    resp.close()
                except Exception:
                    pass

    def _parse(rows: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(rows, list) or not rows:
            return None
        start = 0
        head = rows[0]
        if isinstance(head, list) and head and head[0] == "timestamp":
            start = 1
        if len(rows) <= start:
            return None
        row = rows[start]
        if not isinstance(row, list) or not row:
            return None
        ts = str(row[0]) if len(row) > 0 and row[0] else None
        original = str(row[1]) if len(row) > 1 and row[1] else None
        status = str(row[2]) if len(row) > 2 and row[2] else None
        if not ts and not original:
            return None
        link = f"https://web.archive.org/web/{ts}/{domain}" if ts else None
        return {"timestamp": ts, "url": original, "status": status,
                "archive_link": link}

    code_first, rows_first = _cdx("1")
    code_last, rows_last = _cdx("-1")
    first = _parse(rows_first)
    last = _parse(rows_last)
    data = {"first": first or dict(empty), "last": last or dict(empty)}

    if first is not None or last is not None:
        return data, "ok"
    codes = (code_first, code_last)
    if any(cd == 200 for cd in codes):
        return data, "no_results"
    if all(cd is None for cd in codes):
        return data, "error: no_response"
    non_ok = [cd for cd in codes if cd is not None]
    return data, _status_for(non_ok[-1])


# --------------------------------------------------------------------------- #
# 6. PDF / document metadata (no hard dependency — pypdf optional, regex back)
# --------------------------------------------------------------------------- #
def _clean_pdf_value(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    if isinstance(raw, bytes):
        if raw.startswith(b"\xfe\xff"):
            try:
                text = raw.decode("utf-16-be", "ignore")
            except Exception:
                text = raw.decode("latin-1", "ignore")
        else:
            text = raw.decode("latin-1", "ignore")
    else:
        text = str(raw)
    text = text.replace("\\(", "(").replace("\\)", ")").replace("\\\\", "\\")
    text = text.replace("\x00", "")
    text = " ".join(text.split())
    return text[:200] if text else None


def _pdf_date(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    v = value.strip()
    m = re.match(r"D?:?(\d{4})(\d{2})(\d{2})", v)
    if not m:
        m = re.search(r"(\d{4})[-/]?(\d{2})[-/]?(\d{2})", v)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    return v[:40] or None


def _pdf_metadata(data: bytes) -> Dict[str, Optional[str]]:
    out: Dict[str, Optional[str]] = {"title": None, "author": None,
                                     "creator": None, "producer": None,
                                     "creation_date": None}
    # 1) pypdf when available (handles compressed / cross-referenced Info dicts)
    try:
        from pypdf import PdfReader  # type: ignore
        reader = PdfReader(io.BytesIO(data))
        info = reader.metadata
        if info is not None:
            out["title"] = _clean_pdf_value(getattr(info, "title", None))
            out["author"] = _clean_pdf_value(getattr(info, "author", None))
            out["creator"] = _clean_pdf_value(getattr(info, "creator", None))
            out["producer"] = _clean_pdf_value(getattr(info, "producer", None))
            created = getattr(info, "creation_date", None)
            if created is not None:
                try:
                    out["creation_date"] = created.date().isoformat() \
                        if hasattr(created, "date") else _pdf_date(str(created))
                except Exception:
                    out["creation_date"] = _pdf_date(str(created))
    except Exception:
        pass
    # 2) regex fallback over the raw bytes (uncompressed Info dicts)
    for key, pattern in _PDF_STR_FIELDS:
        if out.get(key):
            continue
        m = re.search(pattern, data)
        if m:
            out[key] = _clean_pdf_value(m.group(1))
    if not out.get("creation_date"):
        m = _PDF_DATE_RE.search(data)
        if m:
            out["creation_date"] = _pdf_date(_clean_pdf_value(m.group(1)))
    return out


def _collect_documents(domain: str, homepage: dict, sitemap: dict,
                       html: str) -> Tuple[List[dict], str]:
    pdf_urls: List[str] = []

    def _add(candidate: Optional[str]) -> None:
        if not candidate or len(pdf_urls) >= 5:
            return
        clean = str(candidate).split("#", 1)[0].strip()
        if not clean.split("?", 1)[0].lower().endswith(".pdf"):
            return
        if clean not in pdf_urls:
            pdf_urls.append(clean)

    base = f"https://{domain}/"
    if html:
        for match in re.findall(
                r"""(?:href|src)\s*=\s*["']([^"']+\.pdf(?:\?[^"']*)?)["']""",
                html, re.I):
            try:
                _add(urljoin(base, match))
            except Exception:
                pass
        for match in re.findall(
                r"""https?://[^\s"'<>()]+\.pdf(?:\?[^\s"'<>()]+)?""", html, re.I):
            _add(match)
    for entry in (sitemap or {}).get("sample") or []:
        _add(entry)

    if not pdf_urls:
        return [], "no_results"

    documents: List[dict] = []
    failures = 0
    for url in pdf_urls:
        code, data = _read_body(url, timeout=15, cap=_PDF_CAP)
        if code != 200 or not data:
            failures += 1
            continue
        is_pdf = data[:4] == b"%PDF"
        meta = _pdf_metadata(data)
        has_fields = any(meta.get(k) for k in _META_FIELDS)
        if not is_pdf and not has_fields:
            continue
        documents.append({
            "url": url,
            "size": len(data),
            "title": meta.get("title"),
            "author": meta.get("author"),
            "creator": meta.get("creator"),
            "producer": meta.get("producer"),
            "creation_date": meta.get("creation_date"),
        })

    if documents:
        return documents, "ok"
    if failures:
        return documents, "error: fetch_failed"
    return documents, "no_results"


# --------------------------------------------------------------------------- #
# 7. Dork helpers (query strings only — nothing is scraped)
# --------------------------------------------------------------------------- #
def _build_dorks(domain: str) -> Dict[str, Any]:
    github = [
        f'"{domain}" password',
        f'"{domain}" api_key',
        f'"{domain}" secret',
        f'"{domain}" aws_key',
        f'"{domain}" filename:.env',
        f'"{domain}" filename:id_rsa',
        f'"{domain}" "Authorization: Bearer"',
        f'"{domain}" error',
    ]
    google = [
        f"site:{domain} ext:pdf",
        f"site:{domain} filetype:env",
        f"site:{domain} inurl:admin",
        f'site:{domain} intitle:"index of"',
        f'"{domain}" site:pastebin.com',
        f'"{domain}" site:github.com',
    ]
    gitlab = [
        f'"{domain}" password',
        f'"{domain}" filename:.gitlab-ci.yml',
    ]
    shodan = [f'hostname:"{domain}"']
    links = {
        "github_search": "https://github.com/search?q=" + quote(github[0]) + "&type=code",
        "google_search": "https://www.google.com/search?q=" + quote(google[0]),
        "crtsh": f"https://crt.sh/?q=%25.{domain}",
    }
    return {"github": github, "google": google, "gitlab": gitlab,
            "shodan": shodan, "crtsh": domain, "links": links}


# --------------------------------------------------------------------------- #
# Empty fallbacks (used when a collector blows up despite the guards)
# --------------------------------------------------------------------------- #
def _empty_robots() -> dict:
    return {"found": False, "disallow_count": 0, "allow_count": 0,
            "sitemaps": [], "rules_sample": []}


def _empty_sitemap() -> dict:
    return {"url": None, "is_index": False, "entry_count": 0, "sample": []}


def _empty_security() -> dict:
    return {"found": False, "url": None, "contacts": [], "expires": None,
            "policy": None, "acknowledgments": []}


def _empty_homepage() -> dict:
    return {"url": None, "title": None, "emails": [], "trackers": []}


def _empty_wayback() -> dict:
    snap = {"timestamp": None, "url": None, "status": None, "archive_link": None}
    return {"first": dict(snap), "last": dict(snap)}


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def collect_deep(domain: str, *,
                 status_cb: Optional[Callable[[str, dict], None]] = None) -> dict:
    """Run all deep-recon collectors for ``domain``.

    Returns a JSON-serializable dict: domain, robots, sitemap, security_txt,
    homepage, wayback, documents, dorks, sources_status. Every source
    degrades gracefully — failures land in ``sources_status`` as
    ``"ok"`` / ``"no_results"`` / ``"not_found"`` / ``"http_404"`` /
    ``"error: ..."``.
    """
    domain = (domain or "").strip().lower()
    if not domain:
        raise ValueError("invalid domain: %r" % (domain,))
    reset_circuit_breaker()

    sources_status: Dict[str, str] = {}

    def _settle(future, name: str, empty) -> Any:
        try:
            data, status = future.result()
        except Exception as exc:  # pragma: no cover — collectors self-guard
            data, status = empty, f"error: {type(exc).__name__}"
        sources_status[name] = status
        if status_cb is not None:
            try:
                status_cb(name, {"status": status, "domain": domain})
            except Exception:
                pass
        return data

    with ThreadPoolExecutor(max_workers=6) as pool:
        fut_robots = pool.submit(_collect_robots, domain)
        fut_security = pool.submit(_collect_security_txt, domain)
        fut_homepage = pool.submit(_collect_homepage, domain)
        fut_wayback = pool.submit(_collect_wayback, domain)

        robots = _settle(fut_robots, "robots", _empty_robots())
        sitemap_list = robots.get("sitemaps") or [] if isinstance(robots, dict) else []
        fut_sitemap = pool.submit(_collect_sitemap, domain, sitemap_list)

        security_txt = _settle(fut_security, "security_txt", _empty_security())
        homepage = _settle(fut_homepage, "homepage", _empty_homepage())
        wayback = _settle(fut_wayback, "wayback", _empty_wayback())
        sitemap = _settle(fut_sitemap, "sitemap", _empty_sitemap())

        html = homepage.pop("_html", "") if isinstance(homepage, dict) else ""
        fut_docs = pool.submit(_collect_documents, domain, homepage, sitemap, html)
        documents = _settle(fut_docs, "documents", [])

    dorks = _build_dorks(domain)
    sources_status["dorks"] = "ok"
    if status_cb is not None:
        try:
            status_cb("dorks", {"status": "ok", "domain": domain})
        except Exception:
            pass

    return {
        "domain": domain,
        "robots": robots,
        "sitemap": sitemap,
        "security_txt": security_txt,
        "homepage": homepage,
        "wayback": wayback,
        "documents": documents,
        "dorks": dorks,
        "sources_status": sources_status,
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _parse_iso(value: Any) -> Optional[datetime]:
    try:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        return None


def _fmt_timestamp(ts: Any) -> str:
    digits = "".join(ch for ch in str(ts) if ch.isdigit())
    if len(digits) >= 14:
        return (f"{digits[0:4]}-{digits[4:6]}-{digits[6:8]} "
                f"{digits[8:10]}:{digits[10:12]}")
    if len(digits) >= 8:
        return f"{digits[0:4]}-{digits[4:6]}-{digits[6:8]}"
    return str(ts)


def render_text(result: dict) -> None:
    """Print a colored human-readable deep-recon report."""
    domain = result.get("domain", "")
    status = result.get("sources_status") or {}

    # ROBOTS.TXT
    header("ROBOTS.TXT")
    robots = result.get("robots") or {}
    if robots.get("found"):
        print(f"  {c('green')}found{c('reset')}   "
              f"Disallow: {robots.get('disallow_count', 0)}   "
              f"Allow: {robots.get('allow_count', 0)}")
        for sitemap_url in (robots.get("sitemaps") or [])[:10]:
            print(f"  {c('cyan')}sitemap{c('reset')} {c('dim')}{sitemap_url}{c('reset')}")
        sample = robots.get("rules_sample") or []
        if sample:
            print(f"  {c('dim')}sample:{c('reset')}")
            for line in sample:
                print(f"    {c('dim')}{line}{c('reset')}")
    else:
        print(f"  {c('gray')}not found{c('reset')}")

    # SITEMAP
    header("SITEMAP")
    sitemap = result.get("sitemap") or {}
    sitemap_status = status.get("sitemap", "")
    if sitemap_status in ("ok", "no_results") and sitemap.get("url"):
        kind = "sitemap index" if sitemap.get("is_index") else "url list"
        print(f"  {sitemap.get('entry_count', 0)} entries ({kind})")
        print(f"  {c('dim')}{sitemap.get('url')}{c('reset')}")
        for entry_url in (sitemap.get("sample") or [])[:6]:
            print(f"    {c('dim')}{entry_url}{c('reset')}")
    else:
        print(f"  {c('gray')}not found "
              f"({sitemap_status or 'unknown'}){c('reset')}")

    # SECURITY.TXT
    header("SECURITY.TXT")
    security = result.get("security_txt") or {}
    if security.get("found"):
        for contact in security.get("contacts") or []:
            print(f"  {c('cyan')}contact{c('reset')} {contact}")
        expires = security.get("expires")
        if expires:
            exp_dt = _parse_iso(expires)
            if exp_dt is None:
                expiry_color, tag = c("gray"), ""
            elif exp_dt < datetime.now(timezone.utc):
                expiry_color, tag = c("red"), " (EXPIRED)"
            else:
                expiry_color, tag = c("green"), ""
            print(f"  {expiry_color}expires{c('reset')} {expires}{tag}")
        if security.get("policy"):
            print(f"  {c('cyan')}policy{c('reset')} "
                  f"{c('dim')}{security['policy']}{c('reset')}")
        if security.get("url"):
            print(f"  {c('dim')}{security['url']}{c('reset')}")
    else:
        print(f"  {c('gray')}not found{c('reset')}")

    # HOMEPAGE
    header("HOMEPAGE")
    homepage = result.get("homepage") or {}
    emails = homepage.get("emails") or []
    trackers = homepage.get("trackers") or []
    if homepage.get("title") or emails or trackers:
        if homepage.get("title"):
            print(f"  {c('bold')}{homepage['title']}{c('reset')}")
        print(f"  {c('cyan')}emails{c('reset')} {len(emails)}")
        for email in emails[:10]:
            print(f"    {c('dim')}{email}{c('reset')}")
        if len(emails) > 10:
            print(f"    {c('gray')}... and {len(emails) - 10} more{c('reset')}")
        if trackers:
            print(f"  {c('yellow')}trackers{c('reset')} {', '.join(trackers)}")
        else:
            print(f"  {c('gray')}trackers: none detected{c('reset')}")
    else:
        print(f"  {c('gray')}unavailable ({status.get('homepage', 'unknown')}){c('reset')}")

    # WAYBACK
    header("WAYBACK")
    wayback = result.get("wayback") or {}
    for label in ("first", "last"):
        entry = wayback.get(label) or {}
        timestamp = entry.get("timestamp")
        if timestamp:
            when = _fmt_timestamp(timestamp)
            print(f"  {label:<6}{c('dim')}{when}  "
                  f"{entry.get('archive_link')}{c('reset')}")
        else:
            print(f"  {label:<6}{c('gray')}unknown{c('reset')}")

    # DOCUMENT METADATA
    header("DOCUMENT METADATA")
    documents = result.get("documents") or []
    if documents:
        for doc in documents:
            print(f"  {c('bold')}{doc.get('url')}{c('reset')} "
                  f"{c('gray')}({doc.get('size', 0)} bytes){c('reset')}")
            for field in ("author", "creator", "producer", "creation_date", "title"):
                value = doc.get(field)
                if value:
                    print(f"    {c('dim')}{field}: {value}{c('reset')}")
    else:
        print(f"  {c('gray')}no PDF metadata collected{c('reset')}")

    # DORK SUGGESTIONS
    header("DORK SUGGESTIONS")
    dorks = result.get("dorks") or {}
    for key, label in (("github", "GitHub"), ("google", "Google"),
                       ("gitlab", "GitLab"), ("shodan", "Shodan")):
        queries = dorks.get(key) or []
        if not queries:
            continue
        print(f"  {c('bold')}{label}{c('reset')}")
        for query in queries:
            print(f"    {c('gray')}{query}{c('reset')}")
    print(f"  {c('bold')}crt.sh{c('reset')}")
    print(f"    {c('gray')}{dorks.get('crtsh') or domain}{c('reset')}")
    links = dorks.get("links") or {}
    if links:
        print(f"  {c('bold')}Quick links{c('reset')}")
        for name, link in links.items():
            print(f"    {c('cyan')}{name}{c('reset')} {c('dim')}{link}{c('reset')}")

    # SOURCE STATUS
    header("SOURCE STATUS")
    for key in sorted(status):
        print(f"  {c('gray')}{key}: {status[key]}{c('reset')}")
