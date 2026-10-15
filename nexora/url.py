"""Deep URL / HTTP inspection: redirect chain, DNS, TLS, security headers,
technology fingerprint and page metadata.

Fully key-free: only direct HTTP(S) requests and DNS queries. Every source
degrades gracefully and reports its outcome in ``sources_status``.
"""
from __future__ import annotations

import os
import re
import socket
import ssl
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape as html_unescape
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

from .net import http_get, resolve_a, resolve_ns, reset_circuit_breaker
from .output import c, header

# --------------------------------------------------------------------------- #
# Optional shared cache (nexora/cache.py may not exist yet)
# --------------------------------------------------------------------------- #
if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "cache.py")):
    try:
        from .cache import cache_get, cache_set  # type: ignore
    except Exception:  # cache.py half-written / broken -> no-op
        def cache_get(key: str, max_age_seconds: int) -> Any:
            return None

        def cache_set(key: str, value: Any) -> None:
            return None
else:
    def cache_get(key: str, max_age_seconds: int) -> Any:
        return None

    def cache_set(key: str, value: Any) -> None:
        return None

# --------------------------------------------------------------------------- #
# Constants / helpers
# --------------------------------------------------------------------------- #
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
_MAX_HOPS = 10
_BODY_CAP = 512 * 1024  # chars of response body kept for analysis
_DNS_CACHE_TTL = 600
_TLS_CACHE_TTL = 3600

# body substrings (checked against the lowercased response body)
_BODY_NEEDLES: Dict[str, Tuple[str, ...]] = {
    "WordPress": ("wp-content",),
    "Drupal": ("drupal",),
    "Joomla": ("joomla",),
    "React": ("react",),
    "Vue": ("vue",),
    "Angular": ("ng-version",),
    "jQuery": ("jquery",),
    "Bootstrap": ("bootstrap",),
    "Next.js": ("__next",),
    "Nuxt": ("__nuxt",),
    "Shopify": ("cdn.shopify",),
    "Wix": ("wix",),
    "Squarespace": ("squarespace",),
    "Google Analytics": ("google-analytics", "gtag", "gtag("),
    "Google Tag Manager": ("googletagmanager",),
    "Facebook Pixel": ("fbevents.js", "fbevents",),
    "reCAPTCHA": ("recaptcha",),
    "Stripe": ("js.stripe.com",),
    "Laravel": ("laravel",),
    "Django": ("csrfmiddlewaretoken",),
    "PHP": (".php",),
}

# security checklist -> (missing-label, security_headers key)
_SECURITY_CHECK: Tuple[Tuple[str, str], ...] = (
    ("HSTS", "hsts"),
    ("X-Content-Type-Options", "x_content_type_options"),
    ("X-Frame-Options", "x_frame_options"),
    ("Referrer-Policy", "referrer_policy"),
    ("Permissions-Policy", "permissions_policy"),
)

_Task = Tuple[str, Callable[[], Tuple[Any, str, str]]]


def _notify(status_cb: Optional[Callable[..., None]], source: str,
            info: Dict[str, Any]) -> None:
    """Invoke the optional progress callback; never let it break a scan."""
    if status_cb is None:
        return
    try:
        status_cb(source, info)
    except Exception:
        pass


def _safe_char(uni: str, fallback: str) -> str:
    """A unicode glyph that degrades to ASCII on consoles that can't encode it."""
    try:
        uni.encode(sys.stdout.encoding or "ascii")
        return uni
    except Exception:
        return fallback


def _cached(label: str, key_extra: str,
            fn: Callable[[], Tuple[Any, str, str]], ttl: int
            ) -> Tuple[Any, str, str]:
    """Fetch through the shared cache when available (ok/no_results only)."""
    key = f"nexora:url:{label}:{key_extra}"
    try:
        hit = cache_get(key, ttl)
    except Exception:
        hit = None
    if isinstance(hit, dict) and "value" in hit and "status" in hit:
        return hit.get("value"), str(hit.get("status")), str(hit.get("detail") or "")
    value, status, detail = fn()
    if status in ("ok", "no_results"):
        try:
            cache_set(key, {"value": value, "status": status, "detail": detail})
        except Exception:
            pass
    return value, status, detail


# --------------------------------------------------------------------------- #
# TLS helpers
# --------------------------------------------------------------------------- #
def _dn_to_str(rdns: Any) -> str:
    """Flatten an X.509 DN ((('CN', 'x'), ('O', 'y')), ...) into a string."""
    parts: List[str] = []
    try:
        for rdn in rdns or ():
            for key, value in rdn:
                parts.append(f"{key}={value}")
    except Exception:
        pass
    return ", ".join(parts)


def _common_name(rdns: Any) -> Optional[str]:
    try:
        for rdn in rdns or ():
            for key, value in rdn:
                if str(key).lower() == "commonname":
                    return str(value)
    except Exception:
        pass
    return None


def _decode_unverified_cert(der: Optional[bytes]) -> Optional[Dict[str, Any]]:
    """Parse a DER certificate without validation (stdlib, best-effort).

    ``getpeercert()`` returns an empty dict when verification is disabled, so
    the DER is written to a temp PEM file and decoded via the (private but
    long-standing) ``_ssl._test_decode_cert`` helper.
    """
    if not der:
        return None
    try:
        import _ssl  # stdlib C accelerator (ssl._ssl)
        pem = ssl.DER_cert_to_PEM_cert(der)
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(pem)
            return dict(_ssl._test_decode_cert(path) or {})
        finally:
            try:
                os.unlink(path)
            except Exception:
                pass
    except Exception:
        return None


def _cert_summary(cert: Dict[str, Any], verified: bool) -> Dict[str, Any]:
    san = [f"{kind}:{val}" for kind, val in (cert.get("subjectAltName") or ())]
    return {
        "subject_cn": _common_name(cert.get("subject")),
        "issuer": _dn_to_str(cert.get("issuer")) or None,
        "valid_from": cert.get("notBefore"),
        "valid_to": cert.get("notAfter"),
        "san": san,
        "subject_alt_names": len(san),
        "verified": bool(verified),
    }


def _collect_tls(host: str, port: int, scheme: str
                 ) -> Tuple[Optional[Dict[str, Any]], str, str]:
    """Fetch the peer certificate (verified first, then unverified retry)."""
    try:
        if scheme != "https":
            return None, "skipped: not https", ""

        verified_cert: Optional[Dict[str, Any]] = None
        first_error: Optional[BaseException] = None
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    verified_cert = ssock.getpeercert()
        except Exception as e:
            first_error = e

        if verified_cert:
            summary = _cert_summary(verified_cert, True)
            return summary, "ok", f"CN={summary.get('subject_cn') or '?'}"

        # Verification failed (self-signed / expired / timeout on verify) or
        # plain TCP failure: retry once without verification. Never disable
        # verification for the primary attempt above.
        unverified: Optional[Dict[str, Any]] = None
        try:
            ctx = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_dict = ssock.getpeercert() or {}
                    if not cert_dict:  # stdlib returns {} when unverified
                        cert_dict = _decode_unverified_cert(
                            ssock.getpeercert(binary_form=True)) or {}
                    unverified = cert_dict or None
        except Exception as e2:
            if first_error is None:
                first_error = e2

        if unverified:
            summary = _cert_summary(unverified, False)
            return summary, "ok", \
                f"unverified ({type(first_error).__name__ if first_error else 'n/a'})"
        err = type(first_error).__name__ if first_error else "no_response"
        return None, f"error: {err}", str(first_error)[:80] if first_error else ""
    except Exception as e:
        return None, f"error: {type(e).__name__}", str(e)[:80]


# --------------------------------------------------------------------------- #
# Collectors
# --------------------------------------------------------------------------- #
def _walk_redirects(start: str) -> Tuple[Dict[str, Any], Optional[Any], str, str]:
    """Follow redirect hops manually (no auto-follow), max 10 hops.

    Returns (summary, final_response, status, detail); the response object is
    kept for downstream header/tech/page analysis and never stored in the
    JSON-serializable result.
    """
    chain: List[Dict[str, Any]] = []
    seen: List[str] = []
    current = start
    resp: Optional[Any] = None
    hopped = False
    followed = 0
    status = "error: no_response"
    detail = ""

    try:
        for _ in range(_MAX_HOPS):
            if current in seen:
                hopped = True
                detail = "redirect loop detected"
                status = "ok" if chain else "error: no_response"
                break
            seen.append(current)
            r = http_get(current, allow_redirects=False, timeout=8)
            if r is None:
                detail = f"request failed: {current[:120]}"
                status = "ok" if chain else "error: no_response"
                if chain:
                    detail += " (chain incomplete)"
                break
            try:
                st = int(r.status_code)
            except Exception:
                st = 0
            loc = r.headers.get("Location")
            chain.append({"url": current, "status": st, "location": loc})
            if st in _REDIRECT_STATUSES and loc:
                hopped = True
                followed += 1
                current = urljoin(current, loc)
                continue
            resp = r
            status = "ok"
            detail = f"{followed} redirect(s)" if followed else "no redirects"
            break
        else:
            detail = f"hop limit ({_MAX_HOPS}) reached"
            status = "ok" if chain else "error: no_response"

        final_url = current
        try:
            final_url = urlunparse(urlparse(current))
        except Exception:
            pass
        summary = {
            "chain": chain,
            "redirects": followed,
            "hopped": hopped,
            "final_url": final_url,
            "status_code": resp.status_code if resp is not None else None,
        }
        return summary, resp, status, detail
    except Exception as e:
        summary = {"chain": chain, "redirects": followed, "hopped": hopped,
                   "final_url": current, "status_code": None}
        return summary, None, f"error: {type(e).__name__}", str(e)[:80]


def _collect_dns(host: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    try:
        ips = resolve_a(host)
        nameservers = resolve_ns(host)
        out = {"ip": ips[0] if ips else None, "ips": ips,
               "nameservers": nameservers}
        if ips or nameservers:
            return out, "ok", f"{len(ips)} A / {len(nameservers)} NS"
        return out, "no_results", "no A or NS records"
    except Exception as e:
        return None, f"error: {type(e).__name__}", str(e)[:80]


def _cookie_flags(raw_cookies: List[str]) -> Dict[str, Any]:
    blob = " ".join(raw_cookies).lower()
    return {
        "count": len(raw_cookies),
        "httponly": "httponly" in blob,
        "secure": "secure" in blob,
        "samesite": "samesite" in blob,
    }


def _collect_headers(resp: Optional[Any], scheme: str
                     ) -> Tuple[Optional[Dict[str, Any]], str, str]:
    try:
        if resp is None:
            return None, "error: no_response", "no final response"
        H = resp.headers

        raw_cookies: List[str] = []
        try:
            raw_cookies = [str(x) for x in resp.raw.headers.getlist("Set-Cookie")]
        except Exception:
            single = H.get("Set-Cookie")
            if single:
                raw_cookies = [str(single)]

        csp = H.get("Content-Security-Policy")
        csp_report_only = H.get("Content-Security-Policy-Report-Only")
        csp_value = csp or csp_report_only

        security_headers = {
            "hsts": H.get("Strict-Transport-Security"),
            "csp": csp_value,
            "csp_report_only": bool(csp and not csp_report_only) or bool(csp_report_only),
            "x_frame_options": H.get("X-Frame-Options"),
            "x_content_type_options": H.get("X-Content-Type-Options"),
            "referrer_policy": H.get("Referrer-Policy"),
            "permissions_policy": H.get("Permissions-Policy")
            or H.get("Feature-Policy"),
        }

        frame_ok = bool(security_headers["x_frame_options"]) or \
            ("frame-ancestors" in str(csp_value or "").lower())
        missing: List[str] = []
        for label, key in _SECURITY_CHECK:
            if label == "HSTS" and scheme != "https":
                continue  # HSTS only meaningful over https
            if label == "X-Frame-Options":
                if not frame_ok:
                    missing.append(label)
                continue
            if not security_headers.get(key):
                missing.append(label)
        score = 100 - 20 * len(missing)
        if scheme != "https":
            score = max(0, score)  # HSTS skipped -> unchanged (not penalised)

        out = {
            "server": H.get("Server"),
            "powered_by": H.get("X-Powered-By"),
            "content_type": H.get("Content-Type"),
            "content_length": H.get("Content-Length"),
            "set_cookies": _cookie_flags(raw_cookies),
            "hsts": security_headers["hsts"],
            "csp": csp_value,
            "csp_report_only": security_headers["csp_report_only"],
            "x_frame_options": security_headers["x_frame_options"],
            "x_content_type_options": security_headers["x_content_type_options"],
            "referrer_policy": security_headers["referrer_policy"],
            "permissions_policy": security_headers["permissions_policy"],
            "age": H.get("Age"),
            "cache_control": H.get("Cache-Control"),
            "via": H.get("Via"),
            "alt_svc": H.get("Alt-Svc"),
            "security_headers": security_headers,
            "headers_missing": missing,
            "security_score": max(0, min(100, score)),
        }
        return out, "ok", f"score {out['security_score']}/100"
    except Exception as e:
        return None, f"error: {type(e).__name__}", str(e)[:80]


def _detect_technologies(headers: Optional[Any], body: str) -> List[str]:
    """Substring fingerprinting of the response body + headers."""
    hdr_l: Dict[str, str] = {}
    try:
        hdr_l = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    except Exception:
        hdr_l = {}
    server = hdr_l.get("server", "")
    powered = hdr_l.get("x-powered-by", "")
    hdr_blob = " ".join(f"{k}: {v}" for k, v in hdr_l.items())
    body_l = (body or "").lower()

    found: List[str] = []

    def _add(name: str) -> None:
        if name not in found:
            found.append(name)

    if "nginx" in server:
        _add("Nginx")
    if "apache" in server:
        _add("Apache")
    if "cloudflare" in server or "cf-ray" in hdr_l:
        _add("Cloudflare")
    if "php" in powered:
        _add("PHP")
    if "asp.net" in powered:
        _add("ASP.NET")
    if "x-vercel" in hdr_l or "vercel" in server:
        _add("Vercel")
    if "x-nf-request-id" in hdr_l or "netlify" in server:
        _add("Netlify")
    if "laravel" in hdr_blob:
        _add("Laravel")
    for name, needles in _BODY_NEEDLES.items():
        if any(n in body_l for n in needles):
            _add(name)
    return sorted(found, key=str.lower)


def _collect_tech(resp: Optional[Any], body: str
                  ) -> Tuple[Optional[List[str]], str, str]:
    try:
        if resp is None:
            return [], "skipped: no final response", ""
        tech = _detect_technologies(resp.headers, body)
        if not tech:
            return [], "no_results", "nothing recognised"
        return tech, "ok", ", ".join(tech[:5])
    except Exception as e:
        return [], f"error: {type(e).__name__}", str(e)[:80]


_META_RE = re.compile(r"<meta\s+[^>]*>", re.I | re.S)


def _meta_attrs(tag: str) -> Dict[str, str]:
    return {m.group(1).lower(): m.group(2)
            for m in re.finditer(r'([a-zA-Z-]+)\s*=\s*["\']([^"\']*)["\']', tag)}


def _collect_page(body: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    try:
        if not body:
            return {}, "skipped: no response body", ""

        def _clean(text: Optional[str], limit: int = 300) -> Optional[str]:
            if not text:
                return None
            text = html_unescape(re.sub(r"<[^>]+>", " ", text))
            text = " ".join(text.split())
            return text[:limit] or None

        title = None
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
        if m:
            title = _clean(m.group(1), 200)

        generator = None
        description = None
        og_site_name = None
        og_title = None
        for tag in _META_RE.findall(body):
            attrs = _meta_attrs(tag)
            name = (attrs.get("name") or attrs.get("property") or "").lower()
            content = attrs.get("content")
            if name == "generator" and content and not generator:
                generator = content[:200]
            elif name == "description" and content and not description:
                description = _clean(content, 300)
            elif name == "og:site_name" and content and not og_site_name:
                og_site_name = _clean(content, 120)
            elif name == "og:title" and content and not og_title:
                og_title = _clean(content, 200)

        canonical = None
        for tag in re.findall(r"<(?:link|a)\s+[^>]*>", body, re.I | re.S):
            attrs = _meta_attrs(tag)
            if "canonical" in (attrs.get("rel") or "").lower() and attrs.get("href"):
                canonical = attrs["href"][:500]
                break

        forms = len(re.findall(r"<form\b", body, re.I))
        emails: List[str] = []
        for addr in re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                               body):
            if addr.lower().startswith(("mailto:", "image", "data")):
                continue
            if addr not in emails:
                emails.append(addr)
            if len(emails) >= 10:
                break
        comments = body.count("<!--")

        out = {
            "title": title,
            "generator": generator,
            "canonical": canonical,
            "description": description,
            "og_site_name": og_site_name,
            "og_title": og_title,
            "forms": forms,
            "emails": emails,
            "comments": comments,
        }
        if not any((title, generator, canonical, description, og_site_name,
                    og_title)) and not forms and not emails:
            return out, "no_results", "no title/meta/forms/emails found"
        return out, "ok", title or canonical or f"{forms} forms"
    except Exception as e:
        return None, f"error: {type(e).__name__}", str(e)[:80]


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def lookup_url(url: str, *, status_cb: Optional[Callable[..., None]] = None) -> Dict[str, Any]:
    """Inspect a URL: redirects, DNS, TLS, security headers, tech, page meta.

    ``https://`` is assumed when no scheme is given. Returns a JSON-serializable
    dict; raises ValueError for invalid input. All sources degrade gracefully.
    """
    target = str(url or "").strip()
    if not target:
        raise ValueError(f"invalid URL: {url}")
    if "://" not in target:
        target = "https://" + target
    try:
        parts = urlparse(target)
        _ = parts.port  # touching .port surfaces malformed ports as ValueError
    except ValueError:
        raise ValueError(f"invalid URL: {url}")
    except Exception:
        raise ValueError(f"invalid URL: {url}")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"invalid URL: {url}")
    try:
        start_url = urlunparse(parts)
    except Exception:
        start_url = target
    scheme = parts.scheme
    host = parts.hostname
    port = parts.port or (443 if scheme == "https" else 80)

    reset_circuit_breaker()

    sources_status: Dict[str, str] = {}
    result: Dict[str, Any] = {
        "url": start_url,
        "final_url": start_url,
        "status": None,
        "redirects": 0,
        "chain": [],
        "ip": None,
        "ips": [],
        "nameservers": [],
        "tls": None,
        "server": None,
        "security_headers": {},
        "headers_missing": [],
        "security_score": 0,
        "tech": [],
        "page": {},
        "sources_status": sources_status,
    }

    # ------------------------------------------------- concurrent sources
    walk_holder: Dict[str, Any] = {}
    resp_holder: List[Optional[Any]] = [None]

    def _task_walk() -> Tuple[Dict[str, Any], str, str]:
        summary, resp, status, detail = _walk_redirects(start_url)
        walk_holder.update(summary)
        resp_holder[0] = resp
        return summary, status, detail

    tasks: List[_Task] = [
        ("redirect-chain", _task_walk),
        ("dns", lambda: _cached("dns", host, lambda: _collect_dns(host),
                                _DNS_CACHE_TTL)),
        ("tls", lambda: _cached("tls", f"{host}:{port}",
                                lambda: _collect_tls(host, port, scheme),
                                _TLS_CACHE_TTL)),
    ]

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(fn): name for name, fn in tasks}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                value, status, detail = fut.result()
            except Exception as e:
                value, status, detail = None, f"error: {type(e).__name__}", str(e)[:80]
            sources_status[name] = status
            if name == "dns" and isinstance(value, dict):
                result["ip"] = value.get("ip")
                result["ips"] = value.get("ips") or []
                result["nameservers"] = value.get("nameservers") or []
            elif name == "tls":
                result["tls"] = value
            _notify(status_cb, name, {"status": status, "detail": detail})

    # ------------------------------------- derived from the final response
    result["chain"] = walk_holder.get("chain") or []
    result["redirects"] = int(walk_holder.get("redirects") or 0)
    result["final_url"] = walk_holder.get("final_url") or start_url
    result["status"] = walk_holder.get("status_code")

    resp = resp_holder[0]
    body = ""
    if resp is not None and getattr(resp, "status_code", None) == 200:
        try:
            body = resp.text[:_BODY_CAP]
        except Exception:
            body = ""

    for name, fn in (
        ("headers-analysis", lambda: _collect_headers(resp, scheme)),
        ("tech", lambda: _collect_tech(resp, body)),
        ("page", lambda: _collect_page(body)),
    ):
        try:
            value, status, detail = fn()
        except Exception as e:
            value, status, detail = None, f"error: {type(e).__name__}", str(e)[:80]
        sources_status[name] = status
        if name == "headers-analysis" and isinstance(value, dict):
            result["server"] = value.get("server")
            result["security_headers"] = value.get("security_headers") or {}
            result["headers_missing"] = value.get("headers_missing") or []
            result["security_score"] = int(value.get("security_score") or 0)
        elif name == "tech":
            result["tech"] = value or []
        elif name == "page":
            result["page"] = value or {}
        _notify(status_cb, name, {"status": status, "detail": detail})

    return result


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _status_color(value: str) -> str:
    if value.startswith("ok"):
        return c("green")
    if value.startswith("error"):
        return c("red")
    return c("gray")


def _code_color(code: Optional[int]) -> str:
    if code is None:
        return c("gray")
    if 200 <= code < 300:
        return c("green")
    if 300 <= code < 400:
        return c("yellow")
    return c("red")


def _parse_cert_time(text: Optional[str]) -> Optional[float]:
    if not text:
        return None
    try:
        return ssl.cert_time_to_seconds(text)
    except Exception:
        pass
    try:
        from datetime import datetime
        return datetime.strptime(text, "%b %d %H:%M:%S %Y %Z").timestamp()
    except Exception:
        return None


def render_text(result: Dict[str, Any]) -> None:
    """Print a colored human-readable URL inspection report."""
    final_url = result.get("final_url") or result.get("url") or "?"
    status_code = result.get("status")
    arrow = _safe_char("→", "->")
    check = _safe_char("✓", "[ok]")
    cross = _safe_char("✗", "[X]")

    # ---------------------------------------------------------------- SUMMARY
    header("SUMMARY")
    print(f"  URL           {c('bold')}{final_url}{c('reset')}")
    if status_code is None:
        status_txt = f"{c('gray')}no response{c('reset')}"
    else:
        status_txt = f"{_code_color(status_code)}{status_code}{c('reset')}"
    print(f"  Status        {status_txt}")
    print(f"  Redirects     {result.get('redirects') or 0}")
    print(f"  IP            {result.get('ip') or '-'}")
    print(f"  Server        {result.get('server') or '-'}")
    title = (result.get("page") or {}).get("title")
    print(f"  Title         {title or '-'}")

    # -------------------------------------------------------- REDIRECT CHAIN
    header("REDIRECT CHAIN")
    chain = result.get("chain") or []
    if not chain:
        print(f"  {c('gray')}no redirects (no response){c('reset')}")
    else:
        for hop in chain:
            if not isinstance(hop, dict):
                continue
            hop_status = hop.get("status")
            loc = hop.get("location")
            line = f"  {_code_color(hop_status)}{hop_status}{c('reset')} {hop.get('url')}"
            if loc:
                line += f" {c('cyan')}{arrow}{c('reset')} {loc}"
            print(line)
        if not (result.get("redirects") or 0):
            print(f"  {c('gray')}no redirects{c('reset')}")

    # ------------------------------------------------------------------- TLS
    header("TLS")
    tls = result.get("tls")
    tls_status = str((result.get("sources_status") or {}).get("tls") or "")
    if tls:
        print(f"  Issuer        {tls.get('issuer') or '-'}")
        now = time.time()
        for label, key in (("Valid from", "valid_from"), ("Valid to", "valid_to")):
            value = tls.get(key)
            if not value:
                print(f"  {label:<14}-")
                continue
            epoch = _parse_cert_time(value)
            expired = label == "Valid to" and epoch is not None and epoch < now
            col = c("red") if expired else c("green")
            suffix = f"  {c('red')}(EXPIRED){c('reset')}" if expired else ""
            print(f"  {label:<14}{col}{value}{c('reset')}{suffix}")
        print(f"  Subject CN    {tls.get('subject_cn') or '-'}")
        san = tls.get("san") or []
        if san:
            shown = f" {c('dim')}".join(san[:8])
            more = f" {c('dim')}+{len(san) - 8} more{c('reset')}" \
                if len(san) > 8 else ""
            print(f"  SANs          {shown}{more}")
        verified = bool(tls.get("verified"))
        v_col = c("green") if verified else c("red")
        print(f"  Verified      {v_col}{'yes' if verified else 'NO (unverified)'}{c('reset')}")
    elif tls_status.startswith("skipped"):
        print(f"  {c('gray')}({tls_status}){c('reset')}")
    else:
        print(f"  {c('gray')}(no TLS data{(' - ' + tls_status) if tls_status else ''}){c('reset')}")

    # ------------------------------------------------------ SECURITY HEADERS
    header("SECURITY HEADERS")
    sh = result.get("security_headers") or {}
    missing = result.get("headers_missing") or []
    for label, key in _SECURITY_CHECK:
        value = sh.get(key)
        if label == "X-Frame-Options" and not value \
                and "frame-ancestors" in str(sh.get("csp") or "").lower():
            value = "set via CSP frame-ancestors"
        if value:
            text = str(value)
            if len(text) > 60:
                text = text[:59] + "…"
            print(f"  {c('green')}{check}{c('reset')} {label:<24}{c('dim')}{text}{c('reset')}")
        elif label in missing:
            print(f"  {c('red')}{cross}{c('reset')} {label:<24}{c('red')}missing{c('reset')}")
        else:
            print(f"  {c('gray')}- {label:<24}(not applicable){c('reset')}")
    csp = sh.get("csp")
    if csp:
        text = str(csp)
        if len(text) > 60:
            text = text[:59] + "…"
        ro = f" {c('yellow')}(report-only){c('reset')}" if sh.get("csp_report_only") else ""
        print(f"  {c('green')}{check}{c('reset')} {'Content-Security-Policy':<24}{c('dim')}{text}{c('reset')}{ro}")
    else:
        print(f"  {c('gray')}- {'Content-Security-Policy':<24}(not present){c('reset')}")
    score = int(result.get("security_score") or 0)
    score_col = c("green") if score >= 80 else (c("yellow") if score >= 50 else c("red"))
    print(f"  Score         {score_col}{score}/100{c('reset')}")

    # --------------------------------------------------------- TECHNOLOGIES
    header("TECHNOLOGIES")
    tech = result.get("tech") or []
    if tech:
        print(f"  {', '.join(str(t) for t in tech)}")
    else:
        print(f"  {c('gray')}(none detected){c('reset')}")

    # ------------------------------------------------------------------ PAGE
    header("PAGE")
    page = result.get("page") or {}
    print(f"  Title         {page.get('title') or '-'}")
    print(f"  Canonical     {page.get('canonical') or '-'}")
    emails = page.get("emails") or []
    print(f"  Emails        {len(emails)}")
    print(f"  Forms         {page.get('forms') or 0}")

    # --------------------------------------------------------- SOURCE STATUS
    header("SOURCE STATUS")
    statuses = result.get("sources_status") or {}
    for name in sorted(statuses):
        value = str(statuses[name])
        print(f"  {name:<18}{_status_color(value)}{value}{c('reset')}")
