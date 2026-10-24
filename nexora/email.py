"""email address OSINT (validation, MX/SPF/DMARC/DKIM analysis, gravatar, breach check, disposable detection, username guesses)."""
from __future__ import annotations

import dataclasses
import hashlib
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple

from .advanced import _collect_email_security
from .net import http_get, reset_circuit_breaker, resolve_txt
from .output import c, header

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

_DISPOSABLE_URL = ("https://raw.githubusercontent.com/disposable/"
                   "disposable-email-domains/master/"
                   "disposable_email_blocklist.conf")
_DISPOSABLE_TTL = 6 * 3600  # 6 hours
_DISPOSABLE_CACHE: Dict[str, Any] = {"ts": 0.0, "domains": set()}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _notify(status_cb: Optional[Callable[..., None]], source: str,
            info: Dict[str, Any]) -> None:
    """Invoke the optional progress callback; never let it break a lookup."""
    if status_cb is None:
        return
    try:
        status_cb(source, info)
    except Exception:
        pass


def _clip(text: Optional[str], limit: int = 80) -> str:
    if not text:
        return ""
    text = " ".join(str(text).split())
    return text[: limit - 1] + "…" if len(text) > limit else text


def _checkmark() -> str:
    """A ✓ that degrades to ASCII on consoles that can't encode it."""
    try:
        "\u2713".encode(sys.stdout.encoding or "ascii")
        return "\u2713"
    except Exception:
        return "[ok]"


# --------------------------------------------------------------------------- #
# Collectors — each returns (value, status, detail) and never raises
# --------------------------------------------------------------------------- #
def _collect_security(domain: str, sources_status: Dict[str, str]
                      ) -> Tuple[Optional[Dict[str, Any]], str, str]:
    """Run the shared MX/SPF/DMARC/DKIM analyzer from nexora.advanced."""
    try:
        es = _collect_email_security(domain, sources_status)
    except Exception as e:
        sources_status["email-security"] = f"error: {type(e).__name__}"
        return None, sources_status["email-security"], str(e)[:80]
    if es is None:
        sources_status["email-security"] = "no_results"
        return None, "no_results", "no DNS security data"
    status = sources_status.get("email-security", "ok")
    data = dataclasses.asdict(es)
    detail = f"score {data.get('score', 0)}/100"
    return data, status, detail


def _collect_gravatar(email: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    digest = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    out: Dict[str, Any] = {
        "hash": digest,
        "exists": None,
        "avatar_url": f"https://www.gravatar.com/avatar/{digest}",
        "profile_url": f"https://www.gravatar.com/{digest}",
        "display_name": None,
        "location": None,
        "about": None,
        "preferred_username": None,
    }

    resp = http_get(f"https://www.gravatar.com/avatar/{digest}?d=404", timeout=8)
    if resp is None:
        return out, "error: no_response", "Gravatar unreachable"
    out["exists"] = resp.status_code == 200
    if resp.status_code == 404:
        return out, "no_results", "no Gravatar for this address"
    if resp.status_code != 200:
        out["exists"] = None
        return out, f"http_{resp.status_code}", ""

    # Avatar exists — fetch the public profile JSON.
    prof = http_get(f"https://www.gravatar.com/{digest}.json", timeout=8)
    if prof is not None and prof.status_code == 200:
        try:
            data = prof.json()
            entry = data[0] if isinstance(data, list) and data else {}
            if isinstance(entry, dict):
                out["display_name"] = entry.get("display_name")
                out["location"] = entry.get("location")
                out["about"] = entry.get("about")
                out["preferred_username"] = entry.get("preferred_username")
                if entry.get("profile_url"):
                    out["profile_url"] = entry["profile_url"]
        except Exception:
            pass
    detail = out.get("display_name") or "avatar found"
    return out, "ok", _clip(str(detail), 60)


def _collect_breach(email: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    resp = http_get(f"https://api.xposedornot.com/v1/check-email/{email}",
                    timeout=10)
    if resp is None:
        return ({"source": "XposedOrNot", "breach_count": None,
                 "breaches": [], "status": "error: no_response"},
                "error: no_response", "breach service unreachable")
    if resp.status_code != 200:
        return ({"source": "XposedOrNot", "breach_count": 0,
                 "breaches": [], "status": "unavailable"},
                f"http_{resp.status_code}", "breach service unavailable")
    try:
        data = resp.json() or {}
    except Exception:
        return ({"source": "XposedOrNot", "breach_count": None,
                 "breaches": [], "status": "error: invalid_json"},
                "error: invalid_json", "")

    if isinstance(data, dict) and data.get("Breaches"):
        raw = data["Breaches"]
        if isinstance(raw, str):
            raw = [raw]
        breaches: List[str] = []
        for entry in raw:
            for name in str(entry).split(";"):
                name = name.strip()
                if name and name not in breaches:
                    breaches.append(name)
                if len(breaches) >= 25:
                    break
            if len(breaches) >= 25:
                break
        out = {"source": "XposedOrNot", "breach_count": len(breaches),
               "breaches": breaches, "status": "ok"}
        return out, "ok", f"{len(breaches)} breaches"

    if isinstance(data, dict) and data.get("Errors"):
        return ({"source": "XposedOrNot", "breach_count": 0,
                 "breaches": [], "status": "no_breaches"},
                "no_breaches", "no known breaches")
    return ({"source": "XposedOrNot", "breach_count": 0,
             "breaches": [], "status": "unavailable"},
            "unavailable", "unexpected API response")


def _collect_disposable(domain: str) -> Tuple[Optional[bool], str, str]:
    """Check the domain against a cached disposable-domain blocklist (6h TTL)."""
    domain = domain.lower().strip()
    now = time.time()
    cached: set = _DISPOSABLE_CACHE["domains"]
    fresh = bool(cached) and (now - float(_DISPOSABLE_CACHE["ts"])) < _DISPOSABLE_TTL

    if not fresh:
        resp = http_get(_DISPOSABLE_URL, timeout=20)
        if resp is not None and resp.status_code == 200:
            try:
                lines = resp.text.splitlines()
                domains = {ln.strip().lower() for ln in lines if ln.strip()
                           and not ln.startswith("#")}
                if domains:
                    _DISPOSABLE_CACHE["domains"] = domains
                    _DISPOSABLE_CACHE["ts"] = time.time()
                    cached = domains
                    fresh = True
            except Exception:
                pass

    if not cached:
        return None, "unavailable", "blocklist unreachable"
    is_disp = domain in cached
    status = "ok" if fresh else "ok (cached)"
    return is_disp, status, "disposable" if is_disp else "legitimate domain"


def _collect_platforms(email: str, sources_status: Dict[str, str]
                       ) -> Tuple[Optional[Dict[str, Any]], str, str]:
    """Find internet platforms connected to this address (nexora.platforms).

    Uses the module-level ``http_get`` so tests that patch it stay inert.
    """
    try:
        from .platforms import platforms_for_email
        bundle = platforms_for_email(email, getter=http_get)
    except ValueError as e:
        sources_status["platforms"] = "error: invalid_input"
        return None, sources_status["platforms"], str(e)[:80]
    except Exception as e:
        sources_status["platforms"] = f"error: {type(e).__name__}"
        return None, sources_status["platforms"], str(e)[:80]
    for key, value in (bundle.get("sources_status") or {}).items():
        sources_status[f"pf-{key}"] = value
    count = int(bundle.get("platform_count") or 0)
    status = "ok" if count else "no_results"
    detail = f"{count} platform link(s)"
    return bundle, status, detail


def _collect_rdap(domain: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    """Registry record via RDAP (org, registrar, dates, abuse contact)."""
    resp = http_get(f"https://rdap.org/domain/{domain}", timeout=10)
    if resp is None:
        return None, "error: no_response", "RDAP unreachable"
    if resp.status_code == 404:
        return None, "no_results", "no registry data for this domain"
    if resp.status_code != 200:
        return None, f"http_{resp.status_code}", ""
    try:
        data = resp.json() or {}
    except Exception:
        return None, "error: invalid_json", ""
    if not isinstance(data, dict):
        return None, "no_results", ""

    out: Dict[str, Any] = {"domain": domain}
    events = {str(ev.get("eventAction") or ""): str(ev.get("eventDate") or "")
              for ev in (data.get("events") or []) if isinstance(ev, dict)}
    out["created"] = events.get("registration") or None
    out["updated"] = events.get("last changed") or events.get("last update") or None
    statuses = [str(s) for s in (data.get("status") or [])]
    out["statuses"] = statuses[:8]

    def _vcard(entity: Dict[str, Any], key: str) -> Optional[str]:
        try:
            for item in (entity.get("vcardArray") or [None, []])[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] == key:
                    value = item[3]
                    if isinstance(value, list):
                        value = " ".join(str(v) for v in value if v)
                    return _clip(str(value), 80) or None
        except Exception:
            return None
        return None

    for entity in (data.get("entities") or []):
        if not isinstance(entity, dict):
            continue
        roles = [str(r).lower() for r in (entity.get("roles") or [])]
        if "registrar" in roles and not out.get("registrar"):
            out["registrar"] = _vcard(entity, "fn")
        if "registrant" in roles and not out.get("registrant_org"):
            out["registrant_org"] = _vcard(entity, "fn")
        if "abuse" in roles and not out.get("abuse_email"):
            out["abuse_email"] = _vcard(entity, "email")
            out["abuse_name"] = _vcard(entity, "fn")

    known = bool(out.get("registrar") or out.get("registrant_org")
                 or out.get("created") or out.get("abuse_email"))
    if not known:
        return None, "no_results", "registry record without entity data"
    detail = out.get("registrar") or out.get("registrant_org") or "registry data"
    return out, "ok", _clip(str(detail), 60)


def _collect_bimi(domain: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    """BIMI record (brand logo alignment) — DNS only."""
    try:
        records = resolve_txt(f"default._bimi.{domain}")
    except Exception as e:
        return None, f"error: {type(e).__name__}", ""
    for record in records or []:
        if str(record).lower().startswith("v=bimi1"):
            return {"record": _clip(str(record), 120)}, "ok", "BIMI published"
    return None, "no_results", "no BIMI record"


def _username_guesses(local: str) -> List[str]:
    candidates = [
        local,
        local.replace(".", ""),
        local.replace(".", "_"),
        local.split(".")[0],
    ]
    out: List[str] = []
    for cand in candidates:
        cand = cand.strip().lower()
        if cand and cand not in out:
            out.append(cand)
        if len(out) >= 6:
            break
    return out


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def lookup_email(email: str, *,
                 status_cb: Optional[Callable[..., None]] = None) -> Dict[str, Any]:
    """Run OSINT collectors for an email address.

    Returns a JSON-serializable dict. Raises ValueError for invalid input.
    """
    email = (email or "").strip()
    if not _EMAIL_RE.match(email):
        raise ValueError(f"invalid email address: {email}")
    local, _, domain = email.rpartition("@")

    reset_circuit_breaker()

    sources_status: Dict[str, str] = {}
    guesses = _username_guesses(local)

    # (source name, result key, collector)
    tasks: List[Tuple[str, str, Callable[[], Tuple[Any, str, str]]]] = [
        ("email-security", "email_security",
         lambda: _collect_security(domain, sources_status)),
        ("gravatar", "gravatar", lambda: _collect_gravatar(email)),
        ("breach-check", "breach_check", lambda: _collect_breach(email)),
        ("disposable", "is_disposable", lambda: _collect_disposable(domain)),
        ("platforms", "_platforms_bundle",
         lambda: _collect_platforms(email, sources_status)),
        ("rdap", "rdap", lambda: _collect_rdap(domain)),
        ("bimi", "bimi", lambda: _collect_bimi(domain)),
    ]

    result: Dict[str, Any] = {
        "email": email,
        "domain": domain,
        "valid": True,
        "is_disposable": None,
        "username_guesses": guesses,
        "email_security": None,
        "gravatar": None,
        "breach_check": None,
        "connected_platforms": [],
        "dorks": [],
        "rdap": None,
        "bimi": None,
        "sources_status": sources_status,
    }

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(fn): (name, key) for name, key, fn in tasks}
        for fut in as_completed(futures):
            name, key = futures[fut]
            try:
                value, status, detail = fut.result()
            except Exception as e:
                value, status, detail = None, f"error: {type(e).__name__}", str(e)[:80]
            if key != "email_security":  # security collector sets its own status
                sources_status[name] = status
            result[key] = value
            _notify(status_cb, name, {"status": status, "detail": detail})

    # Flatten the platform bundle into first-class result keys.
    bundle = result.pop("_platforms_bundle", None)
    if isinstance(bundle, dict):
        result["connected_platforms"] = bundle.get("platforms") or []
        result["dorks"] = bundle.get("dorks") or []

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


def render_text(result: Dict[str, Any]) -> None:
    """Print a colored human-readable report (reads fine without colors)."""
    email = str(result.get("email") or "?")
    domain = str(result.get("domain") or "?")
    es = result.get("email_security") or {}

    # -------------------------------------------------------- EMAIL SUMMARY
    header("EMAIL SUMMARY")
    print(f"  Address       {c('bold')}{email}{c('reset')}")
    print(f"  Domain        {domain}")
    if result.get("valid"):
        print(f"  Valid         {c('green')}{_checkmark()} format accepted{c('reset')}")
    disp = result.get("is_disposable")
    if disp is True:
        disp_txt = f"{c('red')}disposable address{c('reset')}"
    elif disp is False:
        disp_txt = f"{c('green')}not disposable{c('reset')}"
    else:
        disp_txt = f"{c('gray')}unknown{c('reset')}"
    print(f"  Disposable    {disp_txt}")
    print(f"  Mail provider {es.get('provider') or '-'}")
    score = es.get("score")
    if score is not None:
        if score >= 80:
            score_col = c("green")
        elif score >= 50:
            score_col = c("yellow")
        else:
            score_col = c("red")
        print(f"  Email posture  {score_col}{score}/100{c('reset')}")

    # --------------------------------------------------------- DNS SECURITY
    header("DNS SECURITY")
    if not es:
        print(f"  {c('gray')}(no DNS security data){c('reset')}")
    else:
        mx = es.get("mx_hosts") or []
        if mx:
            print(f"  MX            {', '.join(mx)}")
        else:
            print(f"  MX            {c('red')}no MX records{c('reset')}")

        # DMARC
        policy = es.get("dmarc_policy")
        if not es.get("dmarc_record"):
            print(f"  DMARC         {c('red')}missing{c('reset')}")
        elif policy in ("quarantine", "reject"):
            print(f"  DMARC         {c('green')}policy = {policy}"
                  f"{c('reset')}")
        else:
            print(f"  DMARC         {c('yellow')}policy = {policy or 'none'}"
                  f"{c('reset')}")

        # SPF
        if not es.get("spf_record"):
            print(f"  SPF           {c('red')}missing{c('reset')}")
        elif es.get("spf_valid"):
            print(f"  SPF           {c('green')}valid{c('reset')}")
        else:
            print(f"  SPF           {c('yellow')}invalid{c('reset')}"
                  f"  {c('dim')}{_clip(es.get('spf_record'), 60)}{c('reset')}")

        # DKIM
        dkim = es.get("dkim_selectors_found") or []
        if dkim:
            print(f"  DKIM          {c('green')}selectors: "
                  f"{', '.join(dkim)}{c('reset')}")
        else:
            print(f"  DKIM          {c('yellow')}none found{c('reset')}")

        # Optional records — gray when present
        if es.get("mta_sts"):
            print(f"  MTA-STS       {c('gray')}{_clip(es['mta_sts'], 60)}"
                  f"{c('reset')}")
        if es.get("tls_rpt"):
            print(f"  TLS-RPT       {c('gray')}{_clip(es['tls_rpt'], 60)}"
                  f"{c('reset')}")
        for tlsa in (es.get("dane_tlsa") or []):
            print(f"  DANE          {c('gray')}{_clip(str(tlsa), 60)}"
                  f"{c('reset')}")

        for issue in (es.get("issues") or []):
            print(f"  {c('yellow')}! {issue}{c('reset')}")

    # BIMI lives in the result (not the DNS-security block) — show whenever present
    bimi = result.get("bimi")
    if bimi and bimi.get("record"):
        print(f"  BIMI          {c('green')}{_clip(bimi['record'], 60)}"
              f"{c('reset')}")

    # ------------------------------------------------------------- GRAVATAR
    header("GRAVATAR")
    gv = result.get("gravatar") or {}
    if not gv:
        print(f"  {c('gray')}(no Gravatar data){c('reset')}")
    else:
        exists = gv.get("exists")
        if exists is True:
            ex_txt = f"{c('green')}yes{c('reset')}"
        elif exists is False:
            ex_txt = f"{c('gray')}no{c('reset')}"
        else:
            ex_txt = f"{c('gray')}unknown{c('reset')}"
        print(f"  Exists        {ex_txt}")
        if gv.get("display_name"):
            print(f"  Display name  {gv['display_name']}")
        if gv.get("location"):
            print(f"  Location      {gv['location']}")
        print(f"  Profile       {gv.get('profile_url') or '-'}")

    # --------------------------------------------------------- BREACH CHECK
    header("BREACH CHECK")
    bc = result.get("breach_check") or {}
    status = bc.get("status")
    count = bc.get("breach_count")
    if count:
        print(f"  {c('red')}{c('bold')}FOUND IN {count} BREACHES{c('reset')}")
        for name in (bc.get("breaches") or [])[:15]:
            print(f"    {c('red')}- {name}{c('reset')}")
        remaining = count - min(15, len(bc.get("breaches") or []))
        if remaining > 0:
            print(f"    {c('dim')}... and {remaining} more{c('reset')}")
    elif status == "no_breaches" or count == 0:
        print(f"  {c('green')}no known breaches{c('reset')}")
    else:
        print(f"  {c('gray')}unavailable ({status or 'unknown'}){c('reset')}")

    # -------------------------------------------------- CONNECTED PLATFORMS
    header("CONNECTED PLATFORMS")
    plist = result.get("connected_platforms") or []
    if not plist:
        print(f"  {c('gray')}(no key-free platform links found — "
              f"try the dorks below){c('reset')}")
    else:
        for p in plist:
            if not isinstance(p, dict):
                continue
            plat = str(p.get("platform") or "?")
            handle = p.get("handle")
            url = p.get("url") or "-"
            verified = p.get("verified")
            if verified is True:
                mark, col = _checkmark(), c("green")
            elif verified is False:
                mark, col = "!", c("yellow")
            else:
                mark, col = "-", c("cyan")
            print(f"  {mark} {c('bold')}{plat:<16}{c('reset')}"
                  f"{_clip(str(handle or '-'), 28):<30} {c('gray')}"
                  f"{_clip(url, 58)}{c('reset')}")
            if p.get("evidence"):
                print(f"    {c('dim')}{_clip(p['evidence'], 80)}{c('reset')}")

    # ----------------------------------------------------------- SEARCH DORKS
    header("SEARCH DORKS")
    dorks = result.get("dorks") or []
    if dorks:
        for d in dorks:
            print(f"  {c('gray')}{d}{c('reset')}")
    else:
        print(f"  {c('gray')}(none){c('reset')}")

    # ----------------------------------------------------- DOMAIN REGISTRY
    header("DOMAIN REGISTRY (RDAP)")
    rdap = result.get("rdap") or {}
    if not rdap:
        print(f"  {c('gray')}(no registry data){c('reset')}")
    else:
        if rdap.get("registrar"):
            print(f"  Registrar     {rdap['registrar']}")
        if rdap.get("registrant_org"):
            print(f"  Registrant    {rdap['registrant_org']}")
        if rdap.get("created"):
            print(f"  Created       {rdap['created']}")
        if rdap.get("updated"):
            print(f"  Updated       {rdap['updated']}")
        if rdap.get("abuse_email"):
            print(f"  Abuse contact {c('yellow')}{rdap['abuse_email']}"
                  f"{c('reset')}"
                  + (f"  ({rdap['abuse_name']})" if rdap.get("abuse_name") else ""))
        if rdap.get("statuses"):
            print(f"  Statuses      {c('gray')}{', '.join(rdap['statuses'])}"
                  f"{c('reset')}")

    # ----------------------------------------------------- USERNAME GUESSES
    header("USERNAME GUESSES")
    guesses = result.get("username_guesses") or []
    if guesses:
        print(f"  {c('gray')}{', '.join(guesses)}{c('reset')}")
    else:
        print(f"  {c('gray')}(none){c('reset')}")

    # -------------------------------------------------------- SOURCE STATUS
    header("SOURCE STATUS")
    statuses = result.get("sources_status") or {}
    for name in sorted(statuses):
        value = str(statuses[name])
        print(f"  {name:<18}{_status_color(value)}{value}{c('reset')}")
