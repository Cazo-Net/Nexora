"""Internet platforms connected to an email address or phone number.

Every check is key-free and honest about what it can prove:

Email — real lookups wherever a public API exists:
    * Keybase        email -> user -> verified social proofs (github/twitter/...)
    * GitHub         commit-authorship search by e-mail address
    * Gravatar       profile JSON -> linked accounts (twitter/github/wordpress/...)
    * OpenPGP        keys.openpgp.org verified UIDs (name bound to address)
    plus copy/paste dork suggestions for the walled gardens.

Phone — no fake signals: platforms that use a phone number as their identity
key get deep links (WhatsApp/Signal) or an app-search hint (Telegram), plus
Google dorks in every published number format and heuristic handle candidates.

All collectors return status strings; nothing raises except empty or
non-numberish input (``ValueError``).
"""
from __future__ import annotations

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote

from .net import http_get

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def _notify(status_cb: Optional[Callable[..., None]], source: str,
            info: Dict[str, Any]) -> None:
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


# --------------------------------------------------------------------------- #
# Email collectors — each returns (entries, status, detail) and never raises
# --------------------------------------------------------------------------- #
def _pf_keybase(email: str, getter) -> Tuple[List[Dict[str, Any]], str, str]:
    resp = getter("https://keybase.io/_/api/1.0/user/lookup.json",
                  params={"email": email}, timeout=8)
    if resp is None:
        return [], "error: no_response", "Keybase unreachable"
    if resp.status_code == 404:
        return [], "no_results", ""
    if resp.status_code != 200:
        return [], f"http_{resp.status_code}", ""
    try:
        data = resp.json() or {}
    except Exception:
        return [], "error: invalid_json", ""
    them = data.get("them") or []
    if not them:
        return [], "no_results", "no Keybase user for this address"
    user = them[0] if isinstance(them[0], dict) else {}
    entries: List[Dict[str, Any]] = []
    kb_user = str(user.get("username") or "")
    if kb_user:
        entries.append({
            "platform": "keybase", "handle": kb_user,
            "url": f"https://keybase.io/{kb_user}",
            "evidence": "Keybase account publishes this email",
            "verified": True,
        })
    for proof in (user.get("proofs") or []):
        if not isinstance(proof, dict):
            continue
        ptype = str(proof.get("proof_type") or "").strip().lower()
        if not ptype or ptype in ("dns", "http"):
            continue
        handle = proof.get("nametracker_payload") or proof.get("payload") or ""
        entries.append({
            "platform": ptype, "handle": _clip(str(handle), 60),
            "url": str(proof.get("url") or "")[:200],
            "evidence": "Keybase proof",
            "verified": bool(proof.get("verified")),
        })
    return entries, "ok", f"keybase user: {kb_user or '?'}"


def _pf_github(email: str, getter) -> Tuple[List[Dict[str, Any]], str, str]:
    resp = getter(
        "https://api.github.com/search/commits",
        params={"q": f"author-email:{email}", "per_page": 5},
        headers={"Accept": "application/vnd.github+json"},
        timeout=12,
    )
    if resp is None:
        return [], "error: no_response", "GitHub unreachable"
    if resp.status_code in (403, 429):
        return [], "rate_limited", "GitHub search rate limit"
    if resp.status_code in (404, 422):
        return [], "no_results", ""
    if resp.status_code != 200:
        return [], f"http_{resp.status_code}", ""
    try:
        data = resp.json() or {}
    except Exception:
        return [], "error: invalid_json", ""
    total = int(data.get("total_count") or 0)
    items = [i for i in (data.get("items") or []) if isinstance(i, dict)]
    if not items:
        return [], "no_results", "no commits by this address"
    entries: List[Dict[str, Any]] = []
    seen_logins = set()
    for item in items:
        author = item.get("author") or {}
        login = author.get("login") if isinstance(author, dict) else None
        if login and login not in seen_logins:
            seen_logins.add(login)
            entries.append({
                "platform": "github", "handle": str(login),
                "url": f"https://github.com/{login}",
                "evidence": f"committed with this email ({total} hit(s))",
                "verified": None,
            })
    for item in items[:3]:
        repo = (item.get("repository") or {}).get("full_name") or "?"
        entries.append({
            "platform": "github", "handle": None,
            "url": str(item.get("html_url") or "")[:200],
            "evidence": f"commit in {repo}", "verified": None,
        })
    return entries, "ok", f"{total} commit hit(s)"


def _pf_gravatar(email: str, getter) -> Tuple[List[Dict[str, Any]], str, str]:
    digest = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    resp = getter(f"https://www.gravatar.com/{digest}.json", timeout=8)
    if resp is None:
        return [], "error: no_response", "Gravatar unreachable"
    if resp.status_code == 404:
        return [], "no_results", "no Gravatar profile"
    if resp.status_code != 200:
        return [], f"http_{resp.status_code}", ""
    try:
        data = resp.json()
        entry = data[0] if isinstance(data, list) and data else (data or {})
    except Exception:
        return [], "error: invalid_json", ""
    if not isinstance(entry, dict):
        return [], "no_results", ""
    entries: List[Dict[str, Any]] = []
    for acc in (entry.get("accounts") or [])[:10]:
        if not isinstance(acc, dict):
            continue
        short = str(acc.get("shortname") or acc.get("service") or "").lower()
        url = str(acc.get("url") or "")
        if not short and url:
            short = re.sub(r"^www\.", "", url.split("/")[2] if "//" in url
                           else url).split(".")[0]
        entries.append({
            "platform": short or "unknown", "handle": acc.get("username"),
            "url": url[:200], "evidence": "linked on Gravatar profile",
            "verified": acc.get("verified"),
        })
    if not entries and entry.get("profile_url"):
        entries.append({
            "platform": "gravatar",
            "handle": entry.get("preferred_username"),
            "url": str(entry.get("profile_url"))[:200],
            "evidence": "public Gravatar profile", "verified": None,
        })
    if not entries:
        return [], "no_results", "profile without linked accounts"
    return entries, "ok", f"{len(entries)} linked account(s)"


def _pf_openpgp(email: str, getter) -> Tuple[List[Dict[str, Any]], str, str]:
    url = f"https://keys.openpgp.org/v3/vks/v1/by-email/{quote(email, safe='')}"
    resp = getter(url, headers={"Accept": "application/json"}, timeout=8)
    if resp is None:
        return [], "error: no_response", "keys.openpgp.org unreachable"
    if resp.status_code == 404:
        return [], "no_results", "no key published for this address"
    if resp.status_code != 200:
        return [], f"http_{resp.status_code}", ""
    uids: List[Any] = []
    try:
        data = resp.json()
        uids = data.get("uid") or [] if isinstance(data, dict) else []
    except Exception:
        uids = []
    entries: List[Dict[str, Any]] = []
    for uid in uids[:3]:
        if not isinstance(uid, dict):
            continue
        entries.append({
            "platform": "openpgp", "handle": uid.get("name"),
            "url": url[:200],
            "evidence": "verified UID — email confirmed on keyserver",
            "verified": True,
        })
    if not entries and resp.status_code == 200:
        entries.append({
            "platform": "openpgp", "handle": None, "url": url[:200],
            "evidence": "key published for this address", "verified": True,
        })
    if not entries:
        return [], "no_results", ""
    return entries, "ok", f"{len(entries)} UID(s)"


def email_dorks(email: str) -> List[str]:
    """Copy/paste searches for the platforms that hide behind walled gardens."""
    q = f'"{email}"'
    out = [q]
    for site in ("github.com", "reddit.com", "twitter.com", "linkedin.com",
                 "pastebin.com"):
        out.append(f"{q} site:{site}")
    return out


def username_dorks(username: str) -> List[str]:
    """Copy/paste searches for a handle on the walled gardens."""
    q = f'"{username}"'
    out = [q]
    for site in ("x.com", "instagram.com", "facebook.com", "tiktok.com",
                 "linkedin.com"):
        out.append(f"{q} site:{site}")
    return out


def platforms_for_email(email: str, *,
                        getter: Optional[Callable[..., Any]] = None,
                        status_cb: Optional[Callable[..., None]] = None
                        ) -> Dict[str, Any]:
    """Find internet platforms connected to an email address (key-free).

    Args:
        email: the address to investigate (validated).
        getter: HTTP GET callable (defaults to ``nexora.net.http_get``);
            injectable for tests.
        status_cb: optional progress callback(source, info).

    Returns {platforms, platform_count, dorks, sources_status}.
    Raises ValueError for an invalid address.
    """
    email = (email or "").strip()
    if not _EMAIL_RE.match(email):
        raise ValueError(f"invalid email address: {email}")
    g = getter if getter is not None else http_get

    collectors = {
        "keybase": _pf_keybase,
        "github-commits": _pf_github,
        "gravatar-accounts": _pf_gravatar,
        "openpgp": _pf_openpgp,
    }
    sources: Dict[str, str] = {}
    entries: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(fn, email, g): name
                   for name, fn in collectors.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                ents, status, detail = fut.result()
            except Exception as e:
                ents, status, detail = [], f"error: {type(e).__name__}", str(e)[:80]
            sources[name] = status
            entries.extend(ents or [])
            _notify(status_cb, name, {"status": status, "detail": detail})
    entries.sort(key=lambda e: str(e.get("platform") or ""))
    return {
        "email": email,
        "platforms": entries,
        "platform_count": len(entries),
        "dorks": email_dorks(email),
        "sources_status": sources,
    }


# --------------------------------------------------------------------------- #
# Phone — offline identity-platform map, dorks, handle candidates
# --------------------------------------------------------------------------- #
def _digits(value: Optional[str]) -> str:
    return re.sub(r"\D", "", value or "")


def _derive_e164(raw: str) -> Optional[str]:
    s = (raw or "").strip().replace(" ", "")
    if s.startswith("+"):
        d = _digits(s)
        return "+" + d if len(d) >= 7 else None
    if s.startswith("00"):
        d = _digits(s[2:])
        return "+" + d if len(d) >= 7 else None
    return None


def phone_identity_platforms(e164: str, digits: str) -> List[Dict[str, Any]]:
    """Platforms whose account identity IS the phone number."""
    if len(digits) < 7:
        return []
    return [
        {"platform": "whatsapp", "method": "deep_link",
         "url": f"https://wa.me/{digits}",
         "note": "opens a chat — profile picture/status visible if registered",
         "verified": None},
        {"platform": "signal", "method": "deep_link",
         "url": f"https://signal.me/#p/{e164}",
         "note": "share link resolves a public Signal profile if one exists",
         "verified": None},
        {"platform": "telegram", "method": "app_search",
         "url": "https://web.telegram.org/",
         "note": "search the exact number — reveals the profile if registered",
         "verified": None},
    ]


def phone_dorks(e164: Optional[str], national: Optional[str],
                raw: str, digits: str) -> List[str]:
    """Dorks in every published format of the number."""
    forms: List[str] = []
    for value in (e164, national, raw):
        q = f'"{value}"' if value and re.search(r"\d", value) else ""
        if q and q not in forms:
            forms.append(q)
    if digits and len(digits) >= 7 and f'"{digits}"' not in forms:
        forms.append(f'"{digits}"')
    if not forms:
        return []
    base = forms[0]
    out: List[str] = list(forms[:2])
    for site in ("facebook.com", "instagram.com", "linkedin.com", "x.com",
                 "tiktok.com", "pastebin.com"):
        out.append(f"{base} site:{site}")
    return out[:10]


def platforms_for_phone(phone: str, *, e164: Optional[str] = None,
                        national: Optional[str] = None,
                        status_cb: Optional[Callable[..., None]] = None
                        ) -> Dict[str, Any]:
    """Map a phone number to the platforms that use it as identity.

    Fully offline and honest: deep links / app-search hints / dorks only —
    no fabricated "registered" results. Raises ValueError for empty input
    or something with too few digits to be a number.
    """
    raw = str(phone or "").strip()
    if not raw:
        raise ValueError("empty phone number")
    e164 = e164 or _derive_e164(raw)
    digits = _digits(e164) if e164 else _digits(raw)
    if len(digits) < 6:
        raise ValueError(f"not a phone number: {raw}")
    eff_e164 = e164 or ("+" + digits)

    plats = phone_identity_platforms(eff_e164, digits)
    dorks = phone_dorks(e164, national, raw, digits)

    candidates: List[str] = []
    for value in (digits, _digits(national)):
        if value and len(value) >= 7 and value not in candidates:
            candidates.append(value)

    sources = {"platform-map": "ok (offline)", "dorks": "ok (offline)"}
    _notify(status_cb, "platform-map",
            {"status": "ok (offline)", "detail": f"{len(plats)} platforms"})
    return {
        "phone": raw,
        "e164": e164,
        "platforms": plats,
        "dorks": dorks,
        "handle_candidates": candidates,
        "sources_status": sources,
    }
