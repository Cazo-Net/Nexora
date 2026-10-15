"""Identity correlation engine: presence, profile metadata, avatars,
username aliases and a pure 0-100 correlation score.

Key-free only. Walled gardens (X / Instagram / TikTok / Facebook) are
never scraped — they yield dork suggestions instead. Every source
degrades gracefully into ``sources_status``.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..cache import cache_get, cache_set
from ..net import http_get, reset_circuit_breaker
from ..output import c, header
from ..username import SITES

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")

# Profiles cached for 1 hour (spec: profile metadata 3600)
_PROFILE_TTL = 3600.0

# High-signal, key-free default subset (~35 real catalogue entries).
# ``unreliable`` entries are excluded from correlation by design; the
# walled gardens are handled separately via dorks.
_PRIORITY_NAMES = (
    # code
    "GitHub", "GitLab", "Bitbucket", "Codeberg", "Kaggle", "Dev.to",
    "Hashnode", "npm", "PyPI", "Docker Hub", "Hugging Face", "Keybase",
    "TryHackMe", "HackerOne",
    # social
    "Reddit", "Mastodon", "Tumblr", "About.me", "Linktree",
    # gaming
    "Steam", "Chess.com", "Lichess", "speedrun.com", "Kick",
    # creative
    "DeviantArt", "ArtStation", "Dribbble", "Imgur",
    # music
    "SoundCloud", "Last.fm",
    # writing
    "Medium", "Substack", "WordPress",
    # other / forum
    "Letterboxd", "Archive.org", "Lobsters", "V2EX",
)

# Platforms that are never fetched (login-walled) — dork suggestions only.
_WALLED: Dict[str, str] = {
    "x": '"{h}" site:x.com',
    "instagram": '"{h}" site:instagram.com',
    "tiktok": '"{h}" site:tiktok.com',
    "facebook": '"{h}" site:facebook.com',
}

# SITES-catalogue names that map onto a walled garden (never fetched)
_WALLED_SITE_NAMES: Dict[str, str] = {
    "X (Twitter)": "x",
    "Instagram": "instagram",
    "TikTok": "tiktok",
    "Facebook": "facebook",
}

# HTTP statuses that never prove existence (blocked / method / redirect quirks)
_AMBIGUOUS = (401, 403, 405, 429, 999, 301, 302, 303, 307, 308)


def _validate_handle(handle: str) -> str:
    h = (handle or "").strip()
    if not USERNAME_RE.fullmatch(h):
        raise ValueError("invalid handle: %r" % (handle,))
    return h


def _classify(site: Dict[str, Any], code: int) -> str:
    """Map an HTTP status to found / not_found / maybe / unknown."""
    unreliable = bool(site.get("unreliable"))
    if code == 200:
        return "unknown" if unreliable else "found"
    if code in (404, 410):
        return "not_found"
    if code in _AMBIGUOUS:
        return "unknown" if unreliable else "maybe"
    return "unknown"


def _check_site(site: Dict[str, Any], u: str,
                status_cb: Optional[Callable[[str, dict], None]]) -> dict:
    """Check one catalogue site. Never raises; always closes the response."""
    url = site["url"].format(u=u)
    walled = _WALLED_SITE_NAMES.get(site["name"])
    if walled is not None:
        # walled gardens are never fetched — emit a dork suggestion instead
        return {
            "site": site["name"],
            "category": site.get("category", "other"),
            "url": url,
            "status_code": None,
            "result": "walled",
            "status": "walled",
            "dork": _WALLED[walled].format(h=u),
        }
    rec: Dict[str, Any] = {
        "site": site["name"],
        "category": site.get("category", "other"),
        "url": url,
        "status_code": None,
        "result": "unknown",
    }
    resp = None
    try:
        resp = http_get(url, timeout=6, stream=True)
        if resp is not None:
            rec["status_code"] = int(resp.status_code)
            rec["result"] = _classify(site, rec["status_code"])
    except Exception:
        rec["result"] = "unknown"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass
    if rec["result"] == "found" and status_cb is not None:
        try:
            status_cb(site["name"], {"url": url, "result": "found"})
        except Exception:
            pass
    return rec


# --------------------------------------------------------------------------- #
# Profile metadata (all key-free; silent-fail with a status)
# --------------------------------------------------------------------------- #
def _status_for_code(code: Optional[int]) -> str:
    if code is None:
        return "error: no_response"
    if code == 200:
        return "ok"
    if code in (404, 410):
        return "http_404"
    if code in _AMBIGUOUS:
        return "blocked"
    return f"http_{code}"


def _enrich_github(u: str) -> Tuple[Dict[str, Any], str]:
    resp = None
    try:
        resp = http_get("https://api.github.com/users/" + u, timeout=8)
        if resp is None:
            return {}, "error: no_response"
        status = _status_for_code(int(resp.status_code))
        if status != "ok":
            return {}, status
        try:
            data = resp.json()
        except Exception:
            return {}, "error: bad_json"
        if not isinstance(data, dict):
            return {}, "error: bad_json"
        keys = ("name", "bio", "company", "location", "blog",
                "twitter_username", "followers", "public_repos",
                "created_at", "avatar_url", "html_url")
        out = {k: data.get(k) for k in keys}
        return out, "ok"
    except Exception as exc:
        return {}, f"error: {type(exc).__name__}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _enrich_reddit(u: str) -> Tuple[Dict[str, Any], str]:
    resp = None
    try:
        resp = http_get(f"https://www.reddit.com/user/{u}/about.json", timeout=8)
        if resp is None:
            return {}, "error: no_response"
        status = _status_for_code(int(resp.status_code))
        if status != "ok":
            return {}, status
        try:
            payload = resp.json()
        except Exception:
            return {}, "error: bad_json"
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            return {}, "error: bad_json"
        sub = data.get("subreddit")
        if not isinstance(sub, dict):
            sub = {}
        icon = data.get("icon_img") or ""
        created: Optional[str] = None
        try:
            ts = data.get("created_utc")
            if ts is not None:
                created = datetime.fromtimestamp(
                    float(ts), tz=timezone.utc).isoformat()
        except Exception:
            created = None
        out = {
            "icon_img": icon or None,
            "display_name": sub.get("title") or data.get("name"),
            "public_description": sub.get("public_description"),
            "created_utc": created,
            "total_karma": data.get("total_karma"),
            "avatar_url": icon.split("?")[0] if icon else None,
        }
        return out, "ok"
    except Exception as exc:
        return {}, f"error: {type(exc).__name__}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _enrich_keybase(u: str) -> Tuple[Dict[str, Any], str]:
    resp = None
    try:
        url = ("https://keybase.io/_/api/1.0/user/lookup.json?username="
               + u)
        resp = http_get(url, timeout=8)
        if resp is None:
            return {}, "error: no_response"
        status = _status_for_code(int(resp.status_code))
        if status != "ok":
            return {}, status
        try:
            payload = resp.json()
        except Exception:
            return {}, "error: bad_json"
        if not isinstance(payload, dict):
            return {}, "error: bad_json"
        st = payload.get("status")
        code = None
        if isinstance(st, dict):
            try:
                code = int(st.get("code"))
            except Exception:
                code = None
        if code is not None and code != 200:
            return {}, f"http_{code}" if code in (404, 410) else "error: keybase_%s" % code
        them = payload.get("them")
        if not isinstance(them, list) or not them:
            return {}, "no_results"
        linked: List[Dict[str, Any]] = []
        try:
            proofs = them[0].get("proofs") or []
        except Exception:
            proofs = []
        for proof in proofs:
            if not isinstance(proof, dict):
                continue
            linked.append({
                "proof_type": proof.get("proof_type"),
                "nametracker_payload": proof.get("nametracker_payload"),
                "url": proof.get("url"),
            })
        out: Dict[str, Any] = {"linked_accounts": linked}
        return out, "ok"
    except Exception as exc:
        return {}, f"error: {type(exc).__name__}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _enrich_steam(u: str) -> Tuple[Dict[str, Any], str]:
    resp = None
    try:
        resp = http_get(f"https://steamcommunity.com/id/{u}?xml=1", timeout=8)
        if resp is None:
            return {}, "error: no_response"
        status = _status_for_code(int(resp.status_code))
        if status != "ok":
            return {}, status
        text = resp.text or ""
        if "<profile" not in text:
            return {}, "no_results"
        def tag(name: str) -> Optional[str]:
            m = re.search(r"<%s>(.*?)</%s>" % (name, name), text, re.S)
            if not m:
                return None
            val = re.sub(r"<!\[CDATA\[(.*?)\]\]>", r"\1", m.group(1),
                         flags=re.S).strip()
            return val or None
        out: Dict[str, Any] = {
            "steamID": tag("steamID"),
            "realname": tag("realname"),
            "avatarFull": tag("avatarFull"),
            "summary": tag("summary"),
            "joinDate": tag("membersince"),
            "avatar_url": tag("avatarFull"),
        }
        if not any(out.values()):
            return {}, "no_results"
        return out, "ok"
    except Exception as exc:
        return {}, f"error: {type(exc).__name__}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _enrich_linktree(u: str) -> Tuple[Dict[str, Any], str]:
    resp = None
    try:
        resp = http_get(f"https://linktr.ee/{u}", timeout=8, stream=True)
        if resp is None:
            return {}, "error: no_response"
        status = _status_for_code(int(resp.status_code))
        if status != "ok":
            return {}, status
        body = bytearray()
        try:
            for chunk in resp.iter_content(8192):
                if chunk:
                    body.extend(chunk)
                if len(body) >= 512 * 1024:
                    break
        except Exception:
            pass
        html = bytes(body[:512 * 1024]).decode("utf-8", "ignore")
        out: Dict[str, Any] = {}
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I)
        if m:
            out["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:200] or None
        m = re.search(
            r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']*)',
            html, re.I)
        if m:
            out["description"] = m.group(1).strip()[:500] or None
        m = re.search(
            r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)',
            html, re.I)
        if m:
            out["avatar_url"] = m.group(1).strip()
        if not any(v for v in out.values()):
            return {}, "no_results"
        return out, "ok"
    except Exception as exc:
        return {}, f"error: {type(exc).__name__}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _enrich_devto(u: str) -> Tuple[Dict[str, Any], str]:
    resp = None
    try:
        resp = http_get(f"https://dev.to/api/users/{u}", timeout=8)
        if resp is None:
            return {}, "error: no_response"
        status = _status_for_code(int(resp.status_code))
        if status != "ok":
            return {}, status
        try:
            data = resp.json()
        except Exception:
            return {}, "error: bad_json"
        if not isinstance(data, dict):
            return {}, "error: bad_json"
        keys = ("name", "github_username", "twitter_username",
                "location", "summary", "profile_image")
        out = {k: data.get(k) for k in keys}
        if not any(out.values()):
            return {}, "no_results"
        return out, "ok"
    except Exception as exc:
        return {}, f"error: {type(exc).__name__}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


# Which found platform triggers which enricher (site name -> enricher)
_ENRICHERS: List[Tuple[str, Callable[[str], Tuple[Dict[str, Any], str]]]] = [
    ("GitHub", _enrich_github),
    ("Reddit", _enrich_reddit),
    ("Keybase", _enrich_keybase),
    ("Steam", _enrich_steam),
    ("Linktree", _enrich_linktree),
    ("Dev.to", _enrich_devto),
]


# --------------------------------------------------------------------------- #
# Username variants
# --------------------------------------------------------------------------- #
def _alias_variants(handle: str) -> List[str]:
    candidates = [
        handle,
        handle.replace(".", ""),
        handle.replace("_", ""),
        handle.replace("-", ""),
        handle.replace(".", "_"),
    ]
    out: List[str] = []
    for cand in candidates:
        if cand and cand not in out:
            out.append(cand)
    return out[:5]


def _confirm_alias_github(alias: str) -> Tuple[bool, Optional[str]]:
    """Cheap GitHub-only alias confirmation. Never raises."""
    resp = None
    try:
        resp = http_get("https://api.github.com/users/" + alias, timeout=6)
        if resp is None or int(resp.status_code) != 200:
            return False, None
        data = resp.json()
        if isinstance(data, dict) and data.get("login"):
            return True, data.get("name") or data["login"]
        return False, None
    except Exception:
        return False, None
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Pure correlation scoring
# --------------------------------------------------------------------------- #
def _norm_name(value: Any) -> str:
    """Lowercase + strip everything non-alphanumeric."""
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _norm_avatar(value: Any) -> str:
    """Strip query/fragment and lowercase host so avatars compare equal."""
    url = str(value or "").split("#")[0].split("?")[0]
    try:
        parts = urlparse(url)
        if parts.scheme and parts.netloc:
            return "%s://%s%s" % (parts.scheme.lower(), parts.netloc.lower(),
                                  parts.path)
    except Exception:
        pass
    return url.lower()


def _bio_tokens(value: Any) -> set:
    return {w for w in re.findall(r"[a-z0-9]{3,}", str(value or "").lower())}


def _score_correlation(found_sites: List[Any], profiles: Dict[str, dict],
                       avatars: List[Any],
                       aliases: List[Any]) -> Dict[str, Any]:
    """Score identity correlation 0-100 from harvested signals (PURE).

    Signals (spec):
      * same normalized avatar on >=2 platforms          -> +40
      * same display name across >=3 profiles            -> +25
      * bio/description jaccard >=0.6 between >=2 profs  -> +15
      * handle identical on all found sites              -> +10
      * Keybase linked account corroborates the handle   -> +15
      * matches ONLY on unreliable sites                 -> -20
    """
    signals: List[str] = []
    score = 0

    # -- 1. avatar reuse across platforms ---------------------------------- #
    avatar_platforms: Dict[str, set] = {}
    for entry in avatars or []:
        if isinstance(entry, dict):
            url = _norm_avatar(entry.get("url") or entry.get("avatar_url"))
            site = str(entry.get("site") or entry.get("platform") or "?")
        else:
            url = _norm_avatar(entry)
            site = "?"
        if not url:
            continue
        avatar_platforms.setdefault(url, set()).add(site)
    shared = max((len(v) for v in avatar_platforms.values()), default=0)
    if shared >= 2:
        score += 40
        signals.append("same avatar used on %d platforms" % shared)

    # -- 2. same display name across >=3 profiles --------------------------- #
    name_map: Dict[str, set] = {}
    for site, prof in (profiles or {}).items():
        if not isinstance(prof, dict):
            continue
        raw = (prof.get("display_name") or prof.get("name")
               or prof.get("realname") or prof.get("title"))
        norm = _norm_name(raw)
        if len(norm) >= 3:
            name_map.setdefault(norm, set()).add(site)
    shared_names = max((len(v) for v in name_map.values()), default=0)
    if shared_names >= 3:
        score += 25
        signals.append("display name shared across %d profiles"
                       % shared_names)

    # -- 3. bio jaccard >= 0.6 between >= 2 profiles ------------------------ #
    bios: List[set] = []
    for prof in (profiles or {}).values():
        if not isinstance(prof, dict):
            continue
        raw = (prof.get("bio") or prof.get("public_description")
               or prof.get("description") or prof.get("summary"))
        tokens = _bio_tokens(raw)
        if len(tokens) >= 3:
            bios.append(tokens)
    best_jaccard = 0.0
    for i in range(len(bios)):
        for j in range(i + 1, len(bios)):
            union = bios[i] | bios[j]
            if not union:
                continue
            val = len(bios[i] & bios[j]) / len(union)
            if val > best_jaccard:
                best_jaccard = val
    if best_jaccard >= 0.6:
        score += 15
        signals.append("bio/description overlap %.2f between profiles"
                       % best_jaccard)

    # -- 4. handle identical on all found ----------------------------------- #
    names = [str(s.get("site") if isinstance(s, dict) else s)
             for s in (found_sites or [])]
    if names:
        # a single consistent handle across every hit is a (weak) signal
        score += 10
        signals.append("handle consistent across %d found sites" % len(names))

    # -- 5. Keybase linked accounts corroborate the handle ------------------ #
    linked = (profiles or {}).get("Keybase", {})
    if isinstance(linked, dict):
        proofs = linked.get("linked_accounts") or []
        if proofs:
            score += 15
            signals.append("keybase linked identity proofs present")

    # -- 6. only-unreliable matches ----------------------------------------- #
    reliable_hits = 0
    unreliable_hits = 0
    for entry in found_sites or []:
        if isinstance(entry, dict):
            if entry.get("unreliable"):
                unreliable_hits += 1
            else:
                reliable_hits += 1
    if unreliable_hits and not reliable_hits:
        score -= 20
        signals.append("matches only on unreliable sites (%d)" % unreliable_hits)

    score = max(0, min(100, score))
    if score >= 70:
        verdict = "strongly correlated"
    elif score >= 40:
        verdict = "likely the same identity"
    elif score >= 20:
        verdict = "possible"
    else:
        verdict = "insufficient signal"
    return {"score": score, "verdict": verdict, "signals": signals}


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #
def lookup_identity(handle: str, *, exhaustive: bool = False,
                    status_cb: Optional[Callable[[str, dict], None]] = None
                    ) -> dict:
    """Correlate ``handle`` across the social catalogue.

    Returns a JSON-serializable dict: handle, presence, found_count,
    profiles, linked_accounts, avatars, aliases, correlation, dorks,
    sources_status. Raises ValueError for malformed handles.
    """
    h = _validate_handle(handle)
    reset_circuit_breaker()

    # ---- 1. presence ------------------------------------------------------- #
    if exhaustive:
        sites = [s for s in SITES]
    else:
        priority = set(_PRIORITY_NAMES)
        sites = [s for s in SITES if s["name"] in priority]
    slots: List[Optional[dict]] = [None] * len(sites)
    workers = max(1, min(25, len(sites)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_check_site, site, h, status_cb): idx
            for idx, site in enumerate(sites)
        }
        for fut in as_completed(futures):
            idx = futures[fut]
            try:
                slots[idx] = fut.result()
            except Exception:
                site = sites[idx]
                slots[idx] = {
                    "site": site["name"],
                    "category": site.get("category", "other"),
                    "url": site["url"].format(u=h),
                    "status_code": None,
                    "result": "unknown",
                }
    checks: List[dict] = [s for s in slots if s is not None]
    found = [ch for ch in checks if ch.get("result") == "found"]

    sources_status: Dict[str, str] = {
        "presence": "%d found / %d checked" % (len(found), len(checks)),
    }
    if status_cb is not None:
        try:
            status_cb("presence", {"found": len(found),
                                   "checked": len(checks), "handle": h})
        except Exception:
            pass

    # ---- 2. profile metadata (top found platforms only) -------------------- #
    found_names = {ch["site"] for ch in found}
    profiles: Dict[str, dict] = {}
    linked_accounts: List[dict] = []
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures2 = {}
        for site_name, enricher in _ENRICHERS:
            if site_name in found_names:
                futures2[pool.submit(enricher, h)] = site_name
            else:
                sources_status["profile:" + site_name] = "skipped: not found"
        for fut in as_completed(futures2):
            site_name = futures2[fut]
            key = "profile:" + site_name
            try:
                info, status = fut.result()
            except Exception as exc:
                info, status = {}, f"error: {type(exc).__name__}"
            sources_status[key] = status
            if status == "ok" and info:
                # cache JSON-serializable profiles for 1 hour
                cache_set("social:profile:%s:%s" % (site_name, h.lower()),
                          info)
                profiles[site_name] = info
    # apply cache for any profile the fetcher may have skipped
    for site_name, _enricher in _ENRICHERS:
        if site_name in found_names and site_name not in profiles:
            cached = cache_get("social:profile:%s:%s" % (site_name, h.lower()),
                               _PROFILE_TTL)
            if isinstance(cached, dict) and cached:
                profiles[site_name] = cached
                sources_status["profile:" + site_name] = "ok (cached)"
    kb = profiles.get("Keybase")
    if isinstance(kb, dict):
        linked_accounts = list(kb.get("linked_accounts") or [])

    # Twitch needs an account id — recorded as skipped (never an error)
    if "Twitch" in found_names:
        sources_status["profile:Twitch"] = "skipped: requires account id"

    # ---- 3. avatars -------------------------------------------------------- #
    avatars: List[str] = []
    avatar_pairs: List[Dict[str, str]] = []
    seen_avatars: set = set()
    for site_name, prof in profiles.items():
        for key in ("avatar_url", "profile_image", "icon_img", "avatarFull"):
            val = prof.get(key)
            if isinstance(val, str) and val.startswith("http"):
                norm = _norm_avatar(val)
                if norm and norm not in seen_avatars:
                    seen_avatars.add(norm)
                    avatars.append(norm)
                if norm:
                    avatar_pairs.append({"site": site_name, "url": norm})
            if len(avatars) >= 30:
                break

    # ---- 4. username variants ---------------------------------------------- #
    alias_names = _alias_variants(h)
    alias_records: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures3 = {}
        for alias in alias_names:
            if alias == h:
                # original handle: confirm through the GitHub profile if seen
                continue
            futures3[pool.submit(_confirm_alias_github, alias)] = alias
        confirmations: Dict[str, Tuple[bool, Optional[str]]] = {}
        for fut in as_completed(futures3):
            alias = futures3[fut]
            try:
                confirmations[alias] = fut.result()
            except Exception:
                confirmations[alias] = (False, None)
    for alias in alias_names:
        if alias == h:
            gh = profiles.get("GitHub") or {}
            confirmed = "GitHub" in profiles
            alias_records.append({
                "alias": alias,
                "github_confirmed": bool(confirmed),
                "github_name": gh.get("name") if confirmed else None,
            })
        else:
            ok, name = confirmations.get(alias, (False, None))
            alias_records.append({
                "alias": alias,
                "github_confirmed": bool(ok),
                "github_name": name,
            })
    sources_status["aliases"] = "%d variants" % len(alias_records)

    # ---- 5. dorks for the walled gardens ------------------------------------ #
    dorks = [tpl.format(h=h) for tpl in _WALLED.values()]
    sources_status["dorks"] = "ok"

    # ---- 6. correlation ------------------------------------------------------ #
    correlation = _score_correlation(found, profiles, avatar_pairs,
                                     alias_records)
    sources_status["correlation"] = "ok"

    return {
        "handle": h,
        "presence": checks,
        "found_count": len(found),
        "profiles": profiles,
        "linked_accounts": linked_accounts,
        "avatars": avatars,
        "aliases": alias_records,
        "correlation": correlation,
        "dorks": dorks,
        "sources_status": sources_status,
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render_text(result: dict) -> None:
    """Print a colored human-readable identity-correlation report."""
    h = result.get("handle", "")
    checks = result.get("presence") or []
    found = [ch for ch in checks if ch.get("result") == "found"]
    profiles = result.get("profiles") or {}
    linked = result.get("linked_accounts") or []
    avatars = result.get("avatars") or []
    aliases = result.get("aliases") or []
    corr = result.get("correlation") or {}
    dorks = result.get("dorks") or []
    sources_status = result.get("sources_status") or {}

    # SUMMARY
    header("SUMMARY")
    print(f"  Handle: {c('bold')}{c('cyan')}{h}{c('reset')}")
    print(f"  {c('green')}{len(found)} found / {len(checks)} checked{c('reset')}")
    score = int(corr.get("score", 0))
    verdict = str(corr.get("verdict", ""))
    if score >= 70:
        vcol = c("green")
    elif score >= 40:
        vcol = c("yellow")
    else:
        vcol = c("gray")
    print(f"  Correlation: {vcol}{verdict} ({score}/100){c('reset')}")

    # FOUND
    header("FOUND")
    if found:
        for ch in found[:30]:
            print(f"  {c('green')}✓ {ch.get('site')}{c('reset')} "
                  f"{c('dim')}{ch.get('url')}{c('reset')}")
        if len(found) > 30:
            print(f"  {c('gray')}... and {len(found) - 30} more{c('reset')}")
    else:
        print(f"  {c('gray')}none{c('reset')}")

    # PROFILE ENRICHMENT
    header("PROFILE ENRICHMENT")
    if profiles:
        for site_name, prof in profiles.items():
            print(f"  {c('bold')}{c('magenta')}{site_name}{c('reset')}")
            if site_name == "GitHub":
                rows = [("name", prof.get("name")), ("bio", prof.get("bio")),
                        ("company", prof.get("company")),
                        ("public_repos", prof.get("public_repos")),
                        ("followers", prof.get("followers"))]
            elif site_name == "Reddit":
                rows = [("total_karma", prof.get("total_karma")),
                        ("display_name", prof.get("display_name")),
                        ("created_utc", prof.get("created_utc"))]
            elif site_name == "Steam":
                rows = [("realname", prof.get("realname")),
                        ("steamID", prof.get("steamID")),
                        ("joinDate", prof.get("joinDate"))]
            elif site_name == "Keybase":
                rows = [("linked_accounts",
                         len(prof.get("linked_accounts") or []))]
            else:
                rows = sorted(prof.items())
            for key, val in rows:
                if val is None or (isinstance(val, str) and not val.strip()):
                    continue
                print(f"    {c('cyan')}{key}{c('reset')}: {val}")
    else:
        print(f"  {c('gray')}none{c('reset')}")

    if linked:
        header("LINKED ACCOUNTS")
        for acc in linked:
            ptype = acc.get("proof_type") or "?"
            payload = acc.get("nametracker_payload") or ""
            url = acc.get("url") or ""
            print(f"  {c('green')}• {ptype}{c('reset')} {payload} "
                  f"{c('dim')}{url}{c('reset')}")

    # CORRELATION SIGNALS
    header("CORRELATION SIGNALS")
    sig = corr.get("signals") or []
    if sig:
        for s in sig:
            print(f"  {c('yellow')}• {s}{c('reset')}")
        filled = max(0, min(10, score // 10))
        bar = "█" * filled + "░" * (10 - filled)
        print(f"  {c('cyan')}[{bar}] {score}/100{c('reset')}")
    else:
        print(f"  {c('gray')}none{c('reset')}")

    # ALIASES
    header("ALIASES")
    if aliases:
        for rec in aliases:
            mark = (f" {c('green')}✓ github" if rec.get("github_confirmed")
                    else "")
            name = rec.get("github_name")
            extra = f" {c('dim')}({name})" if name else ""
            print(f"  {rec.get('alias')}{mark}{extra}{c('reset')}")
    else:
        print(f"  {c('gray')}none{c('reset')}")

    # AVATARS
    header("AVATARS")
    if avatars:
        for url in avatars:
            print(f"  {c('dim')}{url}{c('reset')}")
    else:
        print(f"  {c('gray')}none{c('reset')}")

    # DORKS
    header("DORKS")
    if dorks:
        for d in dorks:
            print(f"  {c('gray')}{d}{c('reset')}")
    else:
        print(f"  {c('gray')}none{c('reset')}")

    # SOURCE STATUS
    header("SOURCE STATUS")
    line = ", ".join(f"{k}: {v}" for k, v in sorted(sources_status.items()))
    print(f"  {c('gray')}{line or 'n/a'}{c('reset')}")
