"""Username enumeration across 80+ key-free sites, with profile
enrichment (GitHub, Reddit, Dev.to).

Every check is a plain HTTP GET against the site's public profile URL —
no API keys, no authentication. Each site degrades gracefully: a dead or
blocked host yields status ``unknown`` rather than an error.

Because several big platforms always return HTTP 200 (or wall login),
entries flagged ``unreliable`` never report ``found`` on a 200; they can
only report ``not_found`` (404/410) or ``maybe``/``unknown``.

``render_text()`` prints a colored, human-readable report; it reads fine
with colors disabled.
"""
from __future__ import annotations

import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .net import http_get, reset_circuit_breaker
from .output import c, header
from .platforms import username_dorks

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")


def _checkmark() -> str:
    """A ✓ that degrades to ASCII on consoles that can't encode it."""
    try:
        "\u2713".encode(sys.stdout.encoding or "ascii")
        return "\u2713"
    except Exception:
        return "[ok]"

# --------------------------------------------------------------------------- #
# Site catalogue: {"name", "url" (with {u} placeholder), "category",
#                  "unreliable"} — usernames are validated, so .format() is safe.
# ``unreliable`` = login-walled / always-200 / bot-walled site where a 200
# does NOT prove the profile exists.
# --------------------------------------------------------------------------- #
SITES: List[Dict[str, Any]] = [
    # --- code & development -------------------------------------------------
    {"name": "GitHub", "url": "https://github.com/{u}", "category": "code"},
    {"name": "GitLab", "url": "https://gitlab.com/{u}", "category": "code"},
    {"name": "Bitbucket", "url": "https://bitbucket.org/{u}/", "category": "code"},
    {"name": "Codeberg", "url": "https://codeberg.org/{u}", "category": "code"},
    {"name": "CodePen", "url": "https://codepen.io/{u}", "category": "code"},
    {"name": "CodeSandbox", "url": "https://codesandbox.io/u/{u}", "category": "code"},
    {"name": "Replit", "url": "https://replit.com/@{u}", "category": "code"},
    {"name": "HackerRank", "url": "https://www.hackerrank.com/{u}", "category": "code"},
    {"name": "LeetCode", "url": "https://leetcode.com/{u}/", "category": "code"},
    {"name": "Kaggle", "url": "https://www.kaggle.com/{u}", "category": "code"},
    {"name": "freeCodeCamp", "url": "https://www.freecodecamp.org/{u}", "category": "code"},
    {"name": "Dev.to", "url": "https://dev.to/{u}", "category": "code"},
    {"name": "Hashnode", "url": "https://hashnode.com/@{u}", "category": "code"},
    {"name": "npm", "url": "https://www.npmjs.com/~{u}", "category": "code"},
    {"name": "PyPI", "url": "https://pypi.org/user/{u}/", "category": "code"},
    {"name": "crates.io", "url": "https://crates.io/users/{u}", "category": "code"},
    {"name": "Docker Hub", "url": "https://hub.docker.com/u/{u}/", "category": "code"},
    {"name": "Hugging Face", "url": "https://huggingface.co/{u}", "category": "code"},
    {"name": "Observable", "url": "https://observablehq.com/@{u}", "category": "code"},
    {"name": "DigitalOcean", "url": "https://www.digitalocean.com/community/users/{u}", "category": "code"},
    {"name": "Keybase", "url": "https://keybase.io/{u}", "category": "code"},
    {"name": "Devpost", "url": "https://devpost.com/{u}", "category": "code"},
    {"name": "Stack Overflow", "url": "https://stackoverflow.com/search?tab=user&q={u}", "category": "code", "unreliable": True},
    {"name": "HackerOne", "url": "https://hackerone.com/{u}", "category": "code"},
    {"name": "Bugcrowd", "url": "https://bugcrowd.com/{u}", "category": "code", "unreliable": True},
    {"name": "TryHackMe", "url": "https://tryhackme.com/p/{u}", "category": "code"},
    {"name": "Root-Me", "url": "https://www.root-me.org/en/profile?username={u}", "category": "code", "unreliable": True},
    # --- social -------------------------------------------------------------
    {"name": "Reddit", "url": "https://old.reddit.com/user/{u}/", "category": "social"},
    {"name": "X (Twitter)", "url": "https://x.com/{u}", "category": "social", "unreliable": True},
    {"name": "Instagram", "url": "https://www.instagram.com/{u}/", "category": "social", "unreliable": True},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{u}", "category": "social", "unreliable": True},
    {"name": "Facebook", "url": "https://www.facebook.com/{u}", "category": "social", "unreliable": True},
    {"name": "Threads", "url": "https://www.threads.net/@{u}", "category": "social", "unreliable": True},
    {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{u}", "category": "social", "unreliable": True},
    {"name": "Telegram", "url": "https://t.me/{u}", "category": "social", "unreliable": True},
    {"name": "Snapchat", "url": "https://www.snapchat.com/add/{u}", "category": "social", "unreliable": True},
    {"name": "Mastodon", "url": "https://mastodon.social/@{u}", "category": "social"},
    {"name": "VK", "url": "https://vk.com/{u}", "category": "social", "unreliable": True},
    {"name": "Quora", "url": "https://www.quora.com/profile/{u}", "category": "social", "unreliable": True},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{u}/", "category": "social", "unreliable": True},
    {"name": "Tumblr", "url": "https://{u}.tumblr.com", "category": "social"},
    {"name": "Gravatar", "url": "https://en.gravatar.com/{u}", "category": "social", "unreliable": True},
    {"name": "About.me", "url": "https://about.me/{u}", "category": "social"},
    {"name": "Linktree", "url": "https://linktr.ee/{u}", "category": "social"},
    # --- gaming -------------------------------------------------------------
    {"name": "Steam", "url": "https://steamcommunity.com/id/{u}", "category": "gaming"},
    {"name": "Chess.com", "url": "https://www.chess.com/member/{u}", "category": "gaming"},
    {"name": "Lichess", "url": "https://lichess.org/@/{u}", "category": "gaming"},
    {"name": "NameMC", "url": "https://namemc.com/profile/{u}", "category": "gaming"},
    {"name": "speedrun.com", "url": "https://www.speedrun.com/user/{u}", "category": "gaming"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{u}", "category": "gaming", "unreliable": True},
    {"name": "Kick", "url": "https://kick.com/{u}", "category": "gaming"},
    {"name": "Roblox", "url": "https://www.roblox.com/users/profile?username={u}", "category": "gaming", "unreliable": True},
    {"name": "itch.io", "url": "https://{u}.itch.io", "category": "gaming", "unreliable": True},
    # --- creative -----------------------------------------------------------
    {"name": "DeviantArt", "url": "https://www.deviantart.com/{u}", "category": "creative"},
    {"name": "ArtStation", "url": "https://www.artstation.com/{u}", "category": "creative"},
    {"name": "Dribbble", "url": "https://dribbble.com/{u}", "category": "creative"},
    {"name": "Behance", "url": "https://www.behance.net/{u}", "category": "creative"},
    {"name": "Flickr", "url": "https://www.flickr.com/people/{u}/", "category": "creative"},
    {"name": "Imgur", "url": "https://imgur.com/user/{u}", "category": "creative"},
    {"name": "Unsplash", "url": "https://unsplash.com/@{u}", "category": "creative"},
    {"name": "500px", "url": "https://500px.com/p/{u}", "category": "creative"},
    {"name": "Figma", "url": "https://www.figma.com/@{u}", "category": "creative", "unreliable": True},
    # --- music --------------------------------------------------------------
    {"name": "SoundCloud", "url": "https://soundcloud.com/{u}", "category": "music"},
    {"name": "Bandcamp", "url": "https://bandcamp.com/{u}", "category": "music", "unreliable": True},
    {"name": "Last.fm", "url": "https://www.last.fm/user/{u}", "category": "music"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{u}", "category": "music", "unreliable": True},
    {"name": "Mixcloud", "url": "https://www.mixcloud.com/{u}", "category": "music"},
    {"name": "Audius", "url": "https://audius.co/{u}", "category": "music", "unreliable": True},
    {"name": "Discogs", "url": "https://www.discogs.com/user/{u}", "category": "music"},
    # --- video --------------------------------------------------------------
    {"name": "YouTube", "url": "https://www.youtube.com/@{u}", "category": "video", "unreliable": True},
    {"name": "Rumble", "url": "https://rumble.com/user/{u}", "category": "video"},
    {"name": "Vimeo", "url": "https://vimeo.com/{u}", "category": "video"},
    {"name": "Dailymotion", "url": "https://www.dailymotion.com/{u}", "category": "video"},
    {"name": "Odysee", "url": "https://odysee.com/@{u}", "category": "video"},
    # --- commerce -----------------------------------------------------------
    {"name": "Etsy", "url": "https://www.etsy.com/shop/{u}", "category": "commerce", "unreliable": True},
    {"name": "Gumroad", "url": "https://gumroad.com/{u}", "category": "commerce"},
    {"name": "Patreon", "url": "https://www.patreon.com/{u}", "category": "commerce", "unreliable": True},
    {"name": "Ko-fi", "url": "https://ko-fi.com/{u}", "category": "commerce"},
    {"name": "Buy Me a Coffee", "url": "https://www.buymeacoffee.com/{u}", "category": "commerce"},
    {"name": "eBay", "url": "https://www.ebay.com/usr/{u}", "category": "commerce", "unreliable": True},
    {"name": "Fiverr", "url": "https://www.fiverr.com/{u}", "category": "commerce", "unreliable": True},
    # --- professional -------------------------------------------------------
    {"name": "Product Hunt", "url": "https://www.producthunt.com/@{u}", "category": "professional"},
    {"name": "Indie Hackers", "url": "https://www.indiehackers.com/@{u}", "category": "professional"},
    {"name": "Wellfound", "url": "https://wellfound.com/u/{u}", "category": "professional", "unreliable": True},
    {"name": "Google Scholar", "url": "https://scholar.google.com/citations?user={u}", "category": "professional", "unreliable": True},
    # --- writing ------------------------------------------------------------
    {"name": "Medium", "url": "https://medium.com/@{u}", "category": "writing"},
    {"name": "Substack", "url": "https://{u}.substack.com", "category": "writing"},
    {"name": "Wattpad", "url": "https://www.wattpad.com/user/{u}", "category": "writing"},
    {"name": "Goodreads", "url": "https://www.goodreads.com/{u}", "category": "writing"},
    {"name": "Velog", "url": "https://velog.io/@{u}", "category": "writing"},
    {"name": "WordPress", "url": "https://{u}.wordpress.com", "category": "writing"},
    {"name": "Blogspot", "url": "https://{u}.blogspot.com", "category": "writing"},
    {"name": "LiveJournal", "url": "https://{u}.livejournal.com", "category": "writing"},
    {"name": "Archive of Our Own", "url": "https://archiveofourown.org/users/{u}/profile", "category": "writing"},
    # --- forums -------------------------------------------------------------
    {"name": "Lobsters", "url": "https://lobste.rs/~{u}", "category": "forum"},
    {"name": "V2EX", "url": "https://www.v2ex.com/member/{u}", "category": "forum"},
    {"name": "Hacker News", "url": "https://news.ycombinator.com/user?id={u}", "category": "forum", "unreliable": True},
    # --- other --------------------------------------------------------------
    {"name": "Duolingo", "url": "https://www.duolingo.com/profile/{u}", "category": "other"},
    {"name": "Strava", "url": "https://www.strava.com/athletes/{u}", "category": "other", "unreliable": True},
    {"name": "Archive.org", "url": "https://archive.org/details/@{u}", "category": "other"},
    {"name": "MyAnimeList", "url": "https://myanimelist.net/profile/{u}", "category": "other"},
    {"name": "AniList", "url": "https://anilist.co/user/{u}/", "category": "other"},
    {"name": "Letterboxd", "url": "https://letterboxd.com/{u}/", "category": "other"},
    {"name": "Trakt", "url": "https://trakt.tv/users/{u}", "category": "other"},
    {"name": "OpenStreetMap", "url": "https://www.openstreetmap.org/user/{u}", "category": "other"},
]

# HTTP statuses that never prove existence (blocked / method / redirect quirks)
_AMBIGUOUS = (400, 401, 403, 405, 429, 999, 301, 302, 307, 308)

# Field display order per enriched profile
_PROFILE_FIELDS: Dict[str, List[str]] = {
    "GitHub": ["name", "bio", "location", "company", "blog", "email",
               "twitter_username", "public_repos", "followers"],
    "Reddit": ["display_name", "link_karma", "total_karma",
               "created_utc", "public_description"],
    "Dev.to": ["name", "location", "summary", "github_username",
               "twitter_username"],
    "Keybase": ["username", "linked_accounts"],
}


def _classify(site: Dict[str, Any], code: int) -> str:
    """Map an HTTP status code to found / not_found / maybe / unknown."""
    unreliable = bool(site.get("unreliable"))
    if code == 200:
        return "unknown" if unreliable else "found"
    if code in (404, 410):
        return "not_found"
    if code in _AMBIGUOUS:
        return "unknown" if unreliable else "maybe"
    return "unknown"


def _check_site(site: Dict[str, Any], u: str, timeout: int,
                status_cb: Optional[Callable[[str, dict], None]]) -> dict:
    """Check a single site. Never raises."""
    url = site["url"].format(u=u)
    rec: Dict[str, Any] = {
        "site": site["name"],
        "category": site.get("category", "other"),
        "url": url,
        "status_code": None,
        "result": "unknown",
    }
    resp = None
    try:
        resp = http_get(url, timeout=timeout, stream=True)
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
            status_cb(site["name"], {
                "url": url, "result": "found",
                "category": rec["category"],
            })
        except Exception:
            pass
    return rec


# --------------------------------------------------------------------------- #
# Optional profile enrichment (silent-fail; "_status" drives sources_status)
# --------------------------------------------------------------------------- #
def _enrich_github(u: str) -> Dict[str, Any]:
    resp = None
    try:
        resp = http_get("https://api.github.com/users/" + u, timeout=8)
        if resp is None:
            return {"_status": "error: no_response"}
        if resp.status_code != 200:
            return {"_status": f"http_{resp.status_code}"}
        try:
            data = resp.json()
        except Exception:
            return {"_status": "error: bad_json"}
        if not isinstance(data, dict):
            return {"_status": "error: bad_json"}
        keys = ("name", "bio", "company", "location", "blog", "email",
                "twitter_username", "public_repos", "followers",
                "following", "created_at", "avatar_url", "html_url")
        out: Dict[str, Any] = {k: data.get(k) for k in keys}
        out["_status"] = "ok"
        return out
    except Exception as exc:
        return {"_status": f"error: {type(exc).__name__}"}
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _enrich_reddit(u: str) -> Dict[str, Any]:
    resp = None
    try:
        resp = http_get(f"https://www.reddit.com/user/{u}/about.json", timeout=8)
        if resp is None:
            return {"_status": "error: no_response"}
        if resp.status_code != 200:
            return {"_status": f"http_{resp.status_code}"}
        try:
            payload = resp.json()
        except Exception:
            return {"_status": "error: bad_json"}
        if not isinstance(payload, dict):
            return {"_status": "error: bad_json"}
        data = payload.get("data")
        if not isinstance(data, dict):
            return {"_status": "error: bad_json"}
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
        return {
            "_status": "ok",
            "icon_img": icon or None,
            "display_name": sub.get("title") or data.get("name"),
            "public_description": sub.get("public_description"),
            "created_utc": created,
            "link_karma": data.get("link_karma"),
            "total_karma": data.get("total_karma"),
            "avatar_url": icon.split("?")[0] if icon else None,
        }
    except Exception as exc:
        return {"_status": f"error: {type(exc).__name__}"}
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _enrich_devto(u: str) -> Dict[str, Any]:
    resp = None
    try:
        resp = http_get(f"https://dev.to/api/users/{u}", timeout=8)
        if resp is None:
            return {"_status": "error: no_response"}
        if resp.status_code != 200:
            return {"_status": f"http_{resp.status_code}"}
        try:
            data = resp.json()
        except Exception:
            return {"_status": "error: bad_json"}
        if not isinstance(data, dict):
            return {"_status": "error: bad_json"}
        keys = ("name", "github_username", "twitter_username",
                "location", "summary", "profile_image")
        out: Dict[str, Any] = {k: data.get(k) for k in keys}
        out["_status"] = "ok"
        return out
    except Exception as exc:
        return {"_status": f"error: {type(exc).__name__}"}
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _enrich_keybase(u: str) -> Dict[str, Any]:
    """Keybase profile + verified cross-platform proofs for a handle."""
    resp = None
    try:
        resp = http_get("https://keybase.io/_/api/1.0/user/lookup.json",
                        params={"username": u}, timeout=8)
        if resp is None:
            return {"_status": "error: no_response"}
        if resp.status_code == 404:
            return {"_status": "no_results"}
        if resp.status_code != 200:
            return {"_status": f"http_{resp.status_code}"}
        try:
            data = resp.json()
        except Exception:
            return {"_status": "error: bad_json"}
        them = (data or {}).get("them") or []
        if not them:
            return {"_status": "no_results"}
        user = them[0] if isinstance(them[0], dict) else {}
        linked: List[Dict[str, Any]] = []
        for proof in (user.get("proofs") or []):
            if not isinstance(proof, dict):
                continue
            ptype = str(proof.get("proof_type") or "").strip().lower()
            if not ptype or ptype in ("dns", "http"):
                continue
            linked.append({
                "platform": ptype,
                "handle": str(proof.get("nametracker_payload") or "")[:60],
                "url": str(proof.get("url") or "")[:200],
                "verified": bool(proof.get("verified")),
            })
        return {"_status": "ok",
                "username": user.get("username"),
                "linked_accounts": linked}
    except Exception as exc:
        return {"_status": f"error: {type(exc).__name__}"}
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def lookup_username(username: str, *, concurrency: int = 25,
                    timeout: int = 6,
                    status_cb: Optional[Callable[[str, dict], None]] = None) -> dict:
    """Enumerate ``username`` across the SITES catalogue.

    Returns a JSON-serializable dict with per-site checks, found/maybe
    lists, enriched profiles (GitHub, Reddit, Dev.to) and ``sources_status``.
    Raises ValueError for malformed usernames.
    """
    u = (username or "").strip()
    if not USERNAME_RE.fullmatch(u):
        raise ValueError("invalid username: %r" % (u,))
    reset_circuit_breaker()

    # ---- 1. concurrent profile checks (results kept in SITES order) --------
    slots: List[Optional[dict]] = [None] * len(SITES)
    workers = max(1, min(int(concurrency), len(SITES)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_check_site, site, u, timeout, status_cb): idx
            for idx, site in enumerate(SITES)
        }
        for fut in as_completed(futures):
            idx = futures[fut]
            try:
                slots[idx] = fut.result()
            except Exception:
                site = SITES[idx]
                slots[idx] = {
                    "site": site["name"],
                    "category": site.get("category", "other"),
                    "url": site["url"].format(u=u),
                    "status_code": None,
                    "result": "unknown",
                }
    checks: List[dict] = [s for s in slots if s is not None]

    # ---- 2. optional profile enrichment (concurrent, silent-fail) ---------
    profiles: Dict[str, dict] = {}
    sources_status: Dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures2 = {
            pool.submit(_enrich_github, u): ("GitHub", "enrich-github"),
            pool.submit(_enrich_reddit, u): ("Reddit", "enrich-reddit"),
            pool.submit(_enrich_devto, u): ("Dev.to", "enrich-devto"),
            pool.submit(_enrich_keybase, u): ("Keybase", "enrich-keybase"),
        }
        for fut in as_completed(futures2):
            site_name, status_key = futures2[fut]
            try:
                info = fut.result()
            except Exception as exc:
                info = {"_status": f"error: {type(exc).__name__}"}
            status = str(info.get("_status", "error: unknown"))
            sources_status[status_key] = status
            if status == "ok":
                profiles[site_name] = {k: v for k, v in info.items()
                                       if k != "_status"}

    # ---- 3. aggregate ------------------------------------------------------
    found = [ch for ch in checks if ch.get("result") == "found"]
    maybe = [ch for ch in checks if ch.get("result") == "maybe"]
    not_found_count = sum(1 for ch in checks if ch.get("result") == "not_found")
    unknown_count = sum(1 for ch in checks if ch.get("result") == "unknown")

    avatars: List[str] = []
    for prof in profiles.values():
        for key in ("avatar_url", "profile_image", "icon_img"):
            val = prof.get(key)
            if isinstance(val, str) and val.startswith("http"):
                val = val.split("?")[0]
                if val and val not in avatars:
                    avatars.append(val)

    sources_status["profile-checks"] = f"{len(found)}/{len(checks)} found"

    # ---- 4. identifier pivots: emails, linked accounts, websites ----------
    emails_found: List[Dict[str, Any]] = []
    linked_accounts: List[Dict[str, Any]] = []
    websites: List[Dict[str, Any]] = []
    seen_keys = set()

    def _pivot_email(addr: Any, source: str) -> None:
        if isinstance(addr, str) and "@" in addr:
            key = ("email", addr.lower())
            if key not in seen_keys:
                seen_keys.add(key)
                emails_found.append({"email": addr, "source": source})

    def _pivot_account(platform: Any, handle: Any, via: str,
                       url: str = "") -> None:
        if not isinstance(platform, str) or not isinstance(handle, str):
            return
        platform, handle = platform.strip().lower(), handle.strip()
        if not platform or not handle:
            return
        if platform == "github" and handle.lower() == u.lower():
            return  # the searched handle itself is not a pivot
        key = ("account", platform, handle.lower())
        if key not in seen_keys:
            seen_keys.add(key)
            linked_accounts.append({"platform": platform, "handle": handle,
                                    "via": via, "url": url or None})

    def _pivot_site(url: Any, source: str) -> None:
        if isinstance(url, str) and url.startswith("http"):
            key = ("site", url)
            if key not in seen_keys:
                seen_keys.add(key)
                websites.append({"url": url, "source": source})

    gh = profiles.get("GitHub") or {}
    _pivot_email(gh.get("email"), "github")
    _pivot_account("twitter", gh.get("twitter_username"), "github")
    _pivot_site(gh.get("blog"), "github")

    dt = profiles.get("Dev.to") or {}
    _pivot_account("twitter", dt.get("twitter_username"), "dev.to")
    _pivot_account("github", dt.get("github_username"), "dev.to")

    kb = profiles.get("Keybase") or {}
    for proof in (kb.get("linked_accounts") or []):
        if isinstance(proof, dict):
            _pivot_account(proof.get("platform"), proof.get("handle"),
                           "keybase", str(proof.get("url") or ""))

    return {
        "username": u,
        "checks": checks,
        "found": found,
        "maybe": maybe,
        "not_found_count": not_found_count,
        "unknown_count": unknown_count,
        "profiles": profiles,
        "avatars": avatars,
        "emails_found": emails_found,
        "linked_accounts": linked_accounts,
        "websites": websites,
        "dorks": username_dorks(u),
        "sources_status": sources_status,
    }


def render_text(result: dict) -> None:
    """Print a colored human-readable username-lookup report."""
    username = result.get("username", "")
    checks = result.get("checks") or []
    found = result.get("found") or []
    maybe = result.get("maybe") or []
    profiles = result.get("profiles") or {}
    avatars = result.get("avatars") or []
    sources_status = result.get("sources_status") or {}

    # SUMMARY
    header("SUMMARY")
    tone = c("green") if found else c("gray")
    print(f"  Username: {c('bold')}{c('cyan')}{username}{c('reset')}")
    print(f"  {tone}{len(found)} found / {len(checks)} checked{c('reset')}")
    print(f"  {c('gray')}{result.get('not_found_count', 0)} not found, "
          f"{result.get('unknown_count', 0)} unknown/inconclusive{c('reset')}")

    # FOUND
    header("FOUND")
    if found:
        for ch in found:
            print(f"  {c('green')}✓ {ch.get('site')}{c('reset')} "
                  f"{c('dim')}{ch.get('url')}{c('reset')}")
    else:
        print(f"  {c('gray')}none{c('reset')}")

    # MAYBE (capped at 20)
    header("MAYBE")
    if maybe:
        for ch in maybe[:20]:
            print(f"  {c('yellow')}? {ch.get('site')}{c('reset')} "
                  f"{c('dim')}{ch.get('url')}{c('reset')}")
        if len(maybe) > 20:
            print(f"  {c('gray')}... and {len(maybe) - 20} more{c('reset')}")
    else:
        print(f"  {c('gray')}none{c('reset')}")

    # ENRICHED PROFILES
    header("ENRICHED PROFILES")
    if profiles:
        for site_name, prof in profiles.items():
            print(f"  {c('bold')}{c('magenta')}{site_name}{c('reset')}")
            order = _PROFILE_FIELDS.get(site_name, sorted(prof.keys()))
            for key in order:
                val = prof.get(key)
                if val is None or (isinstance(val, str) and not val.strip()):
                    continue
                print(f"    {c('cyan')}{key}{c('reset')}: {val}")
    else:
        print(f"  {c('gray')}none{c('reset')}")

    # IDENTIFIER PIVOTS
    header("IDENTIFIER PIVOTS")
    emails_found = result.get("emails_found") or []
    linked_accounts = result.get("linked_accounts") or []
    websites = result.get("websites") or []
    if not (emails_found or linked_accounts or websites):
        print(f"  {c('gray')}(no public identifiers found){c('reset')}")
    else:
        for e in emails_found:
            print(f"  {c('green')}email{c('reset')}     {e.get('email')}"
                  f"  {c('dim')}(via {e.get('source')}){c('reset')}")
        for acc in linked_accounts:
            mark = _checkmark() if acc.get("url") else "-"
            print(f"  {c('cyan')}{mark} account{c('reset')} {acc.get('platform')}: "
                  f"{acc.get('handle')}"
                  f"  {c('dim')}(via {acc.get('via')}){c('reset')}")
        for w in websites:
            print(f"  {c('gray')}website  {w.get('url')}"
                  f"  (via {w.get('source')}){c('reset')}")
        if emails_found:
            print(f"  {c('dim')}\u2192 pivot: nexora email {emails_found[0].get('email')}"
                  f" for the full address report{c('reset')}")

    # SEARCH DORKS
    header("SEARCH DORKS")
    dorks = result.get("dorks") or []
    if dorks:
        for d in dorks:
            print(f"  {c('gray')}{d}{c('reset')}")
    else:
        print(f"  {c('gray')}(none){c('reset')}")

    # AVATARS
    header("AVATARS")
    if avatars:
        for url in avatars:
            print(f"  {c('dim')}{url}{c('reset')}")
    else:
        print(f"  {c('gray')}none{c('reset')}")

    # SOURCE STATUS
    header("SOURCE STATUS")
    line = ", ".join(f"{k}: {v}" for k, v in sorted(sources_status.items()))
    print(f"  {c('gray')}{line or 'n/a'}{c('reset')}")
