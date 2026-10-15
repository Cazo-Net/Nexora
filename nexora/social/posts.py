"""Public-timeline collector: Reddit, HackerNews, GitHub events/gists,
Dev.to, Medium/Substack RSS and Mastodon statuses — all key-free.
Walled gardens (X / TikTok / Instagram / Threads) yield dorks instead.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..cache import cache_get, cache_set
from ..net import http_get, reset_circuit_breaker
from ..output import c, header

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")

# Posts are cached for 15 minutes (spec: posts 900)
_POSTS_TTL = 900.0

_PLATFORM_COLORS = {
    "reddit": "yellow", "hackernews": "yellow", "github": "gray",
    "devto": "cyan", "medium": "green", "substack": "cyan",
    "mastodon": "magenta",
}

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_RSS_ITEM_RE = re.compile(r"<item[^>]*>(.*?)</item>", re.S | re.I)
_RSS_FIELD = {
    "title": re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I),
    "link": re.compile(r"<link[^>]*>(.*?)</link>", re.S | re.I),
    "pubDate": re.compile(r"<pubDate[^>]*>(.*?)</pubDate>", re.S | re.I),
}


def _validate_handle(handle: str) -> str:
    h = (handle or "").strip()
    if not USERNAME_RE.fullmatch(h):
        raise ValueError("invalid handle: %r" % (handle,))
    return h


def _strip_html(value: str) -> str:
    return _HTML_TAG_RE.sub(" ", value or "").strip()


def _snippet(text: Any, limit: int = 200) -> str:
    clean = re.sub(r"\s+", " ", str(text or "")).strip()
    return clean[:limit]


def _iso_from_unix(ts: Any) -> Optional[str]:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except Exception:
        return None


def _iso(text: str) -> Optional[str]:
    """Normalize an ISO-8601 string (with or without Z) to isoformat."""
    try:
        value = str(text or "").strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return None


def _from_rss_date(text: str) -> Optional[str]:
    try:
        dt = parsedate_to_datetime(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return _iso(text)


def _status_for_code(code: Optional[int]) -> str:
    if code is None:
        return "error: no_response"
    if code == 200:
        return "ok"
    if code in (404, 410):
        return "http_404"
    if code in (401, 403, 405, 429, 999):
        return "blocked"
    return f"http_{code}"


# --------------------------------------------------------------------------- #
# Collectors — each returns (items, status)
# --------------------------------------------------------------------------- #
def _collect_reddit(h: str, limit: int) -> Tuple[List[dict], str]:
    key = f"social:posts:reddit:{h.lower()}"
    cached = cache_get(key, _POSTS_TTL)
    if isinstance(cached, list) and cached:
        return cached, "ok (cached)"
    url = f"https://www.reddit.com/user/{h}/submitted.json?limit={limit}"
    resp = None
    try:
        resp = http_get(url, timeout=8)
        status = _status_for_code(int(resp.status_code)) \
            if resp is not None else "error: no_response"
        if status != "ok":
            return [], status
        try:
            payload = resp.json()
        except Exception:
            return [], "error: bad_json"
        data = payload.get("data") if isinstance(payload, dict) else None
        children = data.get("children") if isinstance(data, dict) else None
        if not isinstance(children, list):
            return [], "error: bad_json"
        items: List[dict] = []
        for child in children:
            d = child.get("data") if isinstance(child, dict) else None
            if not isinstance(d, dict):
                continue
            permalink = d.get("permalink") or ""
            items.append({
                "platform": "reddit",
                "id": str(d.get("id") or ""),
                "time": _iso_from_unix(d.get("created_utc")),
                "title": _snippet(d.get("title"), 200),
                "snippet": _snippet(d.get("selftext"), 200),
                "url": ("https://www.reddit.com" + permalink)
                if permalink else None,
                "score": d.get("score"),
                "subreddit": d.get("subreddit"),
            })
        if not items:
            return [], "no_results"
        cache_set(key, items)
        return items, "ok"
    except Exception as exc:
        return [], f"error: {type(exc).__name__}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _collect_hn(h: str, limit: int) -> Tuple[List[dict], str]:
    url = ("https://hn.algolia.com/api/v1/search?query=author%%3A%s"
           "&hitsPerPage=%d" % (h, limit))
    resp = None
    try:
        resp = http_get(url, timeout=8)
        status = _status_for_code(int(resp.status_code)) \
            if resp is not None else "error: no_response"
        if status != "ok":
            return [], status
        try:
            payload = resp.json()
        except Exception:
            return [], "error: bad_json"
        hits = payload.get("hits") if isinstance(payload, dict) else None
        if not isinstance(hits, list):
            return [], "error: bad_json"
        items: List[dict] = []
        for hit in hits[:limit]:
            if not isinstance(hit, dict):
                continue
            story_id = hit.get("story_id")
            hn_url = ("https://news.ycombinator.com/item?id=%s" % story_id
                      if story_id else hit.get("url"))
            items.append({
                "platform": "hackernews",
                "id": str(hit.get("objectID") or story_id or ""),
                "time": _iso(hit.get("created_at")),
                "title": _snippet(hit.get("title"), 200),
                "snippet": _snippet(hit.get("story_text"), 200),
                "url": hn_url,
                "score": hit.get("points"),
            })
        if not items:
            return [], "no_results"
        return items, "ok"
    except Exception as exc:
        return [], f"error: {type(exc).__name__}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _collect_github_events(h: str, limit: int) -> Tuple[List[dict], str]:
    url = (f"https://api.github.com/users/{h}/events/public"
           f"?per_page={limit}")
    resp = None
    try:
        resp = http_get(url, timeout=8)
        status = _status_for_code(int(resp.status_code)) \
            if resp is not None else "error: no_response"
        if status != "ok":
            return [], status
        try:
            data = resp.json()
        except Exception:
            return [], "error: bad_json"
        if not isinstance(data, list):
            return [], "error: bad_json"
        items: List[dict] = []
        for event in data[:limit]:
            if not isinstance(event, dict):
                continue
            etype = str(event.get("type") or "Event")
            repo = (event.get("repo") or {}).get("name") \
                if isinstance(event.get("repo"), dict) else None
            title = (f"{etype} on {repo}" if repo else etype)
            items.append({
                "platform": "github",
                "id": str(event.get("id") or ""),
                "time": _iso(event.get("created_at")),
                "title": _snippet(title, 200),
                "snippet": "",
                "url": f"https://github.com/{repo}" if repo else None,
                "score": None,
            })
        if not items:
            return [], "no_results"
        return items, "ok"
    except Exception as exc:
        return [], f"error: {type(exc).__name__}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _collect_gists(h: str) -> Tuple[List[dict], str]:
    url = f"https://api.github.com/users/{h}/gists?per_page=5"
    resp = None
    try:
        resp = http_get(url, timeout=8)
        status = _status_for_code(int(resp.status_code)) \
            if resp is not None else "error: no_response"
        if status != "ok":
            return [], status
        try:
            data = resp.json()
        except Exception:
            return [], "error: bad_json"
        if not isinstance(data, list):
            return [], "error: bad_json"
        items: List[dict] = []
        for gist in data[:5]:
            if not isinstance(gist, dict):
                continue
            files = gist.get("files")
            filename = None
            if isinstance(files, dict) and files:
                filename = next(iter(files), None)
            title = gist.get("description") or filename or "gist"
            items.append({
                "platform": "github",
                "id": str(gist.get("id") or ""),
                "time": _iso(gist.get("created_at")),
                "title": _snippet(title, 200),
                "snippet": "",
                "url": gist.get("html_url"),
                "score": None,
            })
        if not items:
            return [], "no_results"
        return items, "ok"
    except Exception as exc:
        return [], f"error: {type(exc).__name__}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _collect_devto(h: str, limit: int) -> Tuple[List[dict], str]:
    url = f"https://dev.to/api/articles?username={h}&per_page={limit}"
    resp = None
    try:
        resp = http_get(url, timeout=8)
        status = _status_for_code(int(resp.status_code)) \
            if resp is not None else "error: no_response"
        if status != "ok":
            return [], status
        try:
            data = resp.json()
        except Exception:
            return [], "error: bad_json"
        if not isinstance(data, list):
            return [], "error: bad_json"
        items: List[dict] = []
        for art in data[:limit]:
            if not isinstance(art, dict):
                continue
            items.append({
                "platform": "devto",
                "id": str(art.get("id") or ""),
                "time": _iso_from_unix(art.get("published_at_int")),
                "title": _snippet(art.get("title"), 200),
                "snippet": _snippet(art.get("description"), 200),
                "url": art.get("url"),
                "score": art.get("positive_reactions_count"),
            })
        if not items:
            return [], "no_results"
        return items, "ok"
    except Exception as exc:
        return [], f"error: {type(exc).__name__}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _parse_rss_items(text: str, platform: str) -> List[dict]:
    items: List[dict] = []
    for block in _RSS_ITEM_RE.findall(text):
        title_m = _RSS_FIELD["title"].search(block)
        link_m = _RSS_FIELD["link"].search(block)
        date_m = _RSS_FIELD["pubDate"].search(block)
        title = _strip_html(title_m.group(1)).strip('" ') if title_m else ""
        link = link_m.group(1).strip() if link_m else None
        when = _from_rss_date(date_m.group(1)) if date_m else None
        items.append({
            "platform": platform,
            "id": link or "",
            "time": when,
            "title": _snippet(title, 200),
            "snippet": "",
            "url": link,
            "score": None,
        })
    return items


def _collect_rss(h: str, platform: str, url: str) -> Tuple[List[dict], str]:
    resp = None
    try:
        resp = http_get(url, timeout=8)
        status = _status_for_code(int(resp.status_code)) \
            if resp is not None else "error: no_response"
        if status != "ok":
            return [], status
        items = _parse_rss_items(resp.text or "", platform)
        if not items:
            return [], "no_results"
        return items, "ok"
    except Exception as exc:
        return [], f"error: {type(exc).__name__}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _collect_mastodon(h: str, limit: int) -> Tuple[List[dict], str]:
    resp = None
    try:
        resp = http_get(
            f"https://mastodon.social/api/v1/accounts/lookup?acct={h}",
            timeout=8)
        status = _status_for_code(int(resp.status_code)) \
            if resp is not None else "error: no_response"
        if status in ("http_404", "blocked"):
            return [], "no_results"
        if status != "ok":
            return [], status
        try:
            data = resp.json()
        except Exception:
            return [], "error: bad_json"
        if not isinstance(data, dict) or data.get("id") is None:
            return [], "no_results"
        acct_id = data["id"]
        resp2 = None
        try:
            resp2 = http_get(
                "https://mastodon.social/api/v1/accounts/%s/statuses"
                "?limit=%d" % (acct_id, limit), timeout=8)
            if resp2 is None or int(resp2.status_code) != 200:
                return [], ("no_results" if resp2 is not None
                            and int(resp2.status_code) in (401, 404)
                            else _status_for_code(
                                int(resp2.status_code) if resp2 else None))
            try:
                statuses = resp2.json()
            except Exception:
                return [], "error: bad_json"
            if not isinstance(statuses, list):
                return [], "error: bad_json"
            items: List[dict] = []
            for st in statuses[:limit]:
                if not isinstance(st, dict):
                    continue
                content = _strip_html(st.get("content") or "")
                items.append({
                    "platform": "mastodon",
                    "id": str(st.get("id") or ""),
                    "time": _iso(st.get("created_at")),
                    "title": _snippet(content, 200),
                    "snippet": _snippet(content, 200),
                    "url": st.get("url"),
                    "score": st.get("favourites_count"),
                })
            if not items:
                return [], "no_results"
            return items, "ok"
        finally:
            if resp2 is not None:
                try:
                    resp2.close()
                except Exception:
                    pass
    except Exception as exc:
        return [], f"error: {type(exc).__name__}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #
def lookup_posts(handle: str, *, limit: int = 20,
                 status_cb: Optional[Callable[[str, dict], None]] = None
                 ) -> dict:
    """Collect public timeline posts for ``handle``.

    Returns {handle, posts, counts, dorks, sources_status}.
    Raises ValueError for malformed handles.
    """
    h = _validate_handle(handle)
    reset_circuit_breaker()
    try:
        limit = max(1, min(int(limit), 100))
    except Exception:
        limit = 20

    sources_status: Dict[str, str] = {}
    collected: List[dict] = []

    collectors = {
        "reddit": lambda: _collect_reddit(h, limit),
        "hackernews": lambda: _collect_hn(h, limit),
        "github_events": lambda: _collect_github_events(h, limit),
        "github_gists": lambda: _collect_gists(h),
        "devto": lambda: _collect_devto(h, limit),
        "medium": lambda: _collect_rss(
            h, "medium", f"https://medium.com/feed/@{h}"),
        "substack": lambda: _collect_rss(
            h, "substack", f"https://{h}.substack.com/feed"),
        "mastodon": lambda: _collect_mastodon(h, limit),
    }
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {name: pool.submit(fn) for name, fn in collectors.items()}
        for name, fut in futures.items():
            try:
                items, status = fut.result()
            except Exception as exc:
                items, status = [], f"error: {type(exc).__name__}"
            sources_status[name] = status
            if status_cb is not None:
                try:
                    status_cb(name, {"status": status, "handle": h,
                                     "count": len(items)})
                except Exception:
                    pass
            collected.extend(items)

    # Dedupe on (platform, id/url); per-platform cap; overall cap of 60.
    deduped: List[dict] = []
    per_platform: Dict[str, int] = {}
    seen: set = set()
    for item in sorted(collected,
                       key=lambda p: p.get("time") or "",
                       reverse=True):
        platform = str(item.get("platform") or "?")
        ident = item.get("id") or item.get("url") or ""
        key = (platform, ident)
        if key in seen:
            continue
        if per_platform.get(platform, 0) >= limit:
            continue
        seen.add(key)
        per_platform[platform] = per_platform.get(platform, 0) + 1
        deduped.append(item)
        if len(deduped) >= 60:
            break

    counts: Dict[str, int] = {}
    for item in deduped:
        platform = str(item.get("platform") or "?")
        counts[platform] = counts.get(platform, 0) + 1

    dorks = [
        f'"{h}" site:x.com',
        f'"{h}" site:instagram.com',
        f'"{h}" site:tiktok.com',
        f'"{h}" site:threads.net',
        f'"{h}" site:pastebin.com',
        f'"{h}" site:freelancer.com',
    ]
    sources_status["dorks"] = "ok"

    return {
        "handle": h,
        "posts": deduped,
        "counts": counts,
        "dorks": dorks,
        "sources_status": sources_status,
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render_text(result: dict) -> None:
    """Print a colored human-readable posts report."""
    h = result.get("handle", "")
    posts = result.get("posts") or []
    counts = result.get("counts") or {}
    dorks = result.get("dorks") or []
    sources_status = result.get("sources_status") or {}

    header("SUMMARY")
    print(f"  Handle: {c('bold')}{c('cyan')}{h}{c('reset')}")
    print(f"  {c('green')}{len(posts)} posts collected{c('reset')}")
    if counts:
        parts = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
        print(f"  {c('yellow')}{parts}{c('reset')}")

    header("POSTS")
    if posts:
        shown: Dict[str, int] = {}
        for post in posts:
            platform = str(post.get("platform") or "?")
            if shown.get(platform, 0) >= 15:
                continue
            shown[platform] = shown.get(platform, 0) + 1
            col = c(_PLATFORM_COLORS.get(platform, "reset"))
            when = str(post.get("time") or "")[:16].replace("T", " ")
            print(f"  {col}[{platform}]{c('reset')} {c('gray')}{when}"
                  f"{c('reset')} {post.get('title')}")
            if post.get("url"):
                print(f"    {c('dim')}{post.get('url')}{c('reset')}")
    else:
        print(f"  {c('gray')}none{c('reset')}")

    header("DORKS")
    if dorks:
        for d in dorks:
            print(f"  {c('gray')}{d}{c('reset')}")
    else:
        print(f"  {c('gray')}none{c('reset')}")

    header("SOURCE STATUS")
    line = ", ".join(f"{k}: {v}" for k, v in sorted(sources_status.items()))
    print(f"  {c('gray')}{line or 'n/a'}{c('reset')}")
