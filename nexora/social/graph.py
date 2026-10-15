"""Relationship-graph builder: GitHub follows, Reddit communities,
Keybase linked identities, link-in-bio link-outs and Mastodon followers.

All key-free; produces plain JSON nodes/edges with graceful
``sources_status`` degradation.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..net import http_get, reset_circuit_breaker
from ..output import c, header

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")

_EDGE_CAP = 400
_NODE_CAP = 1000

# host fragment -> platform label used for link-out nodes
_SOCIAL_HOSTS = (
    ("twitter.com", "x"), ("x.com", "x"), ("t.co", "x"),
    ("instagram.com", "instagram"), ("tiktok.com", "tiktok"),
    ("facebook.com", "facebook"), ("threads.net", "threads"),
    ("github.com", "github"), ("gitlab.com", "gitlab"),
    ("reddit.com", "reddit"), ("linkedin.com", "linkedin"),
    ("youtube.com", "youtube"), ("youtu.be", "youtube"),
    ("twitch.tv", "twitch"), ("t.me", "telegram"),
    ("telegram.me", "telegram"), ("discord.gg", "discord"),
    ("discord.com", "discord"), ("medium.com", "medium"),
    ("mastodon.social", "mastodon"), ("hachyderm.io", "mastodon"),
    ("bsky.app", "bluesky"), ("bsky.social", "bluesky"),
    ("soundcloud.com", "soundcloud"), ("steamcommunity.com", "steam"),
    ("keybase.io", "keybase"), ("linktr.ee", "linktree"),
    ("about.me", "aboutme"), ("pinterest.com", "pinterest"),
    ("vimeo.com", "vimeo"), ("flickr.com", "flickr"),
)


def _validate_handle(handle: str) -> str:
    h = (handle or "").strip()
    if not USERNAME_RE.fullmatch(h):
        raise ValueError("invalid handle: %r" % (handle,))
    return h


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


def _read_body(url: str, timeout: int = 8, cap: int = 512 * 1024
               ) -> Tuple[Optional[int], bytes]:
    """Streamed GET; returns (status_code, body_bytes up to cap)."""
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


# --------------------------------------------------------------------------- #
# Collectors — each returns (nodes, edges, status)
# --------------------------------------------------------------------------- #
def _collect_github_follow(h: str, kind: str, max_items: int
                           ) -> Tuple[List[dict], List[dict], str]:
    """GitHub followers / following (kind: 'followers'|'following')."""
    url = ("https://api.github.com/users/%s/%s?per_page=%d"
           % (h, kind, max_items))
    resp = None
    try:
        resp = http_get(url, timeout=8)
        status = _status_for_code(int(resp.status_code)) \
            if resp is not None else "error: no_response"
        if status != "ok":
            return [], [], status
        try:
            data = resp.json()
        except Exception:
            return [], [], "error: bad_json"
        if not isinstance(data, list):
            return [], [], "error: bad_json"
        root = "github:" + h
        nodes: List[dict] = []
        edges: List[dict] = []
        for entry in data[:max_items]:
            if not isinstance(entry, dict):
                continue
            login = str(entry.get("login") or "").strip()
            if not login:
                continue
            nid = "github:" + login
            nodes.append({"id": nid, "type": "person", "platform": "github",
                          "url": entry.get("html_url")
                          or "https://github.com/" + login})
            edges.append({"source": root, "target": nid, "type": "follows"})
        return nodes, edges, ("ok" if edges else "no_results")
    except Exception as exc:
        return [], [], f"error: {type(exc).__name__}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _collect_reddit_communities(h: str) -> Tuple[List[dict], List[dict], str]:
    url = f"https://www.reddit.com/user/{h}/subreddits/about.json"
    resp = None
    try:
        resp = http_get(url, timeout=8)
        status = _status_for_code(int(resp.status_code)) \
            if resp is not None else "error: no_response"
        if status != "ok":
            return [], [], status
        try:
            payload = resp.json()
        except Exception:
            return [], [], "error: bad_json"
        data = payload.get("data") if isinstance(payload, dict) else None
        children = data.get("children") if isinstance(data, dict) else None
        if not isinstance(children, list):
            return [], [], "error: bad_json"
        root = "reddit:" + h
        nodes: List[dict] = []
        edges: List[dict] = []
        for child in children:
            d = child.get("data") if isinstance(child, dict) else None
            name = d.get("display_name") if isinstance(d, dict) else None
            if not name:
                continue
            nid = "reddit-community:" + str(name)
            nodes.append({"id": nid, "type": "community", "platform": "reddit",
                          "url": "https://www.reddit.com/r/%s/" % name})
            edges.append({"source": root, "target": nid, "type": "posts_in"})
        return nodes, edges, ("ok" if edges else "no_results")
    except Exception as exc:
        return [], [], f"error: {type(exc).__name__}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _collect_keybase_identities(h: str) -> Tuple[List[dict], List[dict], str]:
    url = ("https://keybase.io/_/api/1.0/user/lookup.json?username=" + h)
    resp = None
    try:
        resp = http_get(url, timeout=8)
        status = _status_for_code(int(resp.status_code)) \
            if resp is not None else "error: no_response"
        if status != "ok":
            return [], [], status
        try:
            payload = resp.json()
        except Exception:
            return [], [], "error: bad_json"
        them = payload.get("them") if isinstance(payload, dict) else None
        if not isinstance(them, list) or not them:
            return [], [], "no_results"
        proofs = them[0].get("proofs") or []
        root = "keybase:" + h
        nodes: List[dict] = []
        edges: List[dict] = []
        seen: set = set()
        for proof in proofs:
            if not isinstance(proof, dict):
                continue
            ptype = str(proof.get("proof_type") or "").strip()
            if not ptype or ptype in seen:
                continue
            seen.add(ptype)
            nid = "kb:" + ptype
            nodes.append({"id": nid, "type": "identity", "platform": "keybase",
                          "external": proof.get("url"),
                          "url": proof.get("url")})
            edges.append({"source": root, "target": nid,
                          "type": "linked_identity"})
        return nodes, edges, ("ok" if edges else "no_results")
    except Exception as exc:
        return [], [], f"error: {type(exc).__name__}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def _collect_link_outs(h: str) -> Tuple[List[dict], List[dict], str]:
    """Anchor hrefs from linktr.ee / about.me (social domains only)."""
    nodes: List[dict] = []
    edges: List[dict] = []
    statuses: List[str] = []
    seen_urls: set = set()
    for base in (f"https://linktr.ee/{h}", f"https://about.me/{h}"):
        code, body = _read_body(base)
        statuses.append(_status_for_code(code))
        if code != 200:
            continue
        html = body.decode("utf-8", "ignore")
        for href in re.findall(r'href=["\']([^"\']+)["\']', html, re.I):
            if href.startswith("//"):
                href = "https:" + href
            if not href.startswith("http"):
                continue
            host = (urlparse(href).hostname or "").lower()
            if not host:
                continue
            # skip self links
            if "linktr.ee" in host or "about.me" in host:
                continue
            platform = None
            for frag, label in _SOCIAL_HOSTS:
                if host == frag or host.endswith("." + frag):
                    platform = label
                    break
            if platform is None:
                continue
            key = (platform, href.split("#")[0])
            if key in seen_urls:
                continue
            seen_urls.add(key)
            if len(seen_urls) > 30:
                break
            nid = "linkout:%s" % href.split("#")[0]
            nodes.append({"id": nid, "type": "person", "platform": platform,
                          "url": href})
            edges.append({"source": "linktree:" + h, "target": nid,
                          "type": "link_out"})
    if not nodes:
        return [], [], ("ok" if any(s == "ok" for s in statuses)
                        else (statuses[0] if statuses else "no_results"))
    return nodes, edges, "ok"


def _collect_mastodon(h: str, max_items: int
                      ) -> Tuple[List[dict], List[dict], str]:
    resp = None
    try:
        resp = http_get(
            f"https://mastodon.social/api/v1/accounts/lookup?acct={h}",
            timeout=8)
        status = _status_for_code(int(resp.status_code)) \
            if resp is not None else "error: no_response"
        if status in ("http_404", "blocked"):
            # lookup miss / instance policy — not an error
            return [], [], "no_results"
        if status != "ok":
            return [], [], status
        try:
            data = resp.json()
        except Exception:
            return [], [], "error: bad_json"
        if not isinstance(data, dict) or data.get("id") is None:
            return [], [], "no_results"
        acct_id = data["id"]
        root = "mastodon:" + h
        nodes: List[dict] = [{"id": root, "type": "person",
                              "platform": "mastodon",
                              "url": "https://mastodon.social/@%s" % h}]
        edges: List[dict] = []
        # best-effort followers (401/404 -> no_results, NOT an error)
        resp2 = None
        try:
            resp2 = http_get(
                "https://mastodon.social/api/v1/accounts/%s/followers"
                "?limit=%d" % (acct_id, min(max_items, 40)), timeout=8)
            if resp2 is not None and int(resp2.status_code) == 200:
                followers = resp2.json()
                if isinstance(followers, list):
                    for entry in followers[:max_items]:
                        if not isinstance(entry, dict):
                            continue
                        acct = str(entry.get("acct") or
                                   entry.get("username") or "").strip()
                        if not acct:
                            continue
                        nid = "mastodon:" + acct
                        nodes.append({"id": nid, "type": "person",
                                      "platform": "mastodon",
                                      "url": "https://mastodon.social/@%s"
                                      % acct})
                        edges.append({"source": root, "target": nid,
                                      "type": "follows"})
        finally:
            if resp2 is not None:
                try:
                    resp2.close()
                except Exception:
                    pass
        return nodes, edges, ("ok" if edges else "no_results")
    except Exception as exc:
        return [], [], f"error: {type(exc).__name__}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #
def lookup_graph(handle: str, *, max_items: int = 100,
                 status_cb: Optional[Callable[[str, dict], None]] = None
                 ) -> dict:
    """Build a nodes/edges relationship graph for ``handle``.

    Returns {handle, nodes, edges, counts, truncated, sources_status}.
    Raises ValueError for malformed handles.
    """
    h = _validate_handle(handle)
    reset_circuit_breaker()
    try:
        max_items = max(1, min(int(max_items), 100))
    except Exception:
        max_items = 100

    sources_status: Dict[str, str] = {}
    nodes_by_id: Dict[str, dict] = {}
    edges_seen: set = set()
    edges: List[dict] = []

    def _add_nodes(items: List[dict]) -> None:
        for node in items:
            nid = node.get("id")
            if not nid or nid in nodes_by_id:
                continue
            if len(nodes_by_id) >= _NODE_CAP:
                return
            nodes_by_id[nid] = node

    def _add_edges(items: List[dict]) -> None:
        for edge in items:
            key = (edge.get("source"), edge.get("target"), edge.get("type"))
            if key in edges_seen:
                continue
            edges_seen.add(key)
            edges.append(edge)

    collectors = {
        "github_followers": lambda: _collect_github_follow(
            h, "followers", max_items),
        "github_following": lambda: _collect_github_follow(
            h, "following", max_items),
        "reddit_communities": lambda: _collect_reddit_communities(h),
        "keybase_identities": lambda: _collect_keybase_identities(h),
        "link_outs": lambda: _collect_link_outs(h),
        "mastodon": lambda: _collect_mastodon(h, max_items),
    }
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {name: pool.submit(fn) for name, fn in collectors.items()}
        for name, fut in futures.items():
            try:
                nodes, edge_list, status = fut.result()
            except Exception as exc:
                nodes, edge_list, status = [], [], f"error: {type(exc).__name__}"
            sources_status[name] = status
            if status_cb is not None:
                try:
                    status_cb(name, {"status": status, "handle": h})
                except Exception:
                    pass
            _add_nodes(nodes)
            _add_edges(edge_list)

    truncated = False
    if len(edges) > _EDGE_CAP:
        edges = edges[:_EDGE_CAP]
        truncated = True
    if len(nodes_by_id) >= _NODE_CAP:
        truncated = True

    by_type: Dict[str, int] = {}
    for edge in edges:
        t = str(edge.get("type") or "unknown")
        by_type[t] = by_type.get(t, 0) + 1

    counts = {"nodes": len(nodes_by_id), "edges": len(edges),
              "by_type": by_type}
    return {
        "handle": h,
        "nodes": list(nodes_by_id.values()),
        "edges": edges,
        "counts": counts,
        "truncated": truncated,
        "sources_status": sources_status,
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _edge_color(edge: dict) -> str:
    target = str(edge.get("target") or "")
    platform = target.split(":", 1)[0] if ":" in target else ""
    return {
        "github": c("gray"), "reddit": c("yellow"),
        "reddit-community": c("yellow"), "mastodon": c("magenta"),
        "kb": c("cyan"), "keybase": c("cyan"), "linkout": c("blue"),
    }.get(platform, c("reset"))


def render_text(result: dict) -> None:
    """Print a colored human-readable relationship-graph report."""
    h = result.get("handle", "")
    nodes = result.get("nodes") or []
    edges = result.get("edges") or []
    counts = result.get("counts") or {}
    by_type = counts.get("by_type") or {}
    sources_status = result.get("sources_status") or {}

    header("SUMMARY")
    print(f"  Handle: {c('bold')}{c('cyan')}{h}{c('reset')}")
    print(f"  {c('green')}{counts.get('nodes', len(nodes))} nodes, "
          f"{counts.get('edges', len(edges))} edges{c('reset')}")
    if result.get("truncated"):
        print(f"  {c('yellow')}graph truncated (cap reached){c('reset')}")

    order = ["follows", "linked_identity", "posts_in", "link_out"]
    for etype in order:
        group = [e for e in edges if e.get("type") == etype]
        if not group:
            continue
        header("EDGES: " + etype.upper())
        for edge in group[:20]:
            col = _edge_color(edge)
            print(f"  {edge.get('source')} {col}--{etype}-->{c('reset')} "
                  f"{col}{edge.get('target')}{c('reset')}")
        if len(group) > 20:
            print(f"  {c('gray')}... and {len(group) - 20} more{c('reset')}")

    linked = [n for n in nodes if n.get("type") == "identity"]
    if linked:
        header("LINKED IDENTITIES")
        for node in linked:
            ext = node.get("external") or node.get("url") or ""
            print(f"  {c('green')}• {node.get('id')}{c('reset')} "
                  f"{c('dim')}{ext}{c('reset')}")

    communities = [n for n in nodes if n.get("type") == "community"]
    if communities:
        header("COMMUNITIES")
        for node in communities[:30]:
            print(f"  {c('yellow')}• {node.get('id')}{c('reset')} "
                  f"{c('dim')}{node.get('url')}{c('reset')}")
        if len(communities) > 30:
            print(f"  {c('gray')}... and {len(communities) - 30} more"
                  f"{c('reset')}")

    header("SOURCE STATUS")
    line = ", ".join(f"{k}: {v}" for k, v in sorted(sources_status.items()))
    print(f"  {c('gray')}{line or 'n/a'}{c('reset')}")
    if by_type:
        line2 = ", ".join(f"{k}: {v}" for k, v in sorted(by_type.items()))
        print(f"  {c('gray')}{line2}{c('reset')}")
