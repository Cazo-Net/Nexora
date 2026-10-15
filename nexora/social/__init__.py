"""SOCIAL MEDIA OSINT CENTER — Nexora's flagship "advanced content" layer.

Five key-free, gracefully-degrading entry points:

* ``lookup_identity`` — username correlation engine: presence across the
  105-site catalogue, profile metadata enrichment (GitHub / Reddit /
  Keybase / Steam / Linktree / Dev.to), avatar + alias harvesting and a
  pure 0-100 identity-correlation score.
* ``lookup_graph``    — follower / community / cross-platform identity
  graph (GitHub follows, Reddit communities, Keybase linked identities,
  link-in-bio link-outs, Mastodon followers) as nodes + edges.
* ``lookup_posts``    — public timelines reachable without API keys
  (Reddit, HackerNews, GitHub, Dev.to, Medium/Substack RSS, Mastodon)
  plus dork suggestions for the walled gardens.
* ``inspect_media``   — EXIF / GPS leak analysis for images and pages,
  plus link-in-bio crawl (``handle:`` targets). Alias: ``lookup_media``.
* ``lookup_brand``    — official-account discovery from a homepage and
  impersonation-candidate detection across relevant platforms.

Every module exposes ``lookup_*(...) -> dict`` (plain JSON-serializable)
and ``render_text(result) -> None``; failures land in ``sources_status``.
Walled gardens (X / TikTok / Instagram / Facebook) are NEVER scraped —
they yield dork suggestions instead.

Each import is guarded so one broken submodule never kills the package;
``SOCIAL_MODULES`` maps a short name to its callable-or-None entry point.
"""
from __future__ import annotations

from typing import Callable, Dict, Optional

try:  # pragma: no cover - defensive import
    from .identity import lookup_identity
except Exception:  # pragma: no cover
    lookup_identity = None  # type: ignore

try:  # pragma: no cover - defensive import
    from .graph import lookup_graph
except Exception:  # pragma: no cover
    lookup_graph = None  # type: ignore

try:  # pragma: no cover - defensive import
    from .posts import lookup_posts
except Exception:  # pragma: no cover
    lookup_posts = None  # type: ignore

try:  # pragma: no cover - defensive import
    from .media import inspect_media, lookup_media
except Exception:  # pragma: no cover
    inspect_media = None  # type: ignore
    lookup_media = None  # type: ignore

try:  # pragma: no cover - defensive import
    from .brand import lookup_brand
except Exception:  # pragma: no cover
    lookup_brand = None  # type: ignore

SOCIAL_MODULES: Dict[str, Optional[Callable[..., dict]]] = {
    "identity": lookup_identity,
    "graph": lookup_graph,
    "posts": lookup_posts,
    "media": inspect_media,
    "brand": lookup_brand,
}

__all__ = [
    "lookup_identity",
    "lookup_graph",
    "lookup_posts",
    "inspect_media",
    "lookup_media",
    "lookup_brand",
    "SOCIAL_MODULES",
]
