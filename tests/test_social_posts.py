"""Offline tests for nexora.social.posts: hermetic Reddit / HackerNews /
GitHub / Dev.to collectors, sorting, dedup, limits and validation."""
from __future__ import annotations

import pytest

import nexora.social.posts as posts_mod
from conftest import FakeResponse


REDDIT_JSON = {
    "data": {"children": [
        {"data": {"id": "aaa", "title": "First post",
                  "permalink": "/r/test/comments/aaa/first_post/",
                  "created_utc": 1700000000, "score": 12,
                  "subreddit": "test", "selftext": "hello world"}},
        {"data": {"id": "bbb", "title": "Second post",
                  "permalink": "/r/test/comments/bbb/second_post/",
                  "created_utc": 1700000500, "score": 3,
                  "subreddit": "test", "selftext": ""}},
        # duplicate id -> must be deduped
        {"data": {"id": "aaa", "title": "First post",
                  "permalink": "/r/test/comments/aaa/first_post/",
                  "created_utc": 1700000000, "score": 12,
                  "subreddit": "test", "selftext": "hello world"}},
    ]}
}

HN_JSON = {
    "hits": [
        {"objectID": "101", "title": "Show HN: A thing",
         "created_at": "2023-11-14T12:00:00.000Z", "points": 42,
         "story_id": 9001, "url": "https://example.com",
         "story_text": None},
        {"objectID": "102", "title": "Ask HN: Why?",
         "created_at": "2023-12-01T08:30:00.000Z", "points": 7,
         "story_id": None, "url": None, "story_text": "details here"},
    ],
}

GITHUB_EVENTS = [
    {"id": "1", "type": "PushEvent",
     "repo": {"name": "testuser/demo"},
     "created_at": "2024-01-05T10:00:00Z"},
    {"id": "2", "type": "WatchEvent",
     "repo": {"name": "testuser/demo"},
     "created_at": "2024-01-06T10:00:00Z"},
]

DEVTO_ARTICLES = [
    {"id": 7, "title": "My article", "published_at_int": 1700000000,
     "positive_reactions_count": 5, "url": "https://dev.to/x/my-article",
     "description": "short desc"},
]


def _fake_http_factory(overrides=None):
    overrides = overrides or {}

    def fake_http(url, **kwargs):
        for prefix, response in overrides.items():
            if url.startswith(prefix):
                return response
        return FakeResponse(404, url=url)

    return fake_http


def _no_cache(monkeypatch):
    monkeypatch.setattr(posts_mod, "cache_get", lambda *a, **k: None)
    monkeypatch.setattr(posts_mod, "cache_set", lambda *a, **k: None)


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad", ["", "a b", "x" * 50, "user/name", None])
def test_lookup_posts_rejects_invalid(bad):
    with pytest.raises(ValueError):
        posts_mod.lookup_posts(bad)


# --------------------------------------------------------------------------- #
# Hermetic collection
# --------------------------------------------------------------------------- #
def test_reddit_parsing(monkeypatch):
    _no_cache(monkeypatch)
    monkeypatch.setattr(posts_mod, "http_get", _fake_http_factory({
        "https://www.reddit.com/user/testuser/submitted.json":
            FakeResponse(200, json_data=REDDIT_JSON),
    }))
    result = posts_mod.lookup_posts("testuser")
    reddit = [p for p in result["posts"] if p["platform"] == "reddit"]
    # duplicate id deduped
    assert len(reddit) == 2
    by_id = {p["id"]: p for p in reddit}
    post = by_id["aaa"]
    assert post["title"] == "First post"
    assert post["url"] == ("https://www.reddit.com"
                           "/r/test/comments/aaa/first_post/")
    assert post["score"] == 12
    assert post["time"] is not None
    assert post["time"].startswith("2023-11-14")  # 1700000000 utc
    assert result["sources_status"]["reddit"] == "ok"
    assert result["counts"]["reddit"] == 2


def test_hn_parsing(monkeypatch):
    _no_cache(monkeypatch)
    monkeypatch.setattr(posts_mod, "http_get", _fake_http_factory({
        "https://hn.algolia.com/api/v1/search":
            FakeResponse(200, json_data=HN_JSON),
    }))
    result = posts_mod.lookup_posts("testuser")
    hn = [p for p in result["posts"] if p["platform"] == "hackernews"]
    assert len(hn) == 2
    by_id = {p["id"]: p for p in hn}
    show = by_id["101"]
    assert show["title"] == "Show HN: A thing"
    assert show["url"] == "https://news.ycombinator.com/item?id=9001"
    assert show["score"] == 42
    ask = by_id["102"]
    assert ask["url"] is None  # no story_id, no external url
    assert ask["snippet"] == "details here"
    assert result["sources_status"]["hackernews"] == "ok"


def test_github_events_and_devto(monkeypatch):
    _no_cache(monkeypatch)
    monkeypatch.setattr(posts_mod, "http_get", _fake_http_factory({
        "https://api.github.com/users/testuser/events/public":
            FakeResponse(200, json_data=GITHUB_EVENTS),
        "https://dev.to/api/articles":
            FakeResponse(200, json_data=DEVTO_ARTICLES),
    }))
    result = posts_mod.lookup_posts("testuser")
    events = [p for p in result["posts"] if p["title"].endswith("on testuser/demo")]
    assert len(events) == 2
    assert any(p["title"] == "PushEvent on testuser/demo" for p in events)
    devto = [p for p in result["posts"] if p["platform"] == "devto"]
    assert devto and devto[0]["title"] == "My article"
    assert devto[0]["score"] == 5
    assert result["sources_status"]["github_events"] == "ok"
    assert result["sources_status"]["devto"] == "ok"


def test_sorting_dedup_and_limits(monkeypatch):
    _no_cache(monkeypatch)
    # many reddit posts with descending times; also a duplicate id
    children = []
    for i in range(30):
        children.append({"data": {
            "id": str(i), "title": "post %d" % i,
            "permalink": "/r/test/%d" % i,
            "created_utc": 1700000000 + i * 60, "score": i,
            "subreddit": "test", "selftext": ""}})
    children.append(dict(children[0]))  # duplicate of id 0
    reddit_json = {"data": {"children": children}}

    monkeypatch.setattr(posts_mod, "http_get", _fake_http_factory({
        "https://www.reddit.com/user/testuser/submitted.json":
            FakeResponse(200, json_data=reddit_json),
    }))
    result = posts_mod.lookup_posts("testuser", limit=5)
    reddit = [p for p in result["posts"] if p["platform"] == "reddit"]
    # per-platform limit respected (dedup happens before limiting)
    assert len(reddit) == 5
    # sorted newest-first
    times = [p["time"] for p in reddit]
    assert times == sorted(times, reverse=True)
    # newest post is the one kept
    assert reddit[0]["id"] == "29"
    assert result["counts"]["reddit"] == 5


def test_overall_cap_of_sixty(monkeypatch):
    _no_cache(monkeypatch)
    children = [{"data": {
        "id": str(i), "title": "p%d" % i, "permalink": "/r/t/%d" % i,
        "created_utc": 1700000000 + i, "score": 1,
        "subreddit": "t", "selftext": ""}} for i in range(80)]
    monkeypatch.setattr(posts_mod, "http_get", _fake_http_factory({
        "https://www.reddit.com/user/testuser/submitted.json":
            FakeResponse(200, json_data={"data": {"children": children}}),
    }))
    result = posts_mod.lookup_posts("testuser", limit=100)
    assert len(result["posts"]) <= 60


def test_sources_status_graceful(monkeypatch):
    _no_cache(monkeypatch)
    # everything dead -> statuses degrade, never raise
    monkeypatch.setattr(posts_mod, "http_get", lambda url, **kw: None)
    result = posts_mod.lookup_posts("testuser")
    assert result["posts"] == []
    assert result["sources_status"]["reddit"] == "error: no_response"
    assert "dorks" in result


def test_walled_gardens_never_fetched(monkeypatch):
    _no_cache(monkeypatch)
    fetched = []

    def fake_http(url, **kwargs):
        fetched.append(url)
        return FakeResponse(404, url=url)

    monkeypatch.setattr(posts_mod, "http_get", fake_http)
    result = posts_mod.lookup_posts("testuser")
    joined = " ".join(fetched)
    assert "x.com" not in joined
    assert "instagram.com" not in joined
    assert "tiktok.com" not in joined
    assert "threads.net" not in joined
    # ...but dork suggestions cover them
    assert any("site:x.com" in d for d in result["dorks"])
    assert any("site:pastebin.com" in d for d in result["dorks"])


def test_render_text_smoke(monkeypatch, capsys):
    _no_cache(monkeypatch)
    monkeypatch.setattr(posts_mod, "http_get", _fake_http_factory({
        "https://www.reddit.com/user/testuser/submitted.json":
            FakeResponse(200, json_data=REDDIT_JSON),
    }))
    result = posts_mod.lookup_posts("testuser")
    posts_mod.render_text(result)
    out = capsys.readouterr().out
    assert "First post" in out
    assert "SUMMARY" in out
