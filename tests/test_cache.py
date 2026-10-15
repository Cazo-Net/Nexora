"""Tests for nexora.cache: TTL set/get, expiry, disable flag, corruption."""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

cache = pytest.importorskip("nexora.cache")


@pytest.fixture
def cache_api(tmp_path):
    """Point the cache at tmp_path and restore global state afterwards."""
    prev_dir = cache._dir
    prev_enabled = cache.cache_enabled()
    prev_mem = dict(cache._mem)
    cache.cache_init(str(tmp_path))
    cache.cache_enable(True)
    cache._mem.clear()
    yield cache
    cache._mem.clear()
    cache._mem.update(prev_mem)
    cache.cache_init(prev_dir)
    cache.cache_enable(prev_enabled)


def test_set_get_hit(cache_api, tmp_path):
    assert cache_api.cache_enabled() is True
    assert cache_api.cache_init() == str(tmp_path)

    cache_api.cache_set("some-key", {"a": 1, "b": ["x", "y"]})
    assert cache_api.cache_get("some-key", max_age=60) == {"a": 1,
                                                           "b": ["x", "y"]}
    # persisted to disk as well
    assert os.path.isfile(cache_api._path("some-key"))

    stats = cache_api.cache_stats()
    assert stats["enabled"] is True
    assert stats["dir"] == str(tmp_path)
    assert stats["file_entries"] >= 1


def test_get_miss_for_unknown_key(cache_api):
    assert cache_api.cache_get("never-written", max_age=60) is None


def test_expiry_miss_via_time(cache_api, monkeypatch):
    now = {"t": 1000.0}
    monkeypatch.setattr(cache_api, "time",
                        SimpleNamespace(time=lambda: now["t"]))

    cache_api.cache_set("expiring", "value")
    assert cache_api.cache_get("expiring", max_age=30) == "value"

    now["t"] = 1040.0  # 40s later -> older than the 30s TTL
    assert cache_api.cache_get("expiring", max_age=30) is None

    # a fresh write is visible again
    cache_api.cache_set("expiring", "value-2")
    assert cache_api.cache_get("expiring", max_age=30) == "value-2"


def test_disable_flag(cache_api):
    cache_api.cache_set("dk", "v")
    assert cache_api.cache_get("dk", max_age=60) == "v"

    cache_api.cache_enable(False)
    assert cache_api.cache_enabled() is False
    assert cache_api.cache_get("dk", max_age=60) is None  # hidden
    cache_api.cache_set("dk2", "never-stored")            # no-op

    cache_api.cache_enable(True)
    assert cache_api.cache_get("dk", max_age=60) == "v"   # still there
    assert cache_api.cache_get("dk2", max_age=60) is None  # set while off


def test_corrupt_file_is_a_safe_miss(cache_api):
    cache_api.cache_set("ck", "v")
    path = cache_api._path("ck")
    assert os.path.isfile(path)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("{ this is not json at all")
    cache_api._mem.clear()  # force the file layer to be exercised

    assert cache_api.cache_get("ck", max_age=60) is None  # no exception
    assert not os.path.exists(path)  # corrupt entry removed


def test_cache_clear(cache_api):
    cache_api.cache_set("x", 1)
    cache_api.cache_set("y", 2)
    assert cache_api.cache_get("x", max_age=60) == 1

    cache_api.cache_clear()
    assert cache_api.cache_get("x", max_age=60) is None
    assert cache_api.cache_get("y", max_age=60) is None
    assert cache_api.cache_stats()["file_entries"] == 0
    assert cache_api.cache_stats()["memory_entries"] == 0
