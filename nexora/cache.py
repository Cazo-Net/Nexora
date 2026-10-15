"""Tiny TTL cache shared by the engine and CLI modules.

Two layers:
* in-memory dict (per process) — survives within a run/watch loop
* JSON files under ``~/.nexora/cache/`` — survives across runs

Public interface:
    cache_init(dir=None) -> str       set/return cache directory
    cache_enable(flag=True)           turn the cache on/off (e.g. --no-cache)
    cache_enabled() -> bool
    cache_get(key, max_age) -> value | None
    cache_set(key, value)             best effort, never raises
    cache_clear()                     drop memory + files
    cache_stats() -> dict

Misses, corrupt files, oversized payloads and OS errors are all silent
``None``/no-op outcomes — the cache can never break a scan.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Any, Dict, Optional

DEFAULT_DIR = os.path.join(os.path.expanduser("~"), ".nexora", "cache")
_MAX_FILE_BYTES = 2_000_000  # don't persist huge bodies

_lock = threading.Lock()
_dir: str = DEFAULT_DIR
_enabled = True
# key -> (timestamp, value)
_mem: Dict[str, tuple] = {}


def cache_init(dir: Optional[str] = None) -> str:
    """Set (optional) and return the cache directory."""
    global _dir
    if dir:
        _dir = dir
    return _dir


def cache_enable(flag: bool = True) -> None:
    global _enabled
    _enabled = bool(flag)


def cache_enabled() -> bool:
    return _enabled


def _path(key: str) -> str:
    digest = hashlib.sha1(key.encode("utf-8", "ignore")).hexdigest()
    return os.path.join(_dir, digest + ".json")


def cache_get(key: str, max_age: float) -> Any:
    """Return a cached value younger than ``max_age`` seconds, else None."""
    if not _enabled:
        return None
    now = time.time()
    with _lock:
        hit = _mem.get(key)
        if hit is not None:
            ts, value = hit
            if now - ts <= max_age:
                return value
            _mem.pop(key, None)
            # stale in memory => stale on disk too (same write)
            return None
    # file layer (fresh process)
    try:
        path = _path(key)
        if not os.path.isfile(path):
            return None
        if now - os.path.getmtime(path) > max_age * 2:
            # cheap pre-check before reading
            os.remove(path)
            return None
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict) or "ts" not in data:
            raise ValueError("bad cache entry")
        if now - float(data["ts"]) > max_age:
            return None
        value = data.get("value")
        with _lock:
            _mem[key] = (float(data["ts"]), value)
        return value
    except Exception:
        # corrupt / unreadable — remove and treat as a miss
        try:
            os.remove(_path(key))
        except Exception:
            pass
        return None


def cache_set(key: str, value: Any) -> None:
    """Store a JSON-serializable value (best effort; never raises)."""
    if not _enabled:
        return
    now = time.time()
    with _lock:
        _mem[key] = (now, value)
    try:
        blob = json.dumps(
            {"ts": now, "key": key, "value": value},
            ensure_ascii=False, default=str,
        )
        if len(blob) > _MAX_FILE_BYTES:
            return
        os.makedirs(_dir, exist_ok=True)
        path = _path(key)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(blob)
        os.replace(tmp, path)
    except Exception:
        pass


def cache_clear() -> None:
    """Drop every cached entry (memory + files)."""
    with _lock:
        _mem.clear()
    try:
        for name in os.listdir(_dir):
            if name.endswith(".json") or name.endswith(".tmp"):
                try:
                    os.remove(os.path.join(_dir, name))
                except Exception:
                    pass
    except Exception:
        pass


def cache_stats() -> Dict[str, Any]:
    """Small diagnostic summary (used by ``osint sources --json``)."""
    files = 0
    try:
        files = len([n for n in os.listdir(_dir) if n.endswith(".json")])
    except Exception:
        pass
    with _lock:
        mem = len(_mem)
    return {"enabled": _enabled, "dir": _dir, "memory_entries": mem,
            "file_entries": files}
