"""Shared network helpers for Nexora CLI modules.

Provides a pooled, retrying HTTP session with a circuit-breaker for dead
hosts, plus graceful DNS helpers (dnspython when available, socket fallback).
Every function degrades gracefully: HTTP helpers return ``None`` on failure,
DNS helpers return empty lists.
"""
from __future__ import annotations

import socket
import time
import warnings
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

try:
    import dns.resolver  # type: ignore
    _HAS_DNS = True
except ImportError:  # pragma: no cover
    _HAS_DNS = False

USER_AGENT = {"User-Agent": "Mozilla/5.0 (compatible; Nexora/2.1; +https://nexora.io)"}
DEFAULT_TIMEOUT = 8

_session = requests.Session()
_adapter = HTTPAdapter(
    max_retries=Retry(total=1, backoff_factor=0.2, status_forcelist=[502, 503, 504]),
    pool_connections=20,
    pool_maxsize=20,
)
_session.mount("https://", _adapter)
_session.mount("http://", _adapter)

# Circuit-breaker: hosts that fail are skipped for _DEAD_HOST_TTL seconds.
_DEAD_HOSTS: Dict[str, float] = {}
_DEAD_HOST_TTL = 300

# Optional politeness delay between requests to the same host (config [net]).
_PER_HOST_DELAY = 0.0
_LAST_REQ: Dict[str, float] = {}


def apply_config(cfg: Optional[dict]) -> None:
    """Apply the ``[net]`` section of the user config. Never raises.

    Keys: ``proxy`` (http/https/socks5 URL), ``user_agent``,
    ``per_host_delay`` (seconds between requests to one host).
    Empty/invalid values keep the current defaults.
    """
    global USER_AGENT, _PER_HOST_DELAY
    if not isinstance(cfg, dict):
        return
    ua = str(cfg.get("user_agent") or "").strip()
    if ua:
        USER_AGENT = {"User-Agent": ua}
    proxy = str(cfg.get("proxy") or "").strip()
    if proxy:
        try:
            _session.proxies.update({"http": proxy, "https": proxy})
        except Exception:
            pass
    try:
        delay = float(cfg.get("per_host_delay") or 0.0)
        _PER_HOST_DELAY = delay if delay > 0 else 0.0
    except (TypeError, ValueError):
        pass


def _throttle(host: Optional[str]) -> None:
    """Best-effort per-host politeness delay (no-op unless configured)."""
    if not _PER_HOST_DELAY or not host:
        return
    try:
        last = _LAST_REQ.get(host)
        now = time.monotonic()
        if last is not None:
            wait = _PER_HOST_DELAY - (now - last)
            if wait > 0:
                time.sleep(wait)
        _LAST_REQ[host] = time.monotonic()
    except Exception:
        pass


def _is_dead(host: Optional[str]) -> bool:
    if not host:
        return False
    expiry = _DEAD_HOSTS.get(host)
    if expiry is None:
        return False
    if time.time() < expiry:
        return True
    _DEAD_HOSTS.pop(host, None)
    return False


def _mark_dead(host: Optional[str]) -> None:
    if host:
        _DEAD_HOSTS[host] = time.time() + _DEAD_HOST_TTL


def reset_circuit_breaker() -> None:
    """Clear the dead-host blacklist (call at the start of each scan)."""
    _DEAD_HOSTS.clear()


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
def http_get(
    url: str,
    params: Optional[dict] = None,
    headers: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
    stream: bool = False,
    allow_redirects: bool = True,
):
    """GET request via the pooled session. Returns a Response or None."""
    host = urlparse(url).hostname
    if _is_dead(host):
        return None
    _throttle(host)
    try:
        resp = _session.get(
            url, params=params, headers={**USER_AGENT, **(headers or {})},
            timeout=timeout, allow_redirects=allow_redirects, stream=stream,
        )
        # Retry once on rate-limit / transient server errors
        if resp.status_code in (429, 503) and not stream:
            time.sleep(1)
            resp = _session.get(
                url, params=params, headers={**USER_AGENT, **(headers or {})},
                timeout=timeout, allow_redirects=allow_redirects,
            )
        return resp
    except Exception:
        _mark_dead(host)
        return None


def http_post(
    url: str,
    data: Optional[dict] = None,
    json_body: Optional[object] = None,
    headers: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
):
    """POST request via the pooled session. Returns a Response or None."""
    host = urlparse(url).hostname
    if _is_dead(host):
        return None
    _throttle(host)
    try:
        return _session.post(
            url, data=data, json=json_body,
            headers={**USER_AGENT, **(headers or {})}, timeout=timeout,
        )
    except Exception:
        _mark_dead(host)
        return None


# --------------------------------------------------------------------------- #
# DNS helpers (dnspython when available; A-record socket fallback)
# --------------------------------------------------------------------------- #
def resolve_a(host: str, timeout: float = 3.0) -> List[str]:
    if _HAS_DNS:
        try:
            answers = dns.resolver.resolve(host, "A", lifetime=timeout)
            return [r.to_text() for r in answers]
        except Exception:
            return []
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except Exception:
        return []


def resolve_txt(host: str, timeout: float = 3.0) -> List[str]:
    if not _HAS_DNS:
        return []
    try:
        answers = dns.resolver.resolve(host, "TXT", lifetime=timeout)
        out: List[str] = []
        for r in answers:
            out.append("".join(
                s.decode("utf-8", "ignore") if isinstance(s, bytes) else s
                for s in r.strings
            ))
        return out
    except Exception:
        return []


def resolve_mx(host: str, timeout: float = 3.0) -> List[str]:
    """MX exchange hostnames, priority-sorted (lowest preference first)."""
    if not _HAS_DNS:
        return []
    try:
        answers = dns.resolver.resolve(host, "MX", lifetime=timeout)
        pairs = sorted((r.preference, str(r.exchange).rstrip(".")) for r in answers)
        return [h for _, h in pairs]
    except Exception:
        return []


def resolve_ns(host: str, timeout: float = 3.0) -> List[str]:
    if not _HAS_DNS:
        return []
    try:
        answers = dns.resolver.resolve(host, "NS", lifetime=timeout)
        return [str(r.target).rstrip(".") for r in answers]
    except Exception:
        return []
