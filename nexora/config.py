"""User configuration for Nexora — ``~/.nexora/config.toml``.

Merge order (later wins): built-in defaults < config file < CLI flags.

Every key is optional; a missing/invalid/unsupported file silently yields
the defaults. ``NEXORA_CONFIG`` env var overrides the path.

Example::

    [defaults]
    profile = "stealth"
    timeout = 90

    [net]
    proxy = "http://127.0.0.1:8080"   # or socks5://127.0.0.1:9050
    user_agent = "my-scanner/1.0"
    per_host_delay = 0.5              # politeness delay, seconds

    [cache]
    enabled = true
    dir = ""                          # default ~/.nexora/cache

    [subdomains]
    wordlist = "C:/wordlists/subs.txt"

    [takeover]
    # extra fingerprints beyond the built-in service list
    extra_fingerprints = [
      { service = "MyCorp Status", cnames = ["status.mycorp.example"],
        markers = ["Page not found"], vulnerable = true },
    ]

    [watch]
    state_dir = ""
"""
from __future__ import annotations

import copy
import os
from typing import Any, Dict, Optional

DEFAULT_CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".nexora", "config.toml")

DEFAULTS: Dict[str, Any] = {
    "defaults": {"profile": "standard", "timeout": 0, "no_color": False},
    "net": {"proxy": "", "user_agent": "", "per_host_delay": 0.0},
    "cache": {"enabled": True, "dir": ""},
    "subdomains": {"wordlist": ""},
    "takeover": {"extra_fingerprints": []},
    "watch": {"state_dir": ""},
}


def _deep_merge(base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, val in (extra or {}).items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], val)
        else:
            out[key] = val
    return out


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Load the TOML config and merge it over defaults. Never raises."""
    cfg = copy.deepcopy(DEFAULTS)
    path = path or os.environ.get("NEXORA_CONFIG") or DEFAULT_CONFIG_PATH
    if not path or not os.path.isfile(path):
        return cfg
    data = None
    try:
        import tomllib  # Python 3.11+
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except ModuleNotFoundError:
        try:
            import tomli  # type: ignore  # backport, if installed
            with open(path, "rb") as fh:
                data = tomli.load(fh)
        except Exception:
            data = None
    except Exception:
        data = None
    if isinstance(data, dict):
        cfg = _deep_merge(cfg, data)
    return cfg


def config_path(path: Optional[str] = None) -> str:
    return path or os.environ.get("NEXORA_CONFIG") or DEFAULT_CONFIG_PATH


def configured_takeover_fingerprints(cfg: Dict[str, Any]) -> list:
    """Return valid extra takeover fingerprints from config ([] if none)."""
    raw = (cfg.get("takeover") or {}).get("extra_fingerprints") or []
    out = []
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict):
            continue
        service = str(entry.get("service") or "").strip()
        cnames = [str(c).lower().rstrip(".") for c in (entry.get("cnames") or [])
                  if isinstance(c, (str, int, float))]
        markers = [str(m) for m in (entry.get("markers") or [])
                   if isinstance(m, str)]
        if not service or not cnames or not markers:
            continue
        out.append({
            "service": service,
            "cnames": cnames,
            "markers": markers,
            "vulnerable": bool(entry.get("vulnerable", True)),
        })
    return out
