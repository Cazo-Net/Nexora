"""Scan profiles, state persistence, and change detection for watch mode.

Profiles control timeout + which source categories the engine skips.
Watch state lets `--watch` runs diff each scan against the previous one
(and resume from disk across process restarts).
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional


@dataclass(frozen=True)
class Profile:
    name: str
    timeout: int
    skip: FrozenSet[str]
    deep: bool
    description: str


# Skip categories map to osint.ALL_SKIPPABLE:
#   ports | threat_intel | web_fingerprint | sensitive_paths
PROFILES: Dict[str, Profile] = {
    "quick": Profile(
        name="quick", timeout=75, deep=False,
        skip=frozenset({"ports", "threat_intel", "sensitive_paths", "web_fingerprint"}),
        description="Fast passive overview (~75s)",
    ),
    "standard": Profile(
        name="standard", timeout=120, deep=False, skip=frozenset(),
        description="Balanced full scan (default, ~2min)",
    ),
    "full": Profile(
        name="full", timeout=300, deep=True, skip=frozenset(),
        description="Everything + deep recon (robots, dorks, docs, wayback)",
    ),
    "stealth": Profile(
        name="stealth", timeout=90, deep=False,
        skip=frozenset({"ports", "sensitive_paths"}),
        description="Passive-only: no port scans or path probing",
    ),
}


def get_profile(name: str) -> Profile:
    try:
        return PROFILES[name]
    except KeyError:
        raise ValueError(
            f"unknown profile: {name!r} (choose from {', '.join(sorted(PROFILES))})"
        )


# --------------------------------------------------------------------------- #
# Watch state (save / load / diff)
# --------------------------------------------------------------------------- #
def default_state_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".nexora", "state")


def state_path(target: str, state_dir: Optional[str] = None) -> str:
    directory = state_dir or default_state_dir()
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", target.strip().lower())[:80] or "target"
    return os.path.join(directory, f"{slug}.json")


def save_state(target: str, payload: dict, state_dir: Optional[str] = None) -> str:
    path = state_path(target, state_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
    return path


def load_state(target: str, state_dir: Optional[str] = None) -> Optional[dict]:
    path = state_path(target, state_dir)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def snapshot(result: dict) -> dict:
    """Extract the changeable facts from an intel_to_dict() payload."""
    subdomains = sorted({
        s.get("hostname", "") for s in result.get("subdomains") or []
        if isinstance(s, dict) and s.get("hostname")
    })
    ports = sorted({
        p.get("port") for p in result.get("ports") or []
        if isinstance(p, dict) and p.get("port")
    })
    cves = sorted({
        v.get("cve_id") for v in result.get("vulnerabilities") or []
        if isinstance(v, dict) and v.get("cve_id")
    })
    takeovers = sorted({
        str(t.get("subdomain") or t.get("hostname") or "")
        for t in result.get("subdomain_takeover") or []
        if isinstance(t, dict) and t.get("vulnerable")
    })
    risk = result.get("risk_score") or {}
    return {
        "ts": time.time(),
        "subdomains": subdomains,
        "ports": ports,
        "cves": cves,
        "takeovers": takeovers,
        "technologies": sorted(result.get("technologies") or []),
        "risk": {"score": risk.get("score"), "grade": risk.get("grade")},
    }


def diff(old: Optional[dict], new: dict) -> List[str]:
    """Human-readable changes between snapshots ('+ added', '- removed')."""
    if not old:
        return []
    changes: List[str] = []

    def _cmp(key: str, label: str) -> None:
        before = set(old.get(key) or [])
        after = set(new.get(key) or [])
        for item in sorted(after - before):
            changes.append(f"+ new {label}: {item}")
        for item in sorted(before - after):
            changes.append(f"- removed {label}: {item}")

    _cmp("subdomains", "subdomain")
    _cmp("ports", "open port")
    _cmp("cves", "CVE")
    _cmp("takeovers", "takeover-vulnerable subdomain")
    _cmp("technologies", "technology")

    old_risk = (old.get("risk") or {}).get("score")
    new_risk = (new.get("risk") or {}).get("score")
    if old_risk is not None and new_risk is not None and old_risk != new_risk:
        arrow = "up" if new_risk > old_risk else "down"
        changes.append(f"~ risk score {old_risk} -> {new_risk} ({arrow})")
    return changes
