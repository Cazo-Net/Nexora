"""Tests for nexora.profiles: profiles, snapshots, diffs, watch state."""
from __future__ import annotations

import os

import pytest

from nexora import profiles


def _result(**overrides):
    """A minimal intel_to_dict()-style payload."""
    base = {
        "subdomains": [{"hostname": "a.example.com"}],
        "ports": [{"port": 80}],
        "vulnerabilities": [{"cve_id": "CVE-2020-0001"}],
        "technologies": ["nginx"],
        "risk_score": {"score": 10, "grade": "A"},
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------- #
# Profiles
# --------------------------------------------------------------------------- #
def test_get_profile_valid():
    for name in ("quick", "standard", "full", "stealth"):
        p = profiles.get_profile(name)
        assert isinstance(p, profiles.Profile)
        assert p.name == name
        assert p.timeout > 0


def test_known_profiles_present():
    assert set(profiles.PROFILES) >= {"quick", "standard", "full", "stealth"}
    assert "ports" in profiles.get_profile("quick").skip
    stealth = profiles.get_profile("stealth")
    assert "ports" in stealth.skip
    assert stealth.deep is False


def test_get_profile_unknown_raises():
    with pytest.raises(ValueError):
        profiles.get_profile("lightning")


# --------------------------------------------------------------------------- #
# Snapshot / diff
# --------------------------------------------------------------------------- #
def test_diff_reports_added_lines():
    old = profiles.snapshot(_result())
    new = profiles.snapshot(_result(
        subdomains=[{"hostname": "a.example.com"},
                    {"hostname": "b.example.com"}],
        ports=[{"port": 80}, {"port": 443}],
        vulnerabilities=[{"cve_id": "CVE-2020-0001"},
                         {"cve_id": "CVE-2024-9999"}],
        technologies=["nginx", "php"],
        risk_score={"score": 45, "grade": "C"},
    ))
    changes = profiles.diff(old, new)
    assert "+ new subdomain: b.example.com" in changes
    assert "+ new open port: 443" in changes
    assert "+ new CVE: CVE-2024-9999" in changes
    assert "+ new technology: php" in changes
    assert any(c.startswith("~ risk score 10 -> 45") and "(up)" in c
               for c in changes)


def test_diff_reports_removed_lines():
    old = profiles.snapshot(_result(
        subdomains=[{"hostname": "gone.example.com"},
                    {"hostname": "stays.example.com"}],
        ports=[{"port": 22}, {"port": 80}],
        technologies=["nginx", "apache"],
        risk_score={"score": 45, "grade": "C"},
    ))
    new = profiles.snapshot(_result(
        subdomains=[{"hostname": "stays.example.com"}],
        ports=[{"port": 80}],
        risk_score={"score": 10, "grade": "A"},
    ))
    changes = profiles.diff(old, new)
    assert "- removed subdomain: gone.example.com" in changes
    assert "- removed open port: 22" in changes
    assert "- removed technology: apache" in changes
    assert any(c.startswith("~ risk score 45 -> 10") and "(down)" in c
               for c in changes)


def test_diff_identical_snapshots_is_empty():
    old = profiles.snapshot(_result())
    new = profiles.snapshot(_result())
    assert profiles.diff(old, new) == []


def test_diff_without_previous_state_is_empty():
    snap = profiles.snapshot(_result())
    assert profiles.diff(None, snap) == []


def test_snapshot_tolerates_missing_keys():
    snap = profiles.snapshot({})
    assert snap["subdomains"] == []
    assert snap["ports"] == []
    assert snap["cves"] == []
    assert snap["technologies"] == []
    assert snap["risk"] == {"score": None, "grade": None}


def test_snapshot_tolerates_junk_entries():
    snap = profiles.snapshot({
        "subdomains": [None, 42, "plain-string", {"hostname": ""},
                       {"hostname": "ok.example.com"}],
        "ports": [None, {}, {"port": None}, {"port": 8080}],
    })
    assert snap["subdomains"] == ["ok.example.com"]
    assert snap["ports"] == [8080]


# --------------------------------------------------------------------------- #
# Watch state
# --------------------------------------------------------------------------- #
def test_state_save_load_roundtrip(tmp_path):
    payload = {"risk": {"score": 5, "grade": "A"},
               "subdomains": ["a.example.com"]}
    path = profiles.save_state("Example.COM", payload, str(tmp_path))
    assert os.path.isfile(path)
    loaded = profiles.load_state("Example.COM", str(tmp_path))
    assert loaded == payload


def test_load_missing_state_returns_none(tmp_path):
    assert profiles.load_state("never-saved.example", str(tmp_path)) is None


def test_load_corrupt_state_returns_none(tmp_path):
    path = profiles.state_path("bad.example", str(tmp_path))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("{ this is not json")
    assert profiles.load_state("bad.example", str(tmp_path)) is None


def test_state_path_slug_has_no_separators(tmp_path):
    path = profiles.state_path("evil/../x", str(tmp_path))
    directory, name = os.path.split(path)
    assert directory == str(tmp_path)
    assert "/" not in name
    assert "\\" not in name
    assert os.sep not in name
    if os.altsep:
        assert os.altsep not in name
    assert name.endswith(".json")


def test_default_state_dir_is_under_home():
    d = profiles.default_state_dir()
    assert os.path.isabs(d)
    assert ".nexora" in d.replace("\\", "/")
