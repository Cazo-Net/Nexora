"""Tests for nexora.ip: validation and hermetic lookup."""
from __future__ import annotations

import pytest

import nexora.ip as ip_mod


# --------------------------------------------------------------------------- #
# Validation (happens before any I/O)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad", ["999.1.1.1", "example.com", ""])
def test_lookup_ip_rejects_invalid(bad):
    with pytest.raises(ValueError):
        ip_mod.lookup_ip(bad)


# --------------------------------------------------------------------------- #
# Hermetic lookup
# --------------------------------------------------------------------------- #
def test_lookup_ip_hermetic(monkeypatch):
    # every HTTP collector degrades to "no response" without the network;
    # reverse DNS is blocked by the autouse socket guard.
    monkeypatch.setattr(ip_mod, "http_get", lambda *a, **k: None)
    monkeypatch.setattr(ip_mod, "http_post", lambda *a, **k: None)

    result = ip_mod.lookup_ip("1.2.3.4", scan_ports=False)

    assert result["ip"] == "1.2.3.4"
    for key in ("reverse_dns", "rdap", "bgp", "geo", "shodan", "reverse_ip",
                "threat_intel", "ports", "sources_status"):
        assert key in result, "missing result key %r" % key
    assert result["ports"] == []  # scan disabled

    status = result["sources_status"]
    assert status, "sources_status must be populated"
    for source in ("rdap", "geo", "shodan", "port-scan"):
        assert source in status, "missing source status %r" % source
    assert status["port-scan"] == "skipped"


def test_lookup_ip_invalid_after_normalisation():
    # ipaddress accepts valid IPv4/IPv6 only; a hostname must fail.
    with pytest.raises(ValueError):
        ip_mod.lookup_ip("not an ip at all")
