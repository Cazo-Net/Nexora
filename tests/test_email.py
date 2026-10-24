"""Tests for nexora.email: validation and hermetic lookup."""
from __future__ import annotations

import pytest

import nexora.email as email_mod
from nexora.advanced import EmailSecurity


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad", ["plain", "a@b", "@b.com", "a @b.com", ""])
def test_lookup_email_rejects_invalid(bad):
    with pytest.raises(ValueError):
        email_mod.lookup_email(bad)


# --------------------------------------------------------------------------- #
# Hermetic lookup
# --------------------------------------------------------------------------- #
def _patch_network(monkeypatch):
    """Make every network-y collector inert."""
    def fake_collect(domain, status):
        status["email-security"] = "ok"
        return EmailSecurity(
            domain=domain,
            spf_record="v=spf1 -all", spf_valid=True,
            dmarc_record="v=DMARC1; p=reject", dmarc_policy="reject",
        )

    monkeypatch.setattr(email_mod, "_collect_email_security", fake_collect)
    monkeypatch.setattr(email_mod, "http_get",
                        lambda *args, **kwargs: None)
    monkeypatch.setattr(email_mod, "resolve_txt",
                        lambda *args, **kwargs: [])


def test_lookup_email_hermetic(monkeypatch):
    _patch_network(monkeypatch)
    result = email_mod.lookup_email("John.Doe+tag@example.com")

    assert result["valid"] is True
    assert result["email"] == "John.Doe+tag@example.com"
    assert result["domain"] == "example.com"

    guesses = result["username_guesses"]
    assert isinstance(guesses, list)
    assert len(guesses) >= 2
    assert guesses[0] == "john.doe+tag"
    assert "john" in guesses
    assert len(guesses) == len(set(guesses))
    assert all(g == g.lower() for g in guesses)

    # every collector reported a status, none crashed
    status = result["sources_status"]
    assert status.get("gravatar") == "error: no_response"
    assert status.get("breach-check") == "error: no_response"
    assert status.get("disposable") == "unavailable"
    assert result["is_disposable"] is None
    assert result["email_security"]["dmarc_policy"] == "reject"
    assert result["gravatar"] is not None
    assert result["breach_check"] is not None


def test_lookup_email_survives_collector_crash(monkeypatch):
    _patch_network(monkeypatch)

    def boom(domain):
        raise RuntimeError("disposable fetcher exploded")

    monkeypatch.setattr(email_mod, "_collect_disposable", boom)
    result = email_mod.lookup_email("John.Doe+tag@example.com")
    assert result["valid"] is True
    assert result["sources_status"].get("disposable") == "error: RuntimeError"
    assert result["is_disposable"] is None


def test_render_text_smoke(capsys):
    payload = {
        "email": "a@b.com", "domain": "b.com", "valid": True,
        "is_disposable": None, "username_guesses": ["a"],
        "email_security": None, "gravatar": None, "breach_check": None,
        "sources_status": {"gravatar": "error: no_response"},
    }
    email_mod.render_text(payload)  # must not raise with colors off
    out = capsys.readouterr().out
    assert "EMAIL SUMMARY" in out
    assert "a@b.com" in out
