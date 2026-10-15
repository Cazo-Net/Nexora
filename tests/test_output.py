"""Tests for nexora.output: colors, severity mapping, headers."""
from __future__ import annotations

import pytest

from nexora import output


def test_colors_disabled_by_default():
    assert output.colors_enabled() is False
    assert output.c("red") == ""


def test_known_colors_nonempty_when_enabled():
    output.enable_colors(True)
    try:
        assert output.colors_enabled() is True
        assert output.c("red") == output.COLORS["red"]
        assert output.c("red") != ""
        for name in ("reset", "bold", "dim", "red", "green", "yellow",
                     "blue", "magenta", "cyan", "gray"):
            assert output.c(name), "expected non-empty code for %r" % name
    finally:
        output.enable_colors(False)


def test_unknown_color_name_is_safe():
    output.enable_colors(True)
    try:
        assert output.c("no-such-color") == ""
        assert output.c("") == ""
        assert output.c("RED") == ""  # names are case-sensitive, never raise
    finally:
        output.enable_colors(False)


def test_sev_color_mapping():
    output.enable_colors(True)
    try:
        assert output.sev_color("CRITICAL") == output.c("red")
        assert output.sev_color("HIGH") == output.c("red")
        assert output.sev_color("high") == output.c("red")  # case-insensitive
        assert output.sev_color("MEDIUM") == output.c("yellow")
        assert output.sev_color("LOW") == output.c("green")
        assert output.sev_color("INFO") == output.c("gray")
        assert output.sev_color("something-else") == output.c("gray")
        assert output.sev_color("") == output.c("gray")
        # distinct severities must map to distinct codes while enabled
        assert output.sev_color("HIGH") != output.sev_color("MEDIUM")
        assert output.sev_color("MEDIUM") != output.sev_color("LOW")
    finally:
        output.enable_colors(False)


def test_header_prints_title(capsys):
    output.header("UNIT TEST SECTION")
    out = capsys.readouterr().out
    assert "UNIT TEST SECTION" in out
    assert "==" in out
