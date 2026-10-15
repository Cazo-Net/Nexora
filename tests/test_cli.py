"""Tests for nexora.cli: command detection, parser, exit codes."""
from __future__ import annotations

import pytest

cli = pytest.importorskip("nexora.cli")


# --------------------------------------------------------------------------- #
# _detect_command heuristic
# --------------------------------------------------------------------------- #
def test_detect_email():
    assert cli._detect_command(["a@b.com"]) == ["email", "a@b.com"]


def test_detect_ip():
    assert cli._detect_command(["1.2.3.4"]) == ["ip", "1.2.3.4"]


def test_detect_domain():
    assert cli._detect_command(["example.com"]) == ["domain", "example.com"]


def test_detect_username():
    assert cli._detect_command(["torvalds"]) == ["username", "torvalds"]


def test_detect_passthrough_explicit_command():
    argv = ["domain", "x"]
    assert cli._detect_command(argv) == argv


def test_detect_passthrough_flags():
    argv = ["--help"]
    assert cli._detect_command(argv) == argv
    argv2 = ["-j", "example.com"]
    assert cli._detect_command(argv2) == argv2


def test_detect_empty_argv():
    assert cli._detect_command([]) == []


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def test_parser_profile_choices():
    parser = cli._build_parser()
    args = parser.parse_args(["domain", "example.com", "--profile", "quick"])
    assert args.profile == "quick"
    args = parser.parse_args(["domain", "example.com", "--profile", "stealth"])
    assert args.profile == "stealth"
    with pytest.raises(SystemExit):
        parser.parse_args(["domain", "example.com", "--profile", "turbo"])


def test_parser_skip_choices():
    parser = cli._build_parser()
    args = parser.parse_args(["domain", "example.com", "--skip", "ports"])
    assert args.skip == ["ports"]
    with pytest.raises(SystemExit):
        parser.parse_args(["domain", "example.com", "--skip", "bogus"])


def test_parser_known_subcommands():
    """Only assert on the four long-standing subcommands (more may be
    added concurrently)."""
    parser = cli._build_parser()
    for cmd, target in (("domain", "example.com"), ("ip", "1.2.3.4"),
                        ("email", "a@b.com"), ("username", "torvalds")):
        args = parser.parse_args([cmd, target])
        assert args.command == cmd
        assert args.target == target


# --------------------------------------------------------------------------- #
# main() exit codes
# --------------------------------------------------------------------------- #
def test_main_invalid_ip_returns_1(capsys):
    rc = cli.main(["ip", "not-an-ip", "--no-color"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "invalid IP address" in err


def test_main_empty_argv_prints_help_and_returns_0(capsys):
    rc = cli.main([])
    assert rc == 0
    out = capsys.readouterr().out
    assert "usage" in out.lower()


def test_check_deps_ok():
    # requests is importable in this environment, so deps are satisfied.
    assert cli._check_deps(want_domain=True) == 0
    assert cli._check_deps(want_domain=False) == 0
