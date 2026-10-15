"""Nexora CLI dispatcher.

    osint domain example.com        full engine scan (delegates to osint.py)
    osint ip 1.2.3.4                IP investigation
    osint email a@b.com             email OSINT
    osint username johndoe          80+ site username enumeration

A subcommand may be omitted — it is inferred from the target
(``@`` -> email, valid IP -> ip, contains ``.`` -> domain, else username).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import sys
import time
from typing import List, Optional

from . import __version__
from .output import c, colors_enabled, enable_colors, header
from .profiles import (
    PROFILES, diff, get_profile, load_state, save_state, snapshot,
)

# Keep in sync with osint.ALL_SKIPPABLE
SKIP_CHOICES = ("ports", "sensitive_paths", "threat_intel", "web_fingerprint")


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def _detect_command(argv: List[str]) -> List[str]:
    """Insert a subcommand when the user omitted one (heuristic)."""
    if not argv:
        return argv
    first = argv[0]
    if first in COMMANDS or first.startswith("-"):
        return argv
    if first.lower().startswith(("http://", "https://")):
        return ["url"] + list(argv)
    if "@" in first:
        return ["email"] + list(argv)
    if first.startswith("+"):
        return ["phone"] + list(argv)
    try:
        ipaddress.ip_address(first)
        return ["ip"] + list(argv)
    except ValueError:
        pass
    if re.match(r"^(?:AS)?\d{1,10}$", first, re.IGNORECASE):
        return ["asn"] + list(argv)
    if "." in first:
        return ["domain"] + list(argv)
    return ["username"] + list(argv)


COMMANDS = ("domain", "ip", "email", "username", "asn", "url", "phone")


def _common_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("-j", "--json", action="store_true",
                   help="print results as JSON to stdout")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="also write JSON results to a file")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--no-banner", action="store_true",
                   help="suppress the startup banner")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="per-source progress on stderr")
    return p


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nexora",
        description="Nexora — key-free OSINT toolkit (domain, IP, email, username).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  nexora example.com                       # subcommand auto-detected\n"
            "  nexora domain example.com --profile full # includes deep recon\n"
            "  nexora ip 8.8.8.8 --no-ports\n"
            "  nexora email admin@example.com\n"
            "  nexora username torvalds\n"
            "  nexora asn AS13335\n"
            "  nexora url https://example.com\n"
            "  nexora phone +14155552671\n"
            "  nexora domain example.com --watch 3600 --count 24   # hourly diff\n"
            "  nexora domain example.com -j -o report.json\n"
        ),
    )
    parser.add_argument("--version", action="version",
                        version=f"Nexora {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="command")
    common = _common_parser()

    p_dom = sub.add_parser(
        "domain", parents=[common],
        help="full domain/company investigation (engine: osint.py)")
    p_dom.add_argument("target", help="domain, URL, or company name")
    p_dom.add_argument("-t", "--timeout", type=int, default=None,
                       help="overall timeout in seconds")
    p_dom.add_argument("--profile", choices=sorted(PROFILES), default="standard",
                       help="scan profile (default: standard)")
    p_dom.add_argument("--skip", action="append", choices=SKIP_CHOICES, default=[],
                       help="skip a source category (repeatable)")
    p_dom.add_argument("--deep", action="store_true",
                       help="force deep recon (robots, dorks, PDFs, wayback)")
    p_dom.add_argument("-n", "--limit", type=int, default=50, metavar="N",
                       help="max subdomains/vulns to display (default: 50)")
    p_dom.add_argument("--watch", type=int, default=0, metavar="SECONDS",
                       help="re-scan every N seconds and report changes")
    p_dom.add_argument("--count", type=int, default=0, metavar="N",
                       help="stop after N watch cycles (0 = unlimited)")
    p_dom.add_argument("--state-dir", default=None, metavar="DIR",
                       help="watch state directory (default: ~/.nexora/state)")

    p_ip = sub.add_parser("ip", parents=[common], help="IP address investigation")
    p_ip.add_argument("target", help="IPv4/IPv6 address")
    p_ip.add_argument("--no-ports", action="store_true", help="skip the TCP port scan")

    p_em = sub.add_parser("email", parents=[common], help="email address OSINT")
    p_em.add_argument("target", help="email address")

    p_un = sub.add_parser("username", parents=[common],
                          help="username enumeration across 100+ sites")
    p_un.add_argument("target", help="username")
    p_un.add_argument("--concurrency", type=int, default=25, metavar="N",
                      help="parallel site checks (default: 25)")

    p_asn = sub.add_parser("asn", parents=[common],
                           help="ASN / network investigation")
    p_asn.add_argument("target", help="ASN like AS13335 or 13335")

    p_url = sub.add_parser("url", parents=[common],
                           help="URL / HTTP inspection (redirects, TLS, headers)")
    p_url.add_argument("target", help="http(s):// URL")

    p_phone = sub.add_parser("phone", parents=[common],
                             help="phone number intelligence (offline, key-free)")
    p_phone.add_argument("target", help="phone number, e.g. +14155552671")
    return parser


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _make_progress(args) -> Optional[object]:
    if not getattr(args, "verbose", False):
        return None

    def _cb(source, info) -> None:
        try:
            print(f"  {c('green')}[+]{c('reset')} {source}: {info}", file=sys.stderr)
        except Exception:
            pass
    return _cb


def _check_deps(want_domain: bool) -> int:
    try:
        import requests  # noqa: F401
    except ImportError:
        print(f"{c('red')}Missing dependency: requests{c('reset')}", file=sys.stderr)
        print("Install with:  pip install requests", file=sys.stderr)
        return 2
    for mod, why in (("dns", "DNS lookups will be limited"),
                     ("aiohttp", "takeover check uses sync fallback")):
        if mod == "aiohttp" and not want_domain:
            continue
        try:
            __import__(mod)
        except ImportError:
            print(f"{c('yellow')}note: {mod} not installed — {why}{c('reset')}",
                  file=sys.stderr)
    return 0


def _write_output(args, payload: dict) -> Optional[int]:
    """Write -o FILE; returns exit code on failure, None on success/skip."""
    if not args.output:
        return None
    try:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
        print(f"{c('green')}JSON report written to {args.output}{c('reset')}",
              file=sys.stderr)
        return None
    except OSError as e:
        print(f"{c('red')}Could not write {args.output}: {e}{c('reset')}",
              file=sys.stderr)
        return 1


def _emit(args, payload: dict, renderer=None) -> int:
    err = _write_output(args, payload)
    if err is not None:
        return err
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    elif renderer is not None:
        renderer(payload)
    return 0


def _load_engine():
    try:
        import osint  # sibling osint.py — the full engine
        return osint
    except ImportError as e:
        raise SystemExit(
            f"{c('red')}error: engine module 'osint.py' not found next to the "
            f"nexora package ({e}){c('reset')}")


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_domain(args) -> int:
    engine = _load_engine()
    profile = get_profile(args.profile)
    timeout = args.timeout or profile.timeout
    skip = set(profile.skip) | set(args.skip or [])
    deep_enabled = args.deep or profile.deep
    progress = _make_progress(args)
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)

    do_watch = bool(args.watch and args.watch > 0)
    prev = load_state(args.target, args.state_dir) if do_watch else None
    deep_render = None
    if deep_enabled:
        try:
            from .deep import render_text as deep_render  # type: ignore
        except ImportError:
            print(f"{c('yellow')}note: nexora.deep unavailable — skipping deep recon"
                  f"{c('reset')}", file=sys.stderr)
            deep_enabled = False

    cycle = 0
    while True:
        cycle += 1
        print(f"{c('bold')}{c('magenta')}Nexora OSINT Engine{c('reset')} — "
              f"{profile.name} profile | timeout {timeout}s"
              f"{' | deep' if deep_enabled else ''}"
              f"{' | skipped: ' + ','.join(sorted(skip)) if skip else ''}",
              file=sys.stderr)
        started = time.time()
        try:
            result = engine.lookup_domain(
                args.target, timeout=timeout,
                skip_categories=skip or None,
                on_source_complete=progress,
            )
        except KeyboardInterrupt:
            print(f"\n{c('yellow')}Interrupted.{c('reset')}", file=sys.stderr)
            return 130
        except Exception as e:
            print(f"{c('red')}Lookup failed: {type(e).__name__}: {e}{c('reset')}",
                  file=sys.stderr)
            return 1
        elapsed = time.time() - started

        payload = engine.intel_to_dict(result)

        if deep_enabled:
            try:
                from .deep import collect_deep
                payload["deep"] = collect_deep(args.target, status_cb=progress)
            except Exception as e:
                print(f"{c('yellow')}deep recon failed: {type(e).__name__}{c('reset')}",
                      file=sys.stderr)

        snap = snapshot(payload)
        changes = diff(prev, snap) if do_watch else []
        if do_watch:
            payload["changes"] = changes
            payload["watch_cycle"] = cycle

        err = _write_output(args, payload)
        if err is not None:
            return err

        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
        else:
            if not result.query or result.sources_status.get("input") == "empty":
                print(f"{c('red')}No valid domain derived from {args.target!r}."
                      f"{c('reset')}", file=sys.stderr)
                return 1
            engine._COLOR_ENABLED = colors_enabled()
            engine._render_text(result, limit=max(1, args.limit))
            if deep_enabled and deep_render is not None and "deep" in payload:
                try:
                    deep_render(payload["deep"])
                except Exception:
                    pass
            if changes:
                header(f"CHANGES ({len(changes)})")
                for chg in changes:
                    col = (c("green") if chg.startswith("+")
                           else c("red") if chg.startswith("-") else c("yellow"))
                    print(f"  {col}{chg}{c('reset')}")
            print(f"\n{c('gray')}Completed in {elapsed:.1f}s{c('reset')}")

        if not do_watch:
            return 0

        prev = snap
        try:
            save_state(args.target, snap, args.state_dir)
        except OSError as e:
            print(f"{c('yellow')}could not save state: {e}{c('reset')}", file=sys.stderr)
        if args.count and cycle >= args.count:
            print(f"{c('gray')}Watch finished after {cycle} cycle(s).{c('reset')}",
                  file=sys.stderr)
            return 0
        print(f"{c('gray')}Next scan in {args.watch}s (Ctrl-C to stop)...{c('reset')}",
              file=sys.stderr)
        try:
            time.sleep(args.watch)
        except KeyboardInterrupt:
            print(f"\n{c('yellow')}Watch stopped.{c('reset')}", file=sys.stderr)
            return 130


def cmd_ip(args) -> int:
    try:
        from .ip import lookup_ip, render_text
    except ImportError:
        print(f"{c('red')}error: nexora.ip module unavailable{c('reset')}",
              file=sys.stderr)
        return 1
    try:
        result = lookup_ip(args.target, scan_ports=not args.no_ports,
                           status_cb=_make_progress(args))
    except ValueError as e:
        print(f"{c('red')}{e}{c('reset')}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(f"\n{c('yellow')}Interrupted.{c('reset')}", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"{c('red')}Lookup failed: {type(e).__name__}: {e}{c('reset')}",
              file=sys.stderr)
        return 1
    return _emit(args, result, lambda payload: render_text(payload))


def cmd_email(args) -> int:
    try:
        from .email import lookup_email, render_text
    except ImportError:
        print(f"{c('red')}error: nexora.email module unavailable{c('reset')}",
              file=sys.stderr)
        return 1
    try:
        result = lookup_email(args.target, status_cb=_make_progress(args))
    except ValueError as e:
        print(f"{c('red')}{e}{c('reset')}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(f"\n{c('yellow')}Interrupted.{c('reset')}", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"{c('red')}Lookup failed: {type(e).__name__}: {e}{c('reset')}",
              file=sys.stderr)
        return 1
    return _emit(args, result, lambda payload: render_text(payload))


def cmd_username(args) -> int:
    try:
        from .username import lookup_username, render_text
    except ImportError:
        print(f"{c('red')}error: nexora.username module unavailable{c('reset')}",
              file=sys.stderr)
        return 1
    try:
        result = lookup_username(args.target, concurrency=max(1, args.concurrency),
                                 status_cb=_make_progress(args))
    except ValueError as e:
        print(f"{c('red')}{e}{c('reset')}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(f"\n{c('yellow')}Interrupted.{c('reset')}", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"{c('red')}Lookup failed: {type(e).__name__}: {e}{c('reset')}",
              file=sys.stderr)
        return 1
    return _emit(args, result, lambda payload: render_text(payload))


def cmd_asn(args) -> int:
    try:
        from .asn import lookup_asn, render_text
    except ImportError:
        print(f"{c('red')}error: nexora.asn module unavailable{c('reset')}",
              file=sys.stderr)
        return 1
    try:
        result = lookup_asn(args.target, status_cb=_make_progress(args))
    except ValueError as e:
        print(f"{c('red')}{e}{c('reset')}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(f"\n{c('yellow')}Interrupted.{c('reset')}", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"{c('red')}Lookup failed: {type(e).__name__}: {e}{c('reset')}",
              file=sys.stderr)
        return 1
    return _emit(args, result, lambda payload: render_text(payload))


def cmd_url(args) -> int:
    try:
        from .url import lookup_url, render_text
    except ImportError:
        print(f"{c('red')}error: nexora.url module unavailable{c('reset')}",
              file=sys.stderr)
        return 1
    try:
        result = lookup_url(args.target, status_cb=_make_progress(args))
    except ValueError as e:
        print(f"{c('red')}{e}{c('reset')}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(f"\n{c('yellow')}Interrupted.{c('reset')}", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"{c('red')}Lookup failed: {type(e).__name__}: {e}{c('reset')}",
              file=sys.stderr)
        return 1
    return _emit(args, result, lambda payload: render_text(payload))


def cmd_phone(args) -> int:
    try:
        from .phone import lookup_phone, render_text
    except ImportError:
        print(f"{c('red')}error: nexora.phone module unavailable{c('reset')}",
              file=sys.stderr)
        return 1
    try:
        result = lookup_phone(args.target, status_cb=_make_progress(args))
    except ValueError as e:
        print(f"{c('red')}{e}{c('reset')}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(f"\n{c('yellow')}Interrupted.{c('reset')}", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"{c('red')}Lookup failed: {type(e).__name__}: {e}{c('reset')}",
              file=sys.stderr)
        return 1
    return _emit(args, result, lambda payload: render_text(payload))


_HANDLERS = {
    "domain": cmd_domain,
    "ip": cmd_ip,
    "email": cmd_email,
    "username": cmd_username,
    "asn": cmd_asn,
    "url": cmd_url,
    "phone": cmd_phone,
}


def main(argv: Optional[List[str]] = None) -> int:
    # Windows pipes default to cp1252 — force UTF-8 so ✓/→/· don't crash
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            pass
    argv = _detect_command(list(sys.argv[1:] if argv is None else argv))
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    enable_colors(
        force=(not args.no_color
               and not os.environ.get("NO_COLOR")
               and sys.stdout.isatty())
    )
    rc = _check_deps(want_domain=(args.command == "domain"))
    if rc:
        return rc
    if (not getattr(args, "json", False)
            and not getattr(args, "no_banner", False)
            and not os.environ.get("NEXORA_NO_BANNER")):
        try:
            from .banner import print_banner
            print_banner()
        except Exception:
            pass
    return _HANDLERS[args.command](args)
