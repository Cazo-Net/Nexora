"""Nexconsole — the Metasploit-style interactive REPL for Nexora.

Entry point::

    nexconsole                 # interactive prompt
    nexconsole -c "use recon/ip; set target 1.2.3.4; run"
    nexconsole -x commands.txt # batch file (one command per line)

Batch splitting: newlines always separate commands; ``;`` also separates
commands, but only outside single/double quotes (a simple scan — shell
escapes are NOT honored). Lines starting with ``#`` are comments.
"""
from __future__ import annotations

import argparse
import difflib
import importlib
import json
import os
import shlex
import sys
import time
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .banner import print_banner
from .modules import Module, describe, get as get_module, list_modules
from .modules import search as search_modules
from .output import c, enable_colors
from .store import Store

VERSION_STRING = "Nexora Nexconsole %s" % __version__

# Canonical command names (used by help + did-you-mean suggestions).
COMMANDS = ("back", "banner", "cache", "exit", "export", "go", "help",
            "history", "info", "notes", "quit", "run", "scan", "search",
            "set", "setg", "show", "unset", "unsetg", "use", "version",
            "workspace")

SHOW_TOPICS = ("modules", "options", "info", "workspaces", "findings",
               "hosts", "services", "notes", "banner")


# --------------------------------------------------------------------------- #
# Batch-line splitting helpers
# --------------------------------------------------------------------------- #
def split_commands(text: str) -> List[str]:
    """Split a batch string into command lines.

    Newlines always separate commands; ``;`` separates commands too, but
    only when outside single/double quotes (simple scan, no escapes).
    """
    lines: List[str] = []
    for raw in (text or "").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        buf: List[str] = []
        quote = ""
        for ch in raw:
            if ch in ("'", '"'):
                if quote == "":
                    quote = ch
                elif quote == ch:
                    quote = ""
                buf.append(ch)
            elif ch == ";" and not quote:
                piece = "".join(buf).strip()
                if piece and not piece.startswith("#"):
                    lines.append(piece)
                buf = []
            else:
                buf.append(ch)
        piece = "".join(buf).strip()
        if piece and not piece.startswith("#"):
            lines.append(piece)
    return lines


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in ("true", "1", "yes", "on"):
        return True
    if s in ("false", "0", "no", "off", ""):
        return False
    return bool(value)


# --------------------------------------------------------------------------- #
# Result auto-ingest into the Store
# --------------------------------------------------------------------------- #
_MAX_EVIDENCE_BYTES = 200_000


def _ingest(module_path: str, target: str, payload: Any, store: Store) -> None:
    """Best-effort: pull hosts/services/findings/evidence out of a run.

    Every section is individually guarded — ingestion can never break a
    console session.
    """
    if store is None or not isinstance(payload, dict):
        return
    target = str(target or payload.get("query") or payload.get("email")
                 or payload.get("ip") or "")

    # -- evidence: always (capped at 200KB JSON) -------------------------
    try:
        data: Any = payload
        blob = json.dumps(payload, ensure_ascii=False, default=str)
        if len(blob) > _MAX_EVIDENCE_BYTES:
            data = {"keys": sorted(payload.keys()), "truncated": True}
        store.add_evidence(kind=module_path, source="run", target=target,
                           data=data)
    except Exception:
        pass

    # -- hosts ----------------------------------------------------------
    try:
        if "subdomains" in payload and isinstance(payload.get("subdomains"), list):
            for entry in payload["subdomains"]:
                if not isinstance(entry, dict):
                    continue
                host = str(entry.get("hostname") or "").strip()
                if not host:
                    continue
                ips = entry.get("ips") or []
                ip = str(ips[0]) if isinstance(ips, list) and ips else None
                store.add_host(host, ip=ip, module=module_path)
        ip_val = payload.get("ip")
        if ip_val:
            rev = payload.get("reverse_dns")
            store.add_host(str(ip_val), ip=str(ip_val),
                           module=module_path)
            if rev:
                store.add_host(str(rev), ip=str(ip_val), module=module_path)
    except Exception:
        pass

    # -- services (open ports) -------------------------------------------
    try:
        ports = payload.get("ports")
        if isinstance(ports, list):
            for entry in ports:
                if not isinstance(entry, dict):
                    continue
                port = entry.get("port")
                if port is None:
                    continue
                store.add_service(target, int(port),
                                  proto=str(entry.get("proto") or "tcp"),
                                  name=str(entry.get("service") or ""),
                                  info=str(entry.get("banner") or ""))
    except Exception:
        pass

    # -- findings --------------------------------------------------------
    try:
        risk = payload.get("risk_score")
        if isinstance(risk, dict) and (risk.get("score") or 0) >= 40:
            grade = str(risk.get("grade") or "")
            severity = "HIGH" if grade in ("D", "F") else \
                ("MEDIUM" if grade == "C" else "LOW")
            store.add_finding(
                module_path, target, severity,
                "risk score %s/100 (grade %s)" % (risk.get("score"), grade),
                detail="; ".join((risk.get("findings") or [])[:5]))
        takeovers = payload.get("subdomain_takeover")
        if isinstance(takeovers, list):
            for entry in takeovers:
                if isinstance(entry, dict) and entry.get("vulnerable"):
                    store.add_finding(
                        module_path, target, "HIGH",
                        "subdomain takeover candidate: %s"
                        % (entry.get("subdomain") or entry.get("hostname")
                           or "?"),
                        detail=json.dumps(entry, default=str)[:500])
        paths = payload.get("sensitive_paths")
        if isinstance(paths, list) and paths:
            store.add_finding(
                module_path, target, "MEDIUM",
                "%d sensitive path(s) exposed" % len(paths),
                detail=", ".join(str(p.get("path") if isinstance(p, dict)
                                     else p) for p in paths[:10]))
        bc = payload.get("breach_check")
        if isinstance(bc, dict) and bc.get("breaches"):
            store.add_finding(
                module_path, target, "HIGH",
                "email seen in %d breach(es)" % len(bc["breaches"]),
                detail=", ".join(str(x) for x in bc["breaches"][:15]))
        sec = payload.get("security_score")
        if isinstance(sec, int) and sec < 50:
            severity = "MEDIUM" if sec < 25 else "LOW"
            store.add_finding(
                module_path, target, severity,
                "weak URL security score %d/100" % sec)
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Console
# --------------------------------------------------------------------------- #
class Nexconsole:
    """The REPL. Construct with a Store; ``interactive=False`` for batch."""

    def __init__(self, store: Store, interactive: bool = True,
                 out: Optional[Any] = None) -> None:
        self.store = store
        self.interactive = bool(interactive)
        self.out = out or sys.stdout
        self.current_module: Optional[Module] = None
        self.options: Dict[str, Any] = {}   # per-module set values
        self.globals: Dict[str, Any] = {}   # setg values
        self.history: List[str] = []

    # ------------------------------------------------------------------ #
    # Output helpers
    # ------------------------------------------------------------------ #
    def _p(self, text: str = "") -> None:
        try:
            print(text, file=self.out)
        except Exception:
            pass

    def _section(self, title: str) -> None:
        width = 66
        pad = "=" * max(1, width - len(title) - 3)
        self._p("%s== %s %s%s" % (c("bold"), title, pad, c("reset")))

    def prompt(self) -> str:
        if self.current_module is not None:
            inner = " (%s)" % self.current_module.path
        else:
            inner = ""
        return "%s%snexora%s%s > " % (c("bold"), c("cyan"), inner, c("reset"))

    # ------------------------------------------------------------------ #
    # Option plumbing
    # ------------------------------------------------------------------ #
    def _effective_options(self) -> Dict[str, Any]:
        """defaults <- setg globals <- per-module set values."""
        if self.current_module is None:
            return {}
        eff: Dict[str, Any] = {}
        for opt in self.current_module.options:
            eff[opt.name] = opt.default
        for key, val in self.globals.items():
            eff[key] = val
        for key, val in self.options.items():
            eff[key] = val
        eff["_module_path"] = self.current_module.path
        return eff

    def _find_option(self, name: str):
        if self.current_module is None:
            return None
        for opt in self.current_module.options:
            if opt.name.lower() == str(name).lower():
                return opt
        return None

    # ------------------------------------------------------------------ #
    # Command implementations
    # ------------------------------------------------------------------ #
    def cmd_help(self, args: List[str]) -> bool:
        if args:
            topic = args[0].lower()
            if topic in ("show", "modules", "options"):
                self._p("show modules|options|info|workspaces|findings|"
                        "hosts|services|notes|banner")
                return False
            try:
                self._p(describe(get_module(topic)))
            except KeyError:
                self._p("No help for %r. Type 'help' for the command list."
                        % args[0])
            return False
        self._p("Commands:")
        rows = [
            ("help, ?", "this help, or help <module-path>"),
            ("show <topic>", "modules|options|info|workspaces|findings|"
                             "hosts|services|notes|banner"),
            ("use <path>", "select a module (e.g. use recon/domain)"),
            ("back", "deselect the current module"),
            ("info", "describe the current module"),
            ("set <opt> <value>", "set a module option"),
            ("unset <opt>", "remove a module option value"),
            ("setg <opt> <value>", "set a global option (all modules)"),
            ("unsetg <opt>", "remove a global option"),
            ("run, scan, go", "execute the current module"),
            ("workspace [name]", "list/switch workspace"),
            ("search <term>", "search the workspace database"),
            ("notes [add <text>]", "list or add workspace notes"),
            ("export <file>", "export workspace data to JSON"),
            ("cache stats|clear", "inspect or clear the TTL cache"),
            ("history", "show typed commands"),
            ("version", "print console version"),
            ("banner", "print the Nexora banner"),
            ("quit, exit, q", "leave the console"),
        ]
        for name, desc in rows:
            self._p("  %-22s %s" % (name, desc))
        self._p("")
        self._p("Modules: 'show modules' lists the registry; "
                "'use <path>' selects one, 'run' executes it.")
        return False

    def cmd_show(self, args: List[str]) -> bool:
        topic = (args[0].lower() if args else "modules")
        if topic == "modules":
            mods = list_modules()
            if len(args) > 1 and args[1]:
                mods = search_modules(args[1]) or mods
            self._section("MODULES")
            for m in mods:
                self._p("  %s%-18s%s %s[%s]%s  %s"
                        % (c("magenta"), m.path, c("reset"), c("gray"),
                           m.kind, c("reset"), m.title))
            self._p("")
            self._p("  %d modules — 'use <path>' to select, 'show options' "
                    "for settings" % len(mods))
            return False
        if topic == "options":
            if self.current_module is None:
                self._p("No module selected. Use 'use <path>' "
                        "(see 'show modules').")
                return False
            self._section("MODULE OPTIONS: %s" % self.current_module.path)
            self._p("  %-14s %-18s %-9s %s" % ("Name", "Current Setting",
                                               "Required", "Description"))
            eff = self._effective_options()
            for opt in self.current_module.options:
                val = eff.get(opt.name, opt.default)
                shown = "-" if val in ("", None) else str(val)
                self._p("  %-14s %-18s %-9s %s"
                        % (opt.name, shown,
                           "yes" if opt.required else "no", opt.description))
            return False
        if topic == "info":
            return self.cmd_info([])
        if topic == "workspaces":
            return self.cmd_workspace([])
        if topic == "findings":
            rows = self.store.findings(limit=100)
            self._section("FINDINGS (%d)" % len(rows))
            for r in rows:
                sev = str(r.get("severity") or "")
                color = "red" if sev in ("HIGH", "CRITICAL") else \
                    ("yellow" if sev == "MEDIUM" else "gray")
                self._p("  [%s%s%s] %-14s %s"
                        % (c(color), sev, c("reset"),
                           r.get("module") or "-", r.get("title") or ""))
            if not rows:
                self._p("  (none)")
            return False
        if topic == "hosts":
            rows = self.store.hosts_list(limit=200)
            self._section("HOSTS (%d)" % len(rows))
            for r in rows:
                self._p("  %-30s %-16s %s"
                        % (r.get("host") or "-", r.get("ip") or "-",
                           r.get("last_seen") or ""))
            if not rows:
                self._p("  (none)")
            return False
        if topic == "services":
            rows = self.store.services_list(limit=200)
            self._section("SERVICES (%d)" % len(rows))
            for r in rows:
                self._p("  %-24s %-6s %-6s %s"
                        % (r.get("host") or "-", r.get("port") or "-",
                           r.get("proto") or "tcp", r.get("name") or ""))
            if not rows:
                self._p("  (none)")
            return False
        if topic == "notes":
            return self.cmd_notes([])
        if topic == "banner":
            return self.cmd_banner([])
        self._p("Unknown show topic %r. Try: %s"
                % (args[0] if args else "", "|".join(SHOW_TOPICS)))
        return False

    def cmd_use(self, args: List[str]) -> bool:
        if not args:
            self._p("Usage: use <module-path>  (see 'show modules')")
            return False
        try:
            module = get_module(args[0])
        except KeyError:
            self._p("%smodule not found — try `show modules`%s"
                    % (c("red"), c("reset")))
            return False
        self.current_module = module
        self.options = {}
        # Defensive lazy probe of the concurrently-written social package.
        if module.kind == "social":
            try:
                importlib.import_module(
                    "nexora.social.%s" % module.path.split("/", 1)[1])
            except Exception:
                self._p("%ssocial module unavailable%s — the social package "
                        "is not installed/loaded yet"
                        % (c("yellow"), c("reset")))
        self._p("[*] using %s — %s" % (module.path, module.title))
        return False

    def cmd_back(self, args: List[str]) -> bool:
        self.current_module = None
        self.options = {}
        self._p("[*] back to global context")
        return False

    def cmd_info(self, args: List[str]) -> bool:
        if self.current_module is None:
            self._p("No module selected. Use 'use <path>' "
                    "(see 'show modules').")
            return False
        self._p(describe(self.current_module))
        return False

    def cmd_set(self, args: List[str]) -> bool:
        if len(args) < 2:
            self._p("Usage: set <option> <value>")
            return False
        name, value = args[0], " ".join(args[1:])
        opt = self._find_option(name)
        if opt is None:
            self._p("%swarning:%s unknown option %r for %s (storing anyway)"
                    % (c("yellow"), c("reset"), name,
                       self.current_module.path if self.current_module
                       else "console"))
            self.options[name] = value
            return False
        if opt.kind == "int":
            try:
                int(value)
            except ValueError:
                self._p("%swarning:%s %r is not a valid integer for %r — "
                        "keeping %r"
                        % (c("yellow"), c("reset"), value, opt.name,
                           str(self.options.get(opt.name, opt.default))))
                return False
        elif opt.kind == "bool":
            if str(value).strip().lower() not in (
                    "true", "false", "1", "0", "yes", "no", "on", "off"):
                self._p("%swarning:%s %r is not a valid boolean for %r "
                        "(use true/false)"
                        % (c("yellow"), c("reset"), value, opt.name))
                return False
            value = str(_parse_bool(value)).lower()
        self.options[opt.name] = value
        self._p("  %s => %s" % (opt.name, value))
        return False

    def cmd_unset(self, args: List[str]) -> bool:
        if not args:
            self._p("Usage: unset <option>")
            return False
        removed = False
        for key in list(self.options):
            if key.lower() == args[0].lower():
                del self.options[key]
                removed = True
        if removed:
            self._p("[*] unset %s" % args[0])
        else:
            self._p("[*] %s was not set" % args[0])
        return False

    def cmd_setg(self, args: List[str]) -> bool:
        if len(args) < 2:
            if self.globals:
                self._p("Global options:")
                for key, val in sorted(self.globals.items()):
                    self._p("  %s => %s" % (key, val))
            else:
                self._p("No global options set. Usage: setg <opt> <value>")
            return False
        name, value = args[0], " ".join(args[1:])
        opt = self._find_option(name)
        if opt is not None and opt.kind == "int":
            try:
                int(value)
            except ValueError:
                self._p("%swarning:%s %r is not a valid integer for %r"
                        % (c("yellow"), c("reset"), value, opt.name))
                return False
        self.globals[name] = value
        self._p("  %s => %s (global)" % (name, value))
        return False

    def cmd_unsetg(self, args: List[str]) -> bool:
        if not args:
            self._p("Usage: unsetg <option>")
            return False
        removed = False
        for key in list(self.globals):
            if key.lower() == args[0].lower():
                del self.globals[key]
                removed = True
        self._p("[*] unsetg %s" % args[0] if removed
                else "[*] %s was not a global" % args[0])
        return False

    def cmd_run(self, args: List[str]) -> bool:
        if self.current_module is None:
            self._p("%sNo module selected. Use 'use <path>' first "
                    "(see 'show modules').%s" % (c("red"), c("reset")))
            return False
        module = self.current_module
        eff = self._effective_options()
        missing = [o.name for o in module.options
                   if o.required and str(eff.get(o.name) or "").strip() == ""]
        if missing:
            self._p("%smissing required option(s):%s %s"
                    % (c("red"), c("reset"), ", ".join(missing)))
            return False

        def emit(event: str, data: Any) -> None:
            self._p("  %s[+]%s %s: %s"
                    % (c("green"), c("reset"), event, data))

        started = time.time()
        try:
            runner_mod = importlib.import_module(module.runner_ref[0])
            runner = getattr(runner_mod, module.runner_ref[1], None)
            if not callable(runner):
                raise AttributeError(
                    "runner %s:%s missing" % (module.runner_ref,))
            result = runner(eff, emit)
        except Exception as exc:
            self._p("%srunner failed: %s: %s%s"
                    % (c("red"), type(exc).__name__, exc, c("reset")))
            return False
        elapsed = time.time() - started
        if not isinstance(result, dict):
            result = {"error": "module returned non-dict result"}
        if "error" in result:
            self._p("%serror:%s %s"
                    % (c("red"), c("reset"), result["error"]))
            return False
        self._p("%s[*]%s completed in %.1fs"
                % (c("green"), c("reset"), elapsed))
        # Compact summary: interesting keys + sources_status counts.
        interesting = ("score", "grade", "risk", "found", "count",
                       "security_score", "subdomains", "breach_check")
        summary_bits = []
        for key in interesting:
            val = result.get(key)
            if val is None or val == [] or val == {}:
                continue
            if isinstance(val, (list, dict)):
                summary_bits.append("%s=%d" % (key, len(val)))
            else:
                summary_bits.append("%s=%s" % (key, val))
        if summary_bits:
            self._p("  " + "  ".join(summary_bits))
        status = result.get("sources_status")
        if isinstance(status, dict) and status:
            counts: Dict[str, int] = {}
            for state in status.values():
                key = str(state).split(":", 1)[0]
                counts[key] = counts.get(key, 0) + 1
            self._p("  sources: " + "  ".join(
                "%s=%d" % kv for kv in sorted(counts.items())))
        target = str(eff.get("target") or eff.get("handle")
                     or eff.get("domain") or "")
        _ingest(module.path, target, result, self.store)
        return False

    def cmd_workspace(self, args: List[str]) -> bool:
        if not args:
            current = self.store.current_workspace()
            self._section("WORKSPACES")
            for name in self.store.list_workspaces():
                marker = "*" if name == current else " "
                self._p(" %s %s" % (marker, name))
            return False
        try:
            self.store.use_workspace(args[0])
        except ValueError as exc:
            self._p("%serror:%s %s" % (c("red"), c("reset"), exc))
            return False
        self._p("[*] workspace: %s" % self.store.current_workspace())
        return False

    def cmd_search(self, args: List[str]) -> bool:
        term = " ".join(args).strip()
        if not term:
            self._p("Usage: search <term>")
            return False
        rows = self.store.search(term, limit=50)
        self._section("SEARCH: %s (%d)" % (term, len(rows)))
        for r in rows:
            source = r.get("source") or "?"
            if source == "findings":
                self._p("  findings  %-10s %s" % (r.get("severity") or "",
                                                  r.get("title") or ""))
            elif source == "evidence":
                self._p("  evidence  %-10s %s" % (r.get("kind") or "",
                                                  r.get("target") or ""))
            elif source == "hosts":
                self._p("  hosts     %-10s %s" % (r.get("ip") or "",
                                                  r.get("host") or ""))
            elif source == "notes":
                body = str(r.get("body") or "")
                self._p("  notes     %s" % body[:70])
        if not rows:
            self._p("  (no matches)")
        return False

    def cmd_notes(self, args: List[str]) -> bool:
        if args and args[0].lower() == "add":
            body = " ".join(args[1:]).strip()
            if not body:
                self._p("Usage: notes add <text>")
                return False
            self.store.add_note(body)
            self._p("[*] note added")
            return False
        rows = self.store.notes_list(limit=50)
        self._section("NOTES (%d)" % len(rows))
        for r in rows:
            self._p("  %s  %s" % (r.get("created") or "", r.get("body") or ""))
        if not rows:
            self._p("  (none — 'notes add <text>' to create one)")
        return False

    def cmd_export(self, args: List[str]) -> bool:
        if not args:
            self._p("Usage: export <file>")
            return False
        try:
            path = self.store.export_json(args[0])
        except Exception as exc:
            self._p("%sexport failed: %s%s" % (c("red"), exc, c("reset")))
            return False
        self._p("[*] workspace exported to %s" % path)
        return False

    def cmd_cache(self, args: List[str]) -> bool:
        action = (args[0].lower() if args else "stats")
        try:
            from .cache import cache_clear, cache_stats
        except Exception as exc:
            self._p("%scache unavailable: %s%s" % (c("red"), exc, c("reset")))
            return False
        if action == "stats":
            stats = cache_stats()
            self._section("CACHE")
            for key, val in sorted(stats.items()):
                self._p("  %-16s %s" % (key, val))
        elif action == "clear":
            cache_clear()
            self._p("[*] cache cleared")
        else:
            self._p("Usage: cache stats|clear")
        return False

    def cmd_history(self, args: List[str]) -> bool:
        self._section("HISTORY (%d)" % len(self.history))
        for i, line in enumerate(self.history, 1):
            self._p("  %4d  %s" % (i, line))
        if not self.history:
            self._p("  (empty)")
        return False

    def cmd_version(self, args: List[str]) -> bool:
        self._p(VERSION_STRING)
        return False

    def cmd_banner(self, args: List[str]) -> bool:
        try:
            print_banner(stream=self.out)
        except Exception:
            pass
        return False

    def cmd_quit(self, args: List[str]) -> bool:
        return True

    # ------------------------------------------------------------------ #
    # Dispatch
    # ------------------------------------------------------------------ #
    def execute(self, line: str) -> bool:
        """Execute one command line; returns True when quit was requested."""
        raw = (line or "").strip()
        if not raw or raw.startswith("#"):
            return False
        self.history.append(raw)
        try:
            # posix=False keeps Windows backslash paths intact; we strip
            # the surrounding quotes shell-words style ourselves.
            parts = shlex.split(raw, posix=False)
        except ValueError:
            parts = raw.split()
        parts = [p[1:-1] if len(p) >= 2 and p[0] == p[-1]
                 and p[0] in ("'", '"') else p for p in parts]
        if not parts:
            return False
        token = parts[0].lower()
        method_name = getattr(self, "_HANDLERS", {}).get(token)
        handler = getattr(self, method_name, None) if method_name else None
        if not callable(handler):
            self._p("%sUnknown command '%s'. Type 'help'.%s"
                    % (c("red"), parts[0], c("reset")))
            close = difflib.get_close_matches(token, COMMANDS, n=1, cutoff=0.6)
            if close:
                self._p("Did you mean '%s'?" % close[0])
            return False
        return handler(parts[1:])

    # Maps command token -> method name (bound lazily at dispatch time so
    # the table can live at class level).
    _HANDLERS: Dict[str, str] = {
        "help": "cmd_help", "?": "cmd_help",
        "show": "cmd_show",
        "use": "cmd_use",
        "back": "cmd_back",
        "info": "cmd_info",
        "set": "cmd_set",
        "unset": "cmd_unset",
        "setg": "cmd_setg",
        "unsetg": "cmd_unsetg",
        "run": "cmd_run", "scan": "cmd_run", "go": "cmd_run",
        "workspace": "cmd_workspace",
        "search": "cmd_search",
        "notes": "cmd_notes",
        "export": "cmd_export",
        "cache": "cmd_cache",
        "history": "cmd_history",
        "version": "cmd_version",
        "banner": "cmd_banner",
        "quit": "cmd_quit", "exit": "cmd_quit", "q": "cmd_quit",
    }

    def run_lines(self, lines: Sequence[str]) -> int:
        """Execute a list of command lines (batch mode); 0 on clean exit."""
        for raw in lines:
            for piece in split_commands(str(raw)):
                if self.execute(piece):
                    return 0
        return 0

    def loop(self) -> int:
        """Interactive read-eval-print loop until quit/EOF."""
        while True:
            try:
                line = input(self.prompt())
            except EOFError:
                self._p("")
                return 0
            except KeyboardInterrupt:
                self._p("")
                self._p("%s^C (use 'quit' to exit)%s" % (c("yellow"),
                                                         c("reset")))
                continue
            if self.execute(line):
                self._p("[*] bye")
                return 0


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nexconsole",
        description="Nexconsole — Metasploit-style console for Nexora OSINT.",
        epilog='examples:\n'
               '  nexconsole\n'
               '  nexconsole -c "show modules"\n'
               '  nexconsole -c "use recon/ip; set target 1.2.3.4; run"\n'
               '  nexconsole -x commands.txt --db workspace.db\n',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-c", "--command", metavar="CMD",
                        help="run one or more ;-separated commands and exit")
    parser.add_argument("-x", "--execute", metavar="FILE",
                        help="read commands from FILE (one per line) and exit")
    parser.add_argument("--db", metavar="PATH", default=None,
                        help="workspace database path "
                             "(default: ~/.nexora/nexora.db)")
    parser.add_argument("--no-color", action="store_true",
                        help="disable colored output")
    parser.add_argument("--no-banner", action="store_true",
                        help="suppress the startup banner")
    parser.add_argument("--quiet", action="store_true",
                        help="no banner (batch-friendly)")
    parser.add_argument("--version", action="version",
                        version=VERSION_STRING)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    # Windows pipes default to cp1252 — force UTF-8 so box chars don't crash.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            pass
    args = _build_parser().parse_args(argv)

    enable_colors(force=(not args.no_color
                         and not os.environ.get("NO_COLOR")
                         and sys.stdout.isatty()))
    show_banner = not (args.no_banner or args.quiet
                       or os.environ.get("NEXORA_NO_BANNER"))
    if show_banner:
        try:
            print_banner()
        except Exception:
            pass

    try:
        store = Store(args.db)
    except Exception as exc:
        print("%serror: cannot open workspace database: %s%s"
              % (c("red"), exc, c("reset")), file=sys.stderr)
        return 1

    batch = args.command is not None or args.execute is not None
    console = Nexconsole(store, interactive=not batch)
    try:
        if args.command is not None:
            return console.run_lines(split_commands(args.command))
        if args.execute is not None:
            try:
                with open(args.execute, "r", encoding="utf-8",
                          errors="replace") as fh:
                    text = fh.read()
            except OSError as exc:
                print("%scannot read %s: %s%s"
                      % (c("red"), args.execute, exc, c("reset")),
                      file=sys.stderr)
                return 1
            return console.run_lines(split_commands(text))
        console._p("[*] Nexconsole — type 'help' for commands, "
                   "'show modules' for the registry")
        return console.loop()
    finally:
        store.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
