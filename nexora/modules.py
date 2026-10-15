"""Nexconsole module registry — Metasploit-style ``show modules``.

A :class:`Module` is a static description (path, kind, options) plus a
``runner_ref`` pointing at a callable. The runner is resolved **lazily**
via ``importlib`` only at run time, so importing ``nexora.modules`` never
imports the heavy/network-collecting modules (``osint``, ``nexora.ip``,
``nexora.social``, ...).

Runner contract::

    runner(options: dict, emit) -> dict

``options`` holds the effective values (defaults + setg globals + set
values, coerced by option kind, plus a private ``_module_path`` key);
``emit(event: str, data)`` streams progress to the console. Runners
never raise: failures come back as ``{"error": "..."}``.
"""
from __future__ import annotations

import importlib
import inspect
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

# Registry: path -> Module (populated by register()/register_builtins()).
REGISTRY: Dict[str, "Module"] = {}


@dataclass
class Option:
    """A module option. ``kind`` is one of ``str`` / ``int`` / ``bool``."""
    name: str
    default: Any = ""
    required: bool = False
    description: str = ""
    kind: str = "str"


@dataclass
class Module:
    """Static module descriptor; the runner is imported only at run time."""
    path: str
    kind: str
    title: str
    description: str = ""
    options: List[Option] = field(default_factory=list)
    runner_ref: Tuple[str, str] = ("nexora.modules", "_missing_runner")


# --------------------------------------------------------------------------- #
# Registry API
# --------------------------------------------------------------------------- #
def register(module: Module) -> Module:
    """Register (or replace) a module in the global registry."""
    REGISTRY[module.path] = module
    return module


def get(path: str) -> Module:
    """Look up a module by path; raises KeyError with a friendly message."""
    key = str(path or "").strip()
    module = REGISTRY.get(key) or REGISTRY.get(key.lower())
    if module is None:
        raise KeyError(
            "module not found: %r — try `show modules` for the registry" % (path,))
    return module


def list_modules(kind: Optional[str] = None) -> List[Module]:
    """All modules sorted by path, optionally filtered by kind."""
    mods = sorted(REGISTRY.values(), key=lambda m: m.path)
    if kind:
        kind = str(kind).strip().lower()
        mods = [m for m in mods if m.kind.lower() == kind]
    return mods


def search(term: str) -> List[Module]:
    """Case-insensitive substring match over path/title/description."""
    needle = str(term or "").strip().lower()
    if not needle:
        return list_modules()
    return [m for m in list_modules()
            if needle in m.path.lower()
            or needle in m.title.lower()
            or needle in (m.description or "").lower()]


def describe(module: Module) -> str:
    """Human-readable ``info`` text for one module."""
    lines = [
        "Name: %s" % module.path,
        "Kind: %s" % module.kind,
        "Title: %s" % module.title,
    ]
    if module.description:
        lines.append("Description: %s" % module.description)
    ref = "%s:%s" % (module.runner_ref[0], module.runner_ref[1]) \
        if len(module.runner_ref) == 2 else "(none)"
    lines.append("Runner: %s" % ref)
    lines.append("")
    if module.options:
        width = max(len(o.name) for o in module.options)
        lines.append("Options:")
        lines.append("  %-*s  %-8s  %-10s  %s" % (width, "Name", "Required",
                                                  "Default", "Description"))
        for opt in module.options:
            lines.append("  %-*s  %-8s  %-10s  %s" % (
                width, opt.name,
                "yes" if opt.required else "no",
                "-" if opt.default in ("", None) else str(opt.default),
                opt.description))
    else:
        lines.append("Options: (none)")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Generic dispatcher shared by the built-in runners
# --------------------------------------------------------------------------- #
def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in ("true", "1", "yes", "on"):
        return True
    if s in ("false", "0", "no", "off", ""):
        return False
    return bool(value)


def _invoke(fn: Callable[..., Any], target: Any, kwargs: Dict[str, Any],
            status_cb: Callable[..., None]) -> Any:
    """Call ``fn(target, **kwargs)`` pruning kwargs the signature rejects."""
    try:
        params = inspect.signature(fn).parameters
        has_var_kw = any(p.kind is inspect.Parameter.VAR_KEYWORD
                         for p in params.values())
        accepted: Optional[set] = set(params)
    except (TypeError, ValueError):
        has_var_kw, accepted = True, None
    call_kwargs = dict(kwargs)
    if has_var_kw or accepted is None or "status_cb" in accepted:
        call_kwargs["status_cb"] = status_cb
    if accepted is not None and not has_var_kw:
        call_kwargs = {k: v for k, v in call_kwargs.items() if k in accepted}
    return fn(target, **call_kwargs)


def _call_module_fn(module_path: str, fn_candidates: Iterable[str],
                    options: Dict[str, Any],
                    emit: Callable[[str, Any], None],
                    kwargs_map: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Import ``module_path`` lazily, pick the first callable in
    ``fn_candidates`` and call it with the module target.

    ``kwargs_map`` maps *function kwarg -> option name*. Failures come
    back as ``{"error": "..."}`` — this helper never raises.
    """
    opts = dict(options or {})
    try:
        mod = importlib.import_module(module_path)
    except Exception as exc:  # ImportError or anything at import time
        return {"error": "%s unavailable: %s: %s"
                % (module_path, type(exc).__name__, exc)}
    fn = None
    for name in fn_candidates:
        fn = getattr(mod, name, None)
        if callable(fn):
            break
    if not callable(fn):
        return {"error": "no entry point %s in %s"
                % (", ".join(fn_candidates), module_path)}
    target = ""
    for key in ("target", "handle", "domain"):
        val = opts.get(key)
        if val:
            target = str(val)
            break
    kwargs: Dict[str, Any] = {}
    for kwarg, opt_name in dict(kwargs_map or {}).items():
        if opt_name in opts and opts[opt_name] not in (None, ""):
            kwargs[kwarg] = opts[opt_name]

    def _status_cb(source: Any, info: Any = None, *_a: Any) -> None:
        try:
            if info in (None, ""):
                emit("source", str(source))
            else:
                emit("source", "%s: %s" % (source, info))
        except Exception:
            pass

    try:
        return _invoke(fn, target, kwargs, _status_cb)
    except Exception as exc:
        return {"error": "%s: %s" % (type(exc).__name__, exc)}


# --------------------------------------------------------------------------- #
# Built-in runners (implemented here so cli.py is never imported)
# --------------------------------------------------------------------------- #
def _run_recon_domain(options: Dict[str, Any],
                      emit: Callable[[str, Any], None]) -> Dict[str, Any]:
    """Full domain scan via the sibling ``osint`` engine."""
    opts = dict(options or {})
    try:
        target = str(opts.get("target") or "").strip()
        if not target:
            return {"error": "target is required"}
        try:
            timeout = int(opts.get("timeout") or 0)
        except (TypeError, ValueError):
            timeout = 0
        skip = {s.strip() for s in str(opts.get("skip") or "").split(",")
                if s.strip()}
        profile_name = str(opts.get("profile") or "").strip()
        if profile_name:
            from .profiles import get_profile  # light, stdlib-only
            profile = get_profile(profile_name)  # ValueError -> caught below
            if not timeout:
                timeout = profile.timeout
            skip |= set(profile.skip)

        import osint  # sibling engine — heavy, import only when running

        def _on_source(name: Any, _data: Any = None) -> None:
            try:
                emit("source", str(name))
            except Exception:
                pass

        result = osint.lookup_domain(
            target,
            timeout=timeout or None,
            skip_categories=skip or None,
            on_source_complete=_on_source,
        )
        payload = osint.intel_to_dict(result)
        if not isinstance(payload, dict):
            payload = {"result": payload}
        if _as_bool(opts.get("deep", False)):
            try:
                from .deep import collect_deep
                payload["deep"] = collect_deep(
                    target, status_cb=lambda n, i=None: _on_source(n))
            except Exception as exc:
                payload["deep_error"] = "%s: %s" % (type(exc).__name__, exc)
        return payload
    except Exception as exc:
        return {"error": "%s: %s" % (type(exc).__name__, exc)}


def _run_recon_ip(options: Dict[str, Any],
                  emit: Callable[[str, Any], None]) -> Dict[str, Any]:
    return _call_module_fn("nexora.ip", ("lookup_ip",), options, emit,
                           kwargs_map={"scan_ports": "ports"})


def _run_recon_email(options: Dict[str, Any],
                     emit: Callable[[str, Any], None]) -> Dict[str, Any]:
    return _call_module_fn("nexora.email", ("lookup_email",), options, emit)


def _run_recon_username(options: Dict[str, Any],
                        emit: Callable[[str, Any], None]) -> Dict[str, Any]:
    return _call_module_fn("nexora.username", ("lookup_username",), options,
                           emit, kwargs_map={"concurrency": "concurrency"})


def _run_recon_asn(options: Dict[str, Any],
                   emit: Callable[[str, Any], None]) -> Dict[str, Any]:
    return _call_module_fn("nexora.asn", ("lookup_asn",), options, emit)


def _run_recon_url(options: Dict[str, Any],
                   emit: Callable[[str, Any], None]) -> Dict[str, Any]:
    return _call_module_fn("nexora.url", ("lookup_url",), options, emit)


def _run_recon_phone(options: Dict[str, Any],
                     emit: Callable[[str, Any], None]) -> Dict[str, Any]:
    return _call_module_fn("nexora.phone", ("lookup_phone",), options, emit)


def _run_util_deep(options: Dict[str, Any],
                   emit: Callable[[str, Any], None]) -> Dict[str, Any]:
    return _call_module_fn("nexora.deep", ("collect_deep",), options, emit)


def _run_util_cache(options: Dict[str, Any],
                    emit: Callable[[str, Any], None]) -> Dict[str, Any]:
    """``util/cache`` — show or clear the shared TTL cache."""
    try:
        from . import cache as cache_mod  # light (stdlib only)
    except Exception as exc:
        return {"error": "cache module unavailable: %s" % exc}
    action = str((options or {}).get("action") or "stats").strip().lower()
    try:
        if action == "stats":
            stats = cache_mod.cache_stats()
            try:
                emit("cache", "stats: %s file entries"
                     % stats.get("file_entries", 0))
            except Exception:
                pass
            return dict(stats)
        if action == "clear":
            cache_mod.cache_clear()
            stats = cache_mod.cache_stats()
            try:
                emit("cache", "cleared")
            except Exception:
                pass
            return {"cleared": True}
        return {"error": "unknown action: %r (use stats|clear)" % (action,)}
    except Exception as exc:
        return {"error": "%s: %s" % (type(exc).__name__, exc)}


# social/* all route through here; the console injects ``_module_path`` so
# we know which nexora.social submodule to load.
_SOCIAL_SPECS: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    "identity": ("nexora.social.identity", ("lookup_identity",)),
    "graph": ("nexora.social.graph", ("lookup_graph",)),
    "posts": ("nexora.social.posts", ("lookup_posts",)),
    # media: first callable wins (the module is written concurrently).
    "media": ("nexora.social.media",
              ("lookup_media", "inspect_url", "inspect_media")),
    "brand": ("nexora.social.brand", ("lookup_brand",)),
}


def _run_social(options: Dict[str, Any],
                emit: Callable[[str, Any], None]) -> Dict[str, Any]:
    """Dispatch to ``nexora.social.<name>`` — imported defensively."""
    opts = dict(options or {})
    name = str(opts.get("_module_path") or "").split("/")[-1].strip().lower()
    spec = _SOCIAL_SPECS.get(name)
    if spec is None:
        return {"error": "social module unavailable (unknown social module)"}
    module_path, candidates = spec
    try:
        importlib.import_module(module_path)
    except Exception:
        return {"error": "social modules unavailable"}
    # function kwarg -> option name, per submodule (signatures differ)
    kwargs_map = {
        "identity": {"exhaustive": "exhaustive"},
        "graph": {"max_items": "limit"},
        "posts": {"limit": "limit"},
        "media": {},
        "brand": {},
    }.get(name, {})
    return _call_module_fn(module_path, candidates, opts, emit,
                           kwargs_map=kwargs_map)


def _missing_runner(options: Dict[str, Any],
                    emit: Callable[[str, Any], None]) -> Dict[str, Any]:
    return {"error": "module has no runner"}


# --------------------------------------------------------------------------- #
# Built-in registrations (14 modules)
# --------------------------------------------------------------------------- #
def register_builtins() -> None:
    """(Re-)register the built-in recon/util/social modules."""
    register(Module(
        path="recon/domain", kind="recon",
        title="Full domain intelligence (DNS, subdomains, risk, takeover)",
        description="Runs the osint.py engine: DNS, subdomains, certificates, "
                    "risk score, takeover checks.",
        options=[
            Option("target", "", True, "domain, URL, or company name", "str"),
            Option("profile", "standard", False,
                   "scan profile (quick/standard/full/stealth)", "str"),
            Option("timeout", 0, False,
                   "overall timeout in seconds (0 = profile default)", "int"),
            Option("skip", "", False,
                   "comma-separated source categories to skip", "str"),
            Option("deep", False, False,
                   "also run deep recon (robots, dorks, wayback)", "bool"),
        ],
        runner_ref=("nexora.modules", "_run_recon_domain"),
    ))
    register(Module(
        path="recon/ip", kind="recon",
        title="IP address investigation (RDAP, BGP, reputation, ports)",
        options=[
            Option("target", "", True, "IPv4/IPv6 address", "str"),
            Option("ports", True, False, "run the TCP port scan", "bool"),
        ],
        runner_ref=("nexora.modules", "_run_recon_ip"),
    ))
    register(Module(
        path="recon/email", kind="recon",
        title="Email OSINT (MX/SPF/DMARC/DKIM, gravatar, breaches)",
        options=[
            Option("target", "", True, "email address", "str"),
        ],
        runner_ref=("nexora.modules", "_run_recon_email"),
    ))
    register(Module(
        path="recon/username", kind="recon",
        title="Username enumeration across 100+ sites",
        options=[
            Option("target", "", True, "username", "str"),
            Option("concurrency", 25, False, "parallel site checks", "int"),
        ],
        runner_ref=("nexora.modules", "_run_recon_username"),
    ))
    register(Module(
        path="recon/asn", kind="recon",
        title="ASN / network investigation",
        options=[
            Option("target", "", True, "ASN like AS13335 or 13335", "str"),
        ],
        runner_ref=("nexora.modules", "_run_recon_asn"),
    ))
    register(Module(
        path="recon/url", kind="recon",
        title="URL / HTTP inspection (redirects, TLS, headers)",
        options=[
            Option("target", "", True, "http(s):// URL", "str"),
        ],
        runner_ref=("nexora.modules", "_run_recon_url"),
    ))
    register(Module(
        path="recon/phone", kind="recon",
        title="Phone number intelligence (offline, key-free)",
        options=[
            Option("target", "", True, "phone number, e.g. +14155552671", "str"),
        ],
        runner_ref=("nexora.modules", "_run_recon_phone"),
    ))
    register(Module(
        path="util/deep", kind="util",
        title="Deep recon (robots, sitemap, dorks, documents, wayback)",
        options=[
            Option("target", "", True, "domain to deep-recon", "str"),
        ],
        runner_ref=("nexora.modules", "_run_util_deep"),
    ))
    register(Module(
        path="util/cache", kind="util",
        title="Show or clear the shared TTL cache",
        options=[
            Option("action", "stats", False, "stats | clear", "str"),
        ],
        runner_ref=("nexora.modules", "_run_util_cache"),
    ))
    register(Module(
        path="social/identity", kind="social",
        title="Cross-platform identity correlation for a handle",
        options=[
            Option("handle", "", True, "handle / username", "str"),
            Option("exhaustive", False, False,
                   "check all 100+ sites (default: priority subset)", "bool"),
        ],
        runner_ref=("nexora.modules", "_run_social"),
    ))
    register(Module(
        path="social/graph", kind="social",
        title="Social graph (linked accounts) for a handle",
        options=[
            Option("handle", "", True, "handle / username", "str"),
            Option("limit", 10, False, "max results", "int"),
        ],
        runner_ref=("nexora.modules", "_run_social"),
    ))
    register(Module(
        path="social/posts", kind="social",
        title="Recent posts lookup for a handle",
        options=[
            Option("handle", "", True, "handle / username", "str"),
            Option("limit", 10, False, "max results", "int"),
        ],
        runner_ref=("nexora.modules", "_run_social"),
    ))
    register(Module(
        path="social/media", kind="social",
        title="Media scrape for a URL / page",
        options=[
            Option("target", "", True, "URL or page to inspect", "str"),
            Option("limit", 10, False, "max results", "int"),
        ],
        runner_ref=("nexora.modules", "_run_social"),
    ))
    register(Module(
        path="social/brand", kind="social",
        title="Brand monitoring for a domain",
        options=[
            Option("domain", "", True, "brand / domain name", "str"),
            Option("limit", 10, False, "max results", "int"),
        ],
        runner_ref=("nexora.modules", "_run_social"),
    ))


register_builtins()
