"""Autonomous System (ASN) lookup: BGPView, RIPE Stats and bgp.he.net.

Fully key-free: public JSON/HTML endpoints only. Every source degrades
gracefully and reports its outcome in ``sources_status`` ("ok" /
"no_results" / "http_404" / "error: <ExcName>" / "skipped: ...").
"""
from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple

from .net import http_get, reset_circuit_breaker
from .output import c, header

# --------------------------------------------------------------------------- #
# Optional shared cache (nexora/cache.py may not exist yet)
# --------------------------------------------------------------------------- #
if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "cache.py")):
    try:
        from .cache import cache_get, cache_set  # type: ignore
    except Exception:  # cache.py half-written / broken -> no-op
        def cache_get(key: str, max_age_seconds: int) -> Any:
            return None

        def cache_set(key: str, value: Any) -> None:
            return None
else:
    def cache_get(key: str, max_age_seconds: int) -> Any:
        return None

    def cache_set(key: str, value: Any) -> None:
        return None

# --------------------------------------------------------------------------- #
# Constants / helpers
# --------------------------------------------------------------------------- #
_ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)
_CACHE_TTL = 3600  # seconds

# each collector returns (value, status, detail) and never raises
_Task = Tuple[str, str, Callable[[], Tuple[Any, str, str]]]


def _notify(status_cb: Optional[Callable[..., None]], source: str,
            info: Dict[str, Any]) -> None:
    """Invoke the optional progress callback; never let it break a scan."""
    if status_cb is None:
        return
    try:
        status_cb(source, info)
    except Exception:
        pass


def _err_status(token: str) -> str:
    """Map an internal error token to a sources_status string (idempotent)."""
    if token.startswith("error:") or token.startswith("http_"):
        return token
    if token == "no_response":
        return "error: no_response"
    if token == "404":
        return "http_404"
    return f"error: {token}"


# --------------------------------------------------------------------------- #
# Optional caching wrapper around collectors
# --------------------------------------------------------------------------- #
def _cached(label: str, num: str,
            fn: Callable[[], Tuple[Any, str, str]]) -> Tuple[Any, str, str]:
    """Fetch through the shared cache when available (ok/no_results only)."""
    key = f"nexora:asn:{num}:{label}"
    try:
        hit = cache_get(key, _CACHE_TTL)
    except Exception:
        hit = None
    if isinstance(hit, dict) and "value" in hit and "status" in hit:
        return hit.get("value"), str(hit.get("status")), str(hit.get("detail") or "")
    value, status, detail = fn()
    if status in ("ok", "no_results", "http_404"):
        try:
            cache_set(key, {"value": value, "status": status, "detail": detail})
        except Exception:
            pass
    return value, status, detail


# --------------------------------------------------------------------------- #
# Collectors
# --------------------------------------------------------------------------- #
def _collect_details(num: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    """BGPView ASN registration details."""
    try:
        resp = http_get(f"https://api.bgpview.io/asn/{num}", timeout=8)
        if resp is None:
            return None, "error: no_response", "bgpview unreachable"
        if resp.status_code == 404:
            return None, "http_404", "ASN not found"
        if resp.status_code != 200:
            return None, f"http_{resp.status_code}", ""
        try:
            payload = resp.json()
        except Exception:
            return None, "error: invalid_json", ""
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict) or not data:
            return None, "no_results", "empty payload"
        out = {
            "asn": data.get("asn"),
            "name": data.get("name"),
            "description_short": data.get("description_short"),
            "country_code": data.get("country_code"),
            "rir": data.get("rir"),
            "website": [str(w) for w in (data.get("website") or []) if w],
            "email_contacts": [str(e) for e in (data.get("email_contacts") or []) if e],
            "abuse_contacts": [str(e) for e in (data.get("abuse_contacts") or []) if e],
        }
        return out, "ok", str(out.get("name") or out.get("description_short") or "")
    except Exception as e:
        return None, f"error: {type(e).__name__}", str(e)[:80]


def _collect_prefixes(num: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    """BGPView announced IPv4/IPv6 prefixes (capped at 50 each)."""
    try:
        resp = http_get(f"https://api.bgpview.io/asn/{num}/prefixes", timeout=8)
        if resp is None:
            return None, "error: no_response", "bgpview unreachable"
        if resp.status_code == 404:
            return None, "http_404", "ASN not found"
        if resp.status_code != 200:
            return None, f"http_{resp.status_code}", ""
        try:
            payload = resp.json()
        except Exception:
            return None, "error: invalid_json", ""
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            return None, "no_results", "empty payload"

        def _clean(items: Any, version: str) -> List[Dict[str, Any]]:
            out: List[Dict[str, Any]] = []
            for p in (items or [])[:50]:
                if not isinstance(p, dict) or not p.get("prefix"):
                    continue
                out.append({
                    "prefix": p.get("prefix"),
                    "name": p.get("name"),
                    "description": p.get("description"),
                    "country_code": p.get("country_code"),
                    "version": version,
                })
            return out

        ipv4 = _clean(data.get("ipv4_prefixes"), "ipv4")
        ipv6 = _clean(data.get("ipv6_prefixes"), "ipv6")
        total = len(ipv4) + len(ipv6)
        if not total:
            return {"ipv4_prefixes": [], "ipv6_prefixes": []}, "no_results", ""
        return {"ipv4_prefixes": ipv4, "ipv6_prefixes": ipv6}, "ok", \
            f"{len(ipv4)} ipv4 / {len(ipv6)} ipv6"
    except Exception as e:
        return None, f"error: {type(e).__name__}", str(e)[:80]


def _collect_relations(num: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    """BGPView upstream / downstream / peer AS relationships (cap 25 each)."""
    try:
        sections: Dict[str, List[Dict[str, Any]]] = {}
        statuses: List[str] = []
        counts: List[str] = []
        for label in ("upstreams", "downstreams", "peers"):
            resp = http_get(f"https://api.bgpview.io/asn/{num}/{label}", timeout=8)
            items: List[Dict[str, Any]] = []
            if resp is None:
                statuses.append("error: no_response")
            elif resp.status_code == 404:
                statuses.append("http_404")
            elif resp.status_code != 200:
                statuses.append(f"http_{resp.status_code}")
            else:
                try:
                    payload = resp.json()
                    data = payload.get("data") if isinstance(payload, dict) else None
                    lst = (data or {}).get("list") or []
                    for it in lst[:25]:
                        if isinstance(it, dict) and it.get("asn") is not None:
                            items.append({
                                "asn": it.get("asn"),
                                "name": it.get("name"),
                                "country_code": it.get("country_code"),
                            })
                    statuses.append("ok")
                except Exception as e:
                    statuses.append(f"error: {type(e).__name__}")
            sections[label] = items
            counts.append(f"{len(items)} {label}")
        if all(s == "ok" for s in statuses) or "ok" in statuses:
            status = "ok"
        else:
            first = next((s for s in statuses if s.startswith("error")), "")
            status = first or statuses[0]
        return sections, status, ", ".join(counts)
    except Exception as e:
        return None, f"error: {type(e).__name__}", str(e)[:80]


def _ripe_request(out: Dict[str, Any], endpoint: str, num: str,
                  parse: Callable[[Dict[str, Any]], None]) -> str:
    """One RIPEstat call; returns 'ok' or an error token, never raises.

    The spec-mandated endpoints (asn-overview / prefix-overview) are tried
    first; if RIPEstat no longer serves them for AS resources the caller falls
    back to a live equivalent endpoint.
    """
    resp = http_get(f"https://stat.ripe.net/data/{endpoint}/data.json",
                    params={"resource": f"AS{num}"}, timeout=8)
    if resp is None:
        return "no_response"
    if resp.status_code == 404:
        return "404"
    if resp.status_code != 200:
        return f"http_{resp.status_code}"
    try:
        data = (resp.json() or {}).get("data") or {}
        parse(data)
        return "ok"
    except Exception as e:
        return f"error: {type(e).__name__}"


def _collect_ripe(num: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    """RIPEstat ASN overview + announced prefix count (with live fallbacks)."""
    try:
        out: Dict[str, Any] = {
            "holder": None, "announced": None, "asns": None,
            "count": None, "block": None, "as_name": None,
            "country": None, "rir": None,
        }
        statuses: List[str] = []

        def _parse_overview(data: Dict[str, Any]) -> None:
            holder = data.get("holder")
            asns = data.get("asns") or []
            if not holder and isinstance(asns, list) and asns \
                    and isinstance(asns[0], dict):
                holder = asns[0].get("holder")
            out["holder"] = holder
            out["announced"] = data.get("announced")
            out["asns"] = asns or None

        status = _ripe_request(out, "asn-overview", num, _parse_overview)
        if status != "ok":
            statuses.append(status)

            def _parse_whois(data: Dict[str, Any]) -> None:
                flat: Dict[str, Any] = {}
                for grp in (data.get("records") or []):
                    for item in (grp if isinstance(grp, list) else []):
                        if isinstance(item, dict) and item.get("key") is not None:
                            flat[str(item["key"]).lower()] = item.get("value")
                out["holder"] = flat.get("orgname") or flat.get("org-name") \
                    or out["holder"]
                out["as_name"] = flat.get("asname")
                out["country"] = flat.get("country")
                out["rir"] = flat.get("source")

            statuses.append(_ripe_request(out, "whois", num, _parse_whois))
        else:
            statuses.append("ok")

        def _parse_prefix_overview(data: Dict[str, Any]) -> None:
            out["count"] = data.get("count")
            out["asns"] = data.get("asns") or out["asns"]
            block = data.get("block")
            if isinstance(block, list):
                block = block[0] if block else None
            out["block"] = block

        status = _ripe_request(out, "prefix-overview", num, _parse_prefix_overview)
        if status != "ok":
            statuses.append(status)

            def _parse_announced(data: Dict[str, Any]) -> None:
                prefixes = data.get("prefixes") or []
                out["count"] = len(prefixes)
                if out["announced"] is None:
                    out["announced"] = bool(prefixes)

            statuses.append(_ripe_request(out, "announced-prefixes", num,
                                          _parse_announced))
        else:
            statuses.append("ok")

        if "ok" in statuses:
            detail = f"prefix count: {out['count']}" if out["count"] is not None \
                else str(out.get("holder") or "")
            return out, "ok", detail
        first_err = next((s for s in statuses if s.startswith("error")
                          or s.startswith("http_") or s == "no_response"), "")
        return out, _err_status(first_err) if first_err else "no_results", ""
    except Exception as e:
        return None, f"error: {type(e).__name__}", str(e)[:80]


def _row_cells(row: str) -> List[str]:
    """Strip a <tr> down to its cell texts (tags removed, whitespace squeezed)."""
    cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S | re.I)
    return [" ".join(re.sub(r"<[^>]+>", " ", cell).split()) for cell in cells]


def _looks_country(text: str) -> bool:
    return bool(re.fullmatch(r"[A-Z]{2}", text or ""))


def _collect_bgp_he(num: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    """Best-effort scrape of the bgp.he.net ASN page (name, prefixes, peers)."""
    try:
        resp = http_get(f"https://bgp.he.net/AS{num}", timeout=10)
        if resp is None:
            return None, "error: no_response", "bgp.he.net unreachable"
        if resp.status_code == 404:
            return None, "http_404", "AS not found"
        if resp.status_code != 200:
            return None, f"http_{resp.status_code}", ""
        try:
            html = resp.text[:2_000_000]
        except Exception:
            html = ""

        # Page title / <h1> as an ASN name fallback
        name: Optional[str] = None
        for pat in (r"<h1[^>]*>(.*?)</h1>", r"<title[^>]*>(.*?)</title>"):
            m = re.search(pat, html, re.S | re.I)
            if m:
                text = " ".join(re.sub(r"<[^>]+>", " ", m.group(1)).split())
                text = re.sub(r"(?i)\bbgp\.he\.net\b", "", text).strip(" -|")
                text = re.sub(rf"(?i)\bAS{num}\b", "", text).strip(" -|")
                if text:
                    name = text[:120]
                    break

        # Prefix rows: <a href="/net/1.2.3.0/24">...</a> plus adjacent cells
        prefixes: List[Dict[str, Any]] = []
        seen_prefixes = set()
        for row in re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.S | re.I):
            m = re.search(r'href="/net/([\d\.:a-f/]+)"', row)
            if not m or m.group(1) in seen_prefixes:
                continue
            seen_prefixes.add(m.group(1))
            info: Dict[str, Any] = {"prefix": m.group(1), "name": None,
                                    "country_code": None}
            rest = [t for t in _row_cells(row) if t and m.group(1) not in t]
            country = next((t for t in rest if _looks_country(t)), None)
            netname = next((t for t in rest if t != country and len(t) > 2
                            and not t[0].isdigit()), None)
            info["country_code"] = country
            info["name"] = netname
            prefixes.append(info)
            if len(prefixes) >= 30:
                break

        # Peer rows: <a href="/AS6939">AS6939</a> plus name/country cells
        peers: List[Dict[str, Any]] = []
        seen_asns = set()
        for row in re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.S | re.I):
            m = re.search(r'href="/AS(\d+)"', row)
            if not m:
                continue
            asn_i = int(m.group(1))
            if asn_i == int(num) or asn_i in seen_asns:
                continue
            seen_asns.add(asn_i)
            rest = [t for t in _row_cells(row) if t and f"AS{asn_i}" not in t]
            country = next((t for t in rest if _looks_country(t)), None)
            pname = next((t for t in rest if t != country and len(t) > 2), None)
            peers.append({"asn": asn_i, "name": pname, "country_code": country})
            if len(peers) >= 30:
                break
        if not peers:
            for asn_txt in re.findall(r">(AS\d+)<", html):
                asn_i = int(asn_txt[2:])
                if asn_i == int(num) or asn_i in seen_asns:
                    continue
                seen_asns.add(asn_i)
                peers.append({"asn": asn_i, "name": None, "country_code": None})
                if len(peers) >= 30:
                    break

        out = {"name": name, "prefixes": prefixes, "peers": peers}
        if not (name or prefixes or peers):
            return out, "no_results", "nothing parseable on page"
        return out, "ok", f"{len(prefixes)} prefixes / {len(peers)} peers"
    except Exception as e:
        return None, f"error: {type(e).__name__}", str(e)[:80]


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def lookup_asn(asn: str, *, status_cb: Optional[Callable[..., None]] = None) -> Dict[str, Any]:
    """Look up an Autonomous System across BGPView, RIPEstat and bgp.he.net.

    Accepts ``AS13335``, ``as13335`` or ``13335``. Returns a JSON-serializable
    dict; raises ValueError for invalid input. All sources degrade gracefully.
    """
    target = str(asn or "").strip()
    m = _ASN_RE.match(target)
    if not m:
        raise ValueError(f"invalid ASN: {asn}")
    num = m.group(1)

    reset_circuit_breaker()

    sources_status: Dict[str, str] = {}
    raw: Dict[str, Any] = {}

    tasks: List[_Task] = [
        ("bgpview-details", "details", lambda: _collect_details(num)),
        ("bgpview-prefixes", "prefixes", lambda: _collect_prefixes(num)),
        ("bgpview-relations", "relations", lambda: _collect_relations(num)),
        ("ripe-stat", "ripe", lambda: _collect_ripe(num)),
        ("bgp-he", "bgphe", lambda: _collect_bgp_he(num)),
    ]

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(_cached, name, num, fn): name
                   for name, key, fn in tasks}
        key_by_name = {name: key for name, key, _ in tasks}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                value, status, detail = fut.result()
            except Exception as e:
                value, status, detail = None, f"error: {type(e).__name__}", str(e)[:80]
            sources_status[name] = status
            raw[key_by_name[name]] = value
            _notify(status_cb, name, {"status": status, "detail": detail})

    # ------------------------------------------------------------------ merge
    details = raw.get("details") or {}
    prefixes_data = raw.get("prefixes") or {}
    relations = raw.get("relations") or {}
    ripe = raw.get("ripe") or {}
    bgp_he = raw.get("bgphe") or {}

    prefixes: List[Dict[str, Any]] = []
    seen_prefixes = set()
    for group, version in ((prefixes_data.get("ipv4_prefixes"), "ipv4"),
                           (prefixes_data.get("ipv6_prefixes"), "ipv6")):
        for p in (group or []):
            key = str(p.get("prefix") or "")
            if key and key not in seen_prefixes:
                seen_prefixes.add(key)
                prefixes.append(dict(p, version=p.get("version") or version))
    for p in (bgp_he.get("prefixes") or []):
        key = str(p.get("prefix") or "")
        if key and key not in seen_prefixes:
            seen_prefixes.add(key)
            prefixes.append({"prefix": p.get("prefix"), "name": p.get("name"),
                             "description": None,
                             "country_code": p.get("country_code"),
                             "version": None})

    def _merge_as(items_a: Any, items_b: Any, key: str) -> List[Dict[str, Any]]:
        merged: List[Dict[str, Any]] = []
        seen = set()
        for group in (items_a, items_b):
            for it in (group or []):
                if not isinstance(it, dict):
                    continue
                k = it.get(key)
                if k is None or k in seen:
                    continue
                seen.add(k)
                merged.append(it)
        return merged

    peers = _merge_as(relations.get("peers"), bgp_he.get("peers"), "asn")
    upstreams = list(relations.get("upstreams") or [])
    downstreams = list(relations.get("downstreams") or [])

    contacts: List[str] = []
    for addr in (details.get("email_contacts") or []) + \
            (details.get("abuse_contacts") or []):
        if addr and addr not in contacts:
            contacts.append(addr)

    as_name = details.get("name") or details.get("description_short") \
        or ripe.get("as_name") or bgp_he.get("name")
    country = details.get("country_code") or ripe.get("country")
    rir = details.get("rir") or ripe.get("rir")

    count = ripe.get("count")
    if count is None and ripe.get("asns") is not None:
        try:
            count = len(ripe.get("asns") or []) or None
        except Exception:
            count = None

    return {
        "asn": num,
        "as_name": as_name,
        "holder": ripe.get("holder"),
        "country": country,
        "rir": rir,
        "description": details.get("description_short"),
        "website": list(details.get("website") or []),
        "contacts": contacts,
        "announced": ripe.get("announced"),
        "announced_prefix_count": count,
        "prefixes": prefixes,
        "upstreams": upstreams,
        "downstreams": downstreams,
        "peers": peers,
        "ripe": ripe or None,
        "sources_status": sources_status,
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _status_color(value: str) -> str:
    if value.startswith("ok"):
        return c("green")
    if value.startswith("error"):
        return c("red")
    return c("gray")


def render_text(result: Dict[str, Any]) -> None:
    """Print a colored human-readable ASN report."""
    num = result.get("asn") or "?"

    # ---------------------------------------------------------------- SUMMARY
    header("SUMMARY")
    print(f"  ASN           {c('bold')}AS{num}{c('reset')}")
    print(f"  Name          {result.get('as_name') or '-'}")
    print(f"  Holder        {result.get('holder') or '-'}")
    print(f"  Country       {result.get('country') or '-'}")
    print(f"  RIR           {result.get('rir') or '-'}")
    print(f"  Description   {result.get('description') or '-'}")
    website = result.get("website") or []
    print(f"  Website       {', '.join(website) if website else '-'}")
    contacts = result.get("contacts") or []
    if contacts:
        print(f"  Contacts      {', '.join(contacts)}")
    announced = result.get("announced")
    if announced is None:
        ann_txt = f"{c('gray')}unknown{c('reset')}"
    elif announced:
        ann_txt = f"{c('green')}announced{c('reset')}"
    else:
        ann_txt = f"{c('yellow')}not announced{c('reset')}"
    count = result.get("announced_prefix_count")
    if count is not None:
        ann_txt += f" ({count} prefixes)"
    print(f"  Announced     {ann_txt}")

    # ---------------------------------------------------------------- PREFIXES
    header("PREFIXES")
    prefixes = result.get("prefixes") or []
    if not prefixes:
        print(f"  {c('gray')}(no prefix data){c('reset')}")
    else:
        for p in prefixes[:20]:
            extra_bits = [str(p.get(k)) for k in ("name", "country_code")
                          if p.get(k)]
            extra = f"  {c('dim')}{', '.join(extra_bits)}{c('reset')}" \
                if extra_bits else ""
            print(f"  {p.get('prefix') or '?'}{extra}")
        if len(prefixes) > 20:
            print(f"  {c('dim')}+{len(prefixes) - 20} more{c('reset')}")

    # ---------------------------------------------------------- RELATIONSHIPS
    header("RELATIONSHIPS")
    for label, key in (("Peers", "peers"), ("Upstreams", "upstreams"),
                       ("Downstreams", "downstreams")):
        items = result.get(key) or []
        print(f"  {label}{c('dim')} ({len(items)}){c('reset')}")
        for it in items[:15]:
            if not isinstance(it, dict):
                continue
            asn_i = it.get("asn")
            tag = f"AS{asn_i}" if asn_i is not None else "AS?"
            name = it.get("name") or ""
            print(f"    {tag} {name}".rstrip())
        if len(items) > 15:
            print(f"    {c('dim')}+{len(items) - 15} more{c('reset')}")

    # ------------------------------------------------------------------- RIPE
    header("RIPE")
    ripe = result.get("ripe") or {}
    if ripe:
        print(f"  Holder        {ripe.get('holder') or '-'}")
        announced = ripe.get("announced")
        if announced is None:
            print(f"  Announced     {c('gray')}unknown{c('reset')}")
        else:
            col = c("green") if announced else c("yellow")
            print(f"  Announced     {col}{'yes' if announced else 'no'}{c('reset')}")
        if ripe.get("block"):
            print(f"  Block         {ripe['block']}")
    else:
        print(f"  {c('gray')}(no RIPE data){c('reset')}")

    # --------------------------------------------------------- SOURCE STATUS
    header("SOURCE STATUS")
    statuses = result.get("sources_status") or {}
    for name in sorted(statuses):
        value = str(statuses[name])
        print(f"  {name:<18}{_status_color(value)}{value}{c('reset')}")
