"""IP address investigation (RDAP, BGP/ASN, reputation, Shodan, ports, reverse IP, threat intel)."""
from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple

from .net import http_get, http_post, reset_circuit_breaker
from .output import c, header

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
_COMMON_PORTS: Tuple[int, ...] = (
    21, 22, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433,
    2049, 3000, 3306, 3389, 5432, 5601, 5900, 6379, 6443, 8080, 8443,
    9200, 27017,
)

_SERVICE_MAP: Dict[int, str] = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 2049: "NFS", 3000: "HTTP-DEV",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana",
    5900: "VNC", 6379: "Redis", 6443: "K8s-API", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 9200: "Elasticsearch", 27017: "MongoDB",
}

_HTTP_PORTS = {80, 3000, 8000, 8080}
_TLS_PORTS = {443, 8443}

_IPAPI_FIELDS = (
    "status,message,country,countryCode,regionName,city,isp,org,as,asname,"
    "reverse,mobile,proxy,hosting"
)

# source name -> result key -> collector (returns (value, status, detail))
_Task = Tuple[str, str, Callable[[], Tuple[Any, str, str]]]


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _notify(status_cb: Optional[Callable[..., None]], source: str,
            info: Dict[str, Any]) -> None:
    """Invoke the optional progress callback; never let it break a scan."""
    if status_cb is None:
        return
    try:
        status_cb(source, info)
    except Exception:
        pass


def _clip(text: Optional[str], limit: int = 120) -> Optional[str]:
    if not text:
        return None
    text = " ".join(str(text).split())
    return text[: limit - 1] + "…" if len(text) > limit else text


def _clean_banner(data: bytes, limit: int = 160) -> Optional[str]:
    text = data.decode("utf-8", "ignore")
    text = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in text)
    text = " ".join(text.split())
    return text[:limit] or None


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v]
    return [str(value)]


# --------------------------------------------------------------------------- #
# Collectors — each returns (value, status, detail) and never raises
# --------------------------------------------------------------------------- #
def _collect_reverse_dns(ip: str) -> Tuple[Optional[str], str, str]:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        hostname = (hostname or "").strip().rstrip(".")
        if hostname:
            return hostname, "ok", hostname
        return None, "no_results", "no PTR record"
    except (socket.herror, socket.gaierror):
        return None, "no_results", "no PTR record"
    except Exception as e:
        return None, f"error: {type(e).__name__}", str(e)[:80]


def _rdap_abuse_contacts(entities: Any, depth: int = 0) -> List[str]:
    """Recursively collect e-mail addresses from 'abuse' role entities."""
    out: List[str] = []
    if not isinstance(entities, (list, tuple)) or depth > 3:
        return out
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        roles = [str(r).lower() for r in (ent.get("roles") or []) if r]
        if "abuse" in roles:
            vcard = ent.get("vcardArray")
            if isinstance(vcard, (list, tuple)) and len(vcard) > 1 \
                    and isinstance(vcard[1], (list, tuple)):
                for item in vcard[1]:
                    if isinstance(item, (list, tuple)) and len(item) > 3 \
                            and str(item[0]).lower() == "email":
                        addr = str(item[3]).strip()
                        if addr and addr not in out:
                            out.append(addr)
        for addr in _rdap_abuse_contacts(ent.get("entities"), depth + 1):
            if addr not in out:
                out.append(addr)
    return out


def _collect_rdap(ip: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    resp = http_get(f"https://rdap.org/ip/{ip}", timeout=10)
    if resp is None:
        return None, "error: no_response", "RDAP endpoint unreachable"
    if resp.status_code == 404:
        return None, "http_404", "not found"
    if resp.status_code != 200:
        return None, f"http_{resp.status_code}", ""
    try:
        data = resp.json()
    except Exception:
        return None, "error: invalid_json", ""

    registration: Optional[str] = None
    for ev in (data.get("events") or []):
        if isinstance(ev, dict) and str(ev.get("eventAction", "")).lower() == "registration":
            registration = ev.get("eventDate")
            break

    out: Dict[str, Any] = {
        "name": data.get("name"),
        "handle": data.get("handle"),
        "country": data.get("country"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "registration": registration,
        "parent_handle": data.get("parentHandle"),
        "abuse_contacts": _rdap_abuse_contacts(data.get("entities")),
    }
    summary = _clip(str(out["handle"] or out["name"] or "registered"), 60) or "registered"
    return out, "ok", summary


def _collect_bgp(ip: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    resp = http_get(f"https://api.bgpview.io/ip/{ip}", timeout=10)
    if resp is None:
        return None, "error: no_response", "BGP view unreachable"
    if resp.status_code != 200:
        return None, (f"http_{resp.status_code}" if resp.status_code != 404 else "http_404"), ""
    try:
        data = resp.json().get("data") or {}
    except Exception:
        return None, "error: invalid_json", ""

    prefixes = data.get("prefixes") or []
    if not prefixes:
        prefixes = list(data.get("ipv4_prefixes") or []) + list(data.get("ipv6_prefixes") or [])
    if not prefixes:
        return None, "no_results", "no announced prefix"

    p = prefixes[0] if isinstance(prefixes[0], dict) else {}
    asn_raw = p.get("asn")
    asn = asn_raw if isinstance(asn_raw, dict) else {}

    def pick(key: str, fallback: Any = None) -> Any:
        for src in (asn, p):
            v = src.get(key)
            if v not in (None, "", []):
                return v
        return fallback

    out: Dict[str, Any] = {
        "asn": asn_raw.get("asn") if isinstance(asn_raw, dict) else asn_raw,
        "name": pick("name"),
        "country": pick("country_code") or pick("country"),
        "rir": pick("rir"),
        "prefix": p.get("prefix"),
        "description": pick("description") or pick("name"),
        "website": pick("website"),
        "email_contacts": _as_list(pick("email_contacts")),
        "abuse_contacts": _as_list(pick("abuse_contacts")),
    }
    if out["asn"] is None and not out["prefix"]:
        return None, "no_results", "no announced prefix"
    label = f"AS{out['asn']}" if out["asn"] is not None else "?"
    name = out.get("description") or out.get("name")
    summary = _clip(f"{label} {name}", 60) or label
    return out, "ok", summary


def _collect_geo(ip: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    """Combine ipinfo.io + ip-api.com + GreyNoise into one geo/reputation dict."""
    geo: Dict[str, Any] = {}
    ok = nodata = 0
    fail: Optional[str] = None

    def _put(key: str, value: Any) -> None:
        if value is not None and value != "" and key not in geo:
            geo[key] = value

    # --- ipinfo.io -------------------------------------------------------- #
    resp = http_get(f"https://ipinfo.io/{ip}/json", timeout=6)
    if resp is None:
        fail = "error: no_response"
    elif resp.status_code == 200:
        try:
            d = resp.json() or {}
            for key in ("hostname", "city", "region", "country", "loc", "org"):
                _put(key, d.get(key))
            ok += 1
        except Exception:
            fail = "error: invalid_json"
    elif resp.status_code == 404:
        nodata += 1
    else:
        fail = f"http_{resp.status_code}"

    # --- ip-api.com (free tier, plain http) ------------------------------ #
    resp = http_get(f"http://ip-api.com/json/{ip}?fields={_IPAPI_FIELDS}", timeout=6)
    if resp is None:
        fail = "error: no_response"
    elif resp.status_code == 200:
        try:
            d = resp.json() or {}
            if d.get("status") == "success":
                _put("hostname", d.get("reverse"))
                _put("city", d.get("city"))
                _put("region", d.get("regionName"))
                _put("country", d.get("country"))
                _put("org", d.get("org"))
                _put("isp", d.get("isp"))
                as_field = str(d.get("as") or "")
                m = re.match(r"AS(\d+)", as_field)
                if m:
                    geo["asn"] = int(m.group(1))
                if d.get("asname"):
                    geo["asname"] = str(d["asname"])
                elif as_field and "asn" in geo:
                    geo["asname"] = as_field[m.end():].strip() or None
                geo["is_mobile"] = bool(d.get("mobile"))
                geo["is_proxy"] = bool(d.get("proxy"))
                geo["is_hosting"] = bool(d.get("hosting"))
                ok += 1
            else:
                nodata += 1
        except Exception:
            fail = "error: invalid_json"
    elif resp.status_code == 404:
        nodata += 1
    else:
        fail = f"http_{resp.status_code}"

    # --- GreyNoise community API ----------------------------------------- #
    resp = http_get(f"https://api.greynoise.io/v3/community/{ip}", timeout=6)
    if resp is None:
        fail = "error: no_response"
    elif resp.status_code == 200:
        try:
            d = resp.json() or {}
            for src, dst in (("noise", "greynoise_noise"), ("riot", "greynoise_riot"),
                             ("classification", "greynoise_classification"),
                             ("name", "greynoise_name")):
                if d.get(src) is not None:
                    geo[dst] = d[src]
            ok += 1
        except Exception:
            fail = "error: invalid_json"
    elif resp.status_code == 404:
        nodata += 1  # IP not observed by GreyNoise
    else:
        fail = f"http_{resp.status_code}"

    # Fallback ASN parsing from ipinfo's org ("AS15169 GOOGLE LLC")
    if "asn" not in geo and geo.get("org"):
        m = re.match(r"AS(\d+)", str(geo["org"]))
        if m:
            geo["asn"] = int(m.group(1))

    geo = {k: v for k, v in geo.items() if v is not None}
    if geo:
        summary = ", ".join(
            str(geo[k]) for k in ("city", "region", "country") if geo.get(k))
        summary = summary or str(
            geo.get("org") or geo.get("isp")
            or geo.get("greynoise_classification") or "geo/reputation")
        return geo, "ok", _clip(summary, 60) or "geo/reputation"
    if ok or nodata:
        return None, "no_results", "no geo data for this address"
    return None, fail or "no_results", "geo sources unreachable"


def _collect_shodan(ip: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    resp = http_get(f"https://internetdb.shodan.io/{ip}", timeout=6)
    if resp is None:
        return None, "error: no_response", "InternetDB unreachable"
    if resp.status_code == 404:
        return None, "http_404", "not indexed"
    if resp.status_code != 200:
        return None, f"http_{resp.status_code}", ""
    try:
        d = resp.json() or {}
    except Exception:
        return None, "error: invalid_json", ""
    ports = _as_list(d.get("ports")) if not isinstance(d.get("ports"), list) \
        else [str(p) for p in d.get("ports")]
    out: Dict[str, Any] = {
        "ports": ports,
        "cpes": _as_list(d.get("cpes")),
        "vulns": _as_list(d.get("vulns")),
        "hostnames": _as_list(d.get("hostnames")),
        "cdn": d.get("cdn"),
        "tags": _as_list(d.get("tags")),
    }
    return out, "ok", f"{len(out['ports'])} ports, {len(out['vulns'])} vulns"


def _collect_reverse_ip(ip: str) -> Tuple[List[str], str, str]:
    resp = http_get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=10)
    if resp is None:
        return [], "error: no_response", "reverse IP service unreachable"
    if resp.status_code != 200:
        return [], f"http_{resp.status_code}", ""
    text = (resp.text or "").strip()
    low = text.lower()
    if "api count exceeded" in low:
        return [], "error: api_count_exceeded", "API quota exhausted"
    if low.startswith("error"):
        return [], "error: rejected", _clip(text.splitlines()[0], 60) or "rejected"
    seen: List[str] = []
    for line in text.splitlines():
        host = line.strip()
        if host and host not in seen:
            seen.append(host)
        if len(seen) >= 50:
            break
    if not seen:
        return [], "no_results", "no co-hosted domains"
    return seen, "ok", f"{len(seen)} hostnames"


def _collect_feodo(ip: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    resp = http_get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=15)
    if resp is None:
        return None, "error: no_response", "FeodoTracker unreachable"
    if resp.status_code != 200:
        return None, (f"http_{resp.status_code}" if resp.status_code != 404 else "http_404"), ""
    try:
        entries = resp.json()
    except Exception:
        return None, "error: invalid_json", ""
    if not isinstance(entries, list):
        entries = []
    known = {str(e.get("ip_address", "")) for e in entries if isinstance(e, dict)}
    if ip in known:
        return {"known_c2": True, "matched_ips": [ip]}, "ok", "known C2 match"
    return {"known_c2": False, "matched_ips": []}, "ok", "clean"


def _collect_urlhaus(ip: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    resp = http_post("http://urlhaus-api.abuse.ch/v1/host/",
                     data={"host": ip}, timeout=12)
    if resp is None:
        return None, "error: no_response", "URLhaus unreachable"
    if resp.status_code != 200:
        return None, (f"http_{resp.status_code}" if resp.status_code != 404 else "http_404"), ""
    try:
        d = resp.json() or {}
    except Exception:
        return None, "error: invalid_json", ""
    query_status = str(d.get("query_status") or "unknown")
    if query_status == "ok":
        status = "ok"
    elif query_status in ("no_results", "no_query", "invalid_host"):
        status = "no_results"
    else:
        status = f"error: {query_status}"[:60]
    raw_urls = d.get("urls") if isinstance(d.get("urls"), list) else []
    urls: List[Dict[str, Any]] = []
    for u in raw_urls:
        if not isinstance(u, dict):
            continue
        urls.append({
            "url": u.get("url"),
            "status": u.get("url_status") or u.get("status"),
            "threat": u.get("threat"),
            "date_added": u.get("date_added"),
        })
        if len(urls) >= 5:
            break
    try:
        count = int(d.get("urls_online") or 0)
    except (TypeError, ValueError):
        count = len(urls)
    out = {"status": query_status, "url_count": count, "urls": urls}
    detail = f"{count} malicious URLs" if count else "clean"
    return out, status, detail


# --------------------------------------------------------------------------- #
# Port scanning
# --------------------------------------------------------------------------- #
def _probe_port(ip: str, port: int) -> Optional[Dict[str, Any]]:
    """Connect to one port; return an entry dict when open, else None."""
    try:
        sock = socket.create_connection((ip, port), timeout=2)
    except Exception:
        return None

    service = _SERVICE_MAP.get(port, "unknown")
    banner: Optional[str] = None
    title: Optional[str] = None
    tls_failed = False
    try:
        if port in _TLS_PORTS:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock)
            except Exception:
                tls_failed = True

        if tls_failed:
            pass  # port is open, TLS handshake failed — no banner
        elif port in _HTTP_PORTS or port in _TLS_PORTS:
            request = (
                f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            try:
                sock.sendall(request)
                sock.settimeout(2)
                data = b""
                while len(data) < 1024:
                    chunk = sock.recv(min(1024 - len(data), 512))
                    if not chunk:
                        break
                    data += chunk
                text = data.decode("utf-8", "ignore")
                banner = _clip(text.split("\n", 1)[0].strip(), 100)
                m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
                if m:
                    title = _clip(" ".join(m.group(1).split()), 120)
            except Exception:
                pass
        else:
            try:
                sock.settimeout(2)
                banner = _clean_banner(sock.recv(256))
            except Exception:
                pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return {"port": port, "state": "open", "service": service,
            "banner": banner, "title": title}


def _scan_ports(ip: str) -> Tuple[List[Dict[str, Any]], str, str]:
    found: List[Dict[str, Any]] = []
    try:
        with ThreadPoolExecutor(max_workers=30) as pool:
            futures = [pool.submit(_probe_port, ip, p) for p in _COMMON_PORTS]
            for fut in as_completed(futures):
                try:
                    entry = fut.result()
                except Exception:
                    continue
                if entry:
                    found.append(entry)
    except Exception as e:
        found.sort(key=lambda e2: e2["port"])
        return found, f"error: {type(e).__name__}", str(e)[:80]
    found.sort(key=lambda e2: e2["port"])
    return (found, f"{len(found)} open",
            f"{len(found)} of {len(_COMMON_PORTS)} common ports open")


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def lookup_ip(ip: str, *, scan_ports: bool = True,
              status_cb: Optional[Callable[..., None]] = None) -> Dict[str, Any]:
    """Investigate an IP address across RDAP, BGP, reputation and threat feeds.

    Returns a JSON-serializable dict. Raises ValueError for invalid input.
    """
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        raise ValueError(f"invalid IP address: {ip}")
    ip = str(addr)

    reset_circuit_breaker()

    sources_status: Dict[str, str] = {}
    result: Dict[str, Any] = {
        "ip": ip,
        "reverse_dns": None,
        "rdap": None,
        "bgp": None,
        "geo": None,
        "shodan": None,
        "reverse_ip": [],
        "threat_intel": None,
        "ports": [],
        "sources_status": sources_status,
    }

    tasks: List[_Task] = [
        ("reverse-dns", "reverse_dns", lambda: _collect_reverse_dns(ip)),
        ("rdap", "rdap", lambda: _collect_rdap(ip)),
        ("bgp", "bgp", lambda: _collect_bgp(ip)),
        ("geo", "geo", lambda: _collect_geo(ip)),
        ("shodan", "shodan", lambda: _collect_shodan(ip)),
        ("reverse-ip", "reverse_ip", lambda: _collect_reverse_ip(ip)),
        ("threat-feodo", "_feodo", lambda: _collect_feodo(ip)),
        ("threat-urlhaus", "_urlhaus", lambda: _collect_urlhaus(ip)),
    ]
    if scan_ports:
        tasks.append(("port-scan", "_ports", lambda: _scan_ports(ip)))
    else:
        tasks.append(("port-scan", "_ports",
                      lambda: ([], "skipped", "port scan disabled")))

    extra: Dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(fn): (name, key) for name, key, fn in tasks}
        for fut in as_completed(futures):
            name, key = futures[fut]
            try:
                value, status, detail = fut.result()
            except Exception as e:
                value, status, detail = None, f"error: {type(e).__name__}", str(e)[:80]
            sources_status[name] = status
            if key in ("_feodo", "_urlhaus"):
                extra[key] = value
            elif key == "_ports":
                if value:
                    result["ports"] = value
            else:
                result[key] = value
            _notify(status_cb, name, {"status": status, "detail": detail})

    feodo = extra.get("_feodo")
    urlhaus = extra.get("_urlhaus")
    if feodo is not None or urlhaus is not None:
        result["threat_intel"] = {"feodo": feodo, "urlhaus": urlhaus}

    return result


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
    """Print a colored human-readable report (reads fine without colors)."""
    ip_addr = str(result.get("ip") or "?")
    geo = result.get("geo") or {}
    rdap = result.get("rdap") or {}
    bgp = result.get("bgp") or {}
    shodan = result.get("shodan") or {}
    ti = result.get("threat_intel") or {}

    # ---------------------------------------------------------------- SUMMARY
    header("SUMMARY")
    print(f"  IP            {c('bold')}{ip_addr}{c('reset')}")
    ptr = result.get("reverse_dns")
    print(f"  Reverse DNS   {ptr if ptr else '-'}")
    loc = ", ".join(str(geo[k]) for k in ("city", "region", "country")
                    if geo.get(k))
    print(f"  Location      {loc or '-'}")
    print(f"  Org / ISP     {geo.get('org') or geo.get('isp') or '-'}")
    asn = geo.get("asn")
    asn_txt = f"AS{asn}" if asn is not None else "-"
    if geo.get("asname"):
        asn_txt += f" ({geo['asname']})"
    print(f"  ASN           {asn_txt}")
    gn = geo.get("greynoise_classification")
    if gn:
        if gn == "benign":
            gn_col = c("green")
        elif gn == "malicious":
            gn_col = c("red")
        else:
            gn_col = c("gray")
        print(f"  GreyNoise     {gn_col}{gn}{c('reset')}")

    # ------------------------------------------------------------------ RDAP
    header("RDAP")
    if rdap:
        print(f"  Handle        {rdap.get('handle') or '-'}")
        print(f"  Name          {rdap.get('name') or '-'}")
        print(f"  Country       {rdap.get('country') or '-'}")
        start = rdap.get("start_address")
        end = rdap.get("end_address")
        if start or end:
            print(f"  Range         {start or '?'} - {end or '?'}")
        print(f"  Registration  {rdap.get('registration') or '-'}")
        print(f"  Parent        {rdap.get('parent_handle') or '-'}")
        abuse = rdap.get("abuse_contacts") or []
        if abuse:
            print(f"  Abuse contact {', '.join(abuse)}")
    else:
        print(f"  {c('gray')}(no RDAP data){c('reset')}")

    # ------------------------------------------------------------------ BGP
    header("BGP")
    if bgp:
        asn_b = bgp.get("asn")
        print(f"  ASN           {'AS' + str(asn_b) if asn_b is not None else '-'}"
              + (f" {bgp.get('name')}" if bgp.get("name") else ""))
        print(f"  Prefix        {bgp.get('prefix') or '-'}")
        print(f"  Country       {bgp.get('country') or '-'}")
        print(f"  RIR           {bgp.get('rir') or '-'}")
        print(f"  Description   {bgp.get('description') or '-'}")
        if bgp.get("website"):
            print(f"  Website       {bgp['website']}")
        email_c = bgp.get("email_contacts") or []
        abuse_c = bgp.get("abuse_contacts") or []
        if email_c:
            print(f"  Email         {', '.join(email_c)}")
        if abuse_c:
            print(f"  Abuse         {', '.join(abuse_c)}")
    else:
        print(f"  {c('gray')}(no BGP data){c('reset')}")

    # -------------------------------------------------------- SHODAN INTERNETDB
    header("SHODAN INTERNETDB")
    if shodan:
        ports = shodan.get("ports") or []
        print(f"  Ports         {', '.join(str(p) for p in ports) if ports else '-'}")
        cpes = shodan.get("cpes") or []
        if cpes:
            print(f"  CPEs          {', '.join(cpes[:10])}"
                  + (f" (+{len(cpes) - 10} more)" if len(cpes) > 10 else ""))
        vulns = shodan.get("vulns") or []
        if vulns:
            print(f"  Vulns         {c('red')}{', '.join(vulns)}{c('reset')}")
        tags = shodan.get("tags") or []
        if tags:
            print(f"  Tags          {', '.join(tags)}")
    else:
        print(f"  {c('gray')}(no Shodan InternetDB data){c('reset')}")

    # ----------------------------------------------------------- REPUTATION
    header("REPUTATION")
    flags = [("Mobile", geo.get("is_mobile")),
             ("Proxy/VPN", geo.get("is_proxy")),
             ("Hosting/CDN", geo.get("is_hosting"))]
    shown = False
    for label, val in flags:
        if val is None:
            continue
        shown = True
        col = c("yellow") if val else c("gray")
        print(f"  {label:<14}{col}{'yes' if val else 'no'}{c('reset')}")
    if geo.get("greynoise_name"):
        shown = True
        print(f"  {'GreyNoise name':<14}{geo['greynoise_name']}")
    if geo.get("greynoise_riot") is not None:
        shown = True
        col = c("yellow") if geo.get("greynoise_riot") else c("gray")
        print(f"  {'GreyNoise RIOT':<14}{col}"
              f"{'yes' if geo.get('greynoise_riot') else 'no'}{c('reset')}")
    if not shown:
        print(f"  {c('gray')}(no reputation data){c('reset')}")

    # ----------------------------------------------------------- OPEN PORTS
    header("OPEN PORTS")
    ports = result.get("ports") or []
    if not ports:
        print(f"  {c('gray')}(no open ports found){c('reset')}")
    for entry in ports:
        port = entry.get("port")
        service = entry.get("service") or "?"
        extra = entry.get("title") or entry.get("banner") or ""
        extra = str(extra)[:60]
        print(f"  {str(port):<6}{service:<14}"
              + (f"{c('dim')}{extra}{c('reset')}" if extra else ""))

    # ----------------------------------------------------------- REVERSE IP
    header("REVERSE IP")
    hosts = result.get("reverse_ip") or []
    if not hosts:
        print(f"  {c('gray')}(no results){c('reset')}")
    for h in hosts[:20]:
        print(f"  {h}")
    if len(hosts) > 20:
        print(f"  {c('dim')}... and {len(hosts) - 20} more{c('reset')}")

    # -------------------------------------------------------- THREAT INTEL
    header("THREAT INTEL")
    feodo = ti.get("feodo")
    if feodo is None:
        print(f"  FeodoTracker  {c('gray')}(unavailable){c('reset')}")
    elif feodo.get("known_c2"):
        print(f"  FeodoTracker  {c('red')}IP matches known botnet C2{c('reset')}")
    else:
        print(f"  FeodoTracker  {c('green')}clean - not a known C2{c('reset')}")
    urlhaus = ti.get("urlhaus")
    if urlhaus is None:
        print(f"  URLhaus       {c('gray')}(unavailable){c('reset')}")
    else:
        count = urlhaus.get("url_count") or 0
        if count:
            print(f"  URLhaus       {c('red')}{count} malicious URLs online"
                  f"{c('reset')}")
            for u in (urlhaus.get("urls") or [])[:5]:
                print(f"    {c('dim')}{u.get('url')} ({u.get('threat')})"
                      f"{c('reset')}")
        elif urlhaus.get("status") in ("no_results", "ok"):
            print(f"  URLhaus       {c('green')}clean - no malicious URLs"
                  f"{c('reset')}")
        else:
            print(f"  URLhaus       {c('gray')}({urlhaus.get('status')})"
                  f"{c('reset')}")

    # -------------------------------------------------------- SOURCE STATUS
    header("SOURCE STATUS")
    statuses = result.get("sources_status") or {}
    for name in sorted(statuses):
        value = str(statuses[name])
        print(f"  {name:<16}{_status_color(value)}{value}{c('reset')}")