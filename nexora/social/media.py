"""EXIF / GPS leak analysis + link-in-bio crawl.

``inspect_media(target)`` accepts:
  * an absolute http(s) image URL  -> EXIF + GPS extraction
  * an HTML page URL               -> scans its <img>/og:image for EXIF
  * ``handle:<name>``              -> link-in-bio crawl (linktr.ee,
    about.me) only, no image fetch.

EXIF parsing is pure (``extract_exif``) and covers JPEG (APP1/Exif TIFF),
PNG (tEXt/iTXt, best-effort zTXt) and WEBP (RIFF EXIF chunk). Every
parser is bounds-checked and wrapped so malformed input yields a partial
dict or {} — never an exception.
"""
from __future__ import annotations

import re
import struct
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..net import http_get, reset_circuit_breaker
from ..output import c, header

HANDLE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")

_MAX_BYTES = 10 * 1024 * 1024  # 10MB guard
_FETCH_TIMEOUT = 15

# anchor text / host -> platform label for link-in-bio results
_LINK_PLATFORMS = (
    ("twitter.com", "twitter"), ("x.com", "x"),
    ("instagram.com", "instagram"), ("tiktok.com", "tiktok"),
    ("github.com", "github"), ("youtube.com", "youtube"),
    ("linkedin.com", "linkedin"), ("discord.gg", "discord"),
    ("discord.com", "discord"), ("t.me", "telegram"),
    ("telegram.me", "telegram"), ("twitch.tv", "twitch"),
    ("facebook.com", "facebook"), ("threads.net", "threads"),
    ("reddit.com", "reddit"), ("medium.com", "medium"),
    ("soundcloud.com", "soundcloud"), ("spotify.com", "spotify"),
    ("bsky.app", "bluesky"), ("bsky.social", "bluesky"),
    ("mastodon.social", "mastodon"),
)

_IMG_SRC_RE = re.compile(r"<img[^>]+src=[\"']([^\"']+)[\"']", re.I)
_META_OG_RE = re.compile(
    r"<meta[^>]+(?:property|name)=[\"'](?:og:image|twitter:image)[\"']"
    r"[^>]+content=[\"']([^\"']+)[\"']", re.I)
_META_OG_RE2 = re.compile(
    r"<meta[^>]+content=[\"']([^\"']+)[\"'][^>]+"
    r"(?:property|name)=[\"'](?:og:image|twitter:image)[\"']", re.I)
_ANCHOR_RE = re.compile(r"<a[^>]+href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
                        re.S | re.I)


# --------------------------------------------------------------------------- #
# Fetch helper (streamed, capped, never raises)
# --------------------------------------------------------------------------- #
def _fetch_bytes(url: str, cap: int = _MAX_BYTES,
                 timeout: int = _FETCH_TIMEOUT
                 ) -> Tuple[Optional[int], bytes, str]:
    """GET with streaming. Returns (status_code, body<=cap, content_type)."""
    resp = http_get(url, timeout=timeout, stream=True)
    if resp is None:
        return None, b"", ""
    code: Optional[int] = None
    body = b""
    ctype = ""
    try:
        code = int(resp.status_code)
        try:
            ctype = str(resp.headers.get("Content-Type", "") or "")
        except Exception:
            ctype = ""
        if code == 200:
            buf = bytearray()
            for chunk in resp.iter_content(8192):
                if chunk:
                    buf.extend(chunk)
                if len(buf) >= cap:
                    break
            body = bytes(buf[:cap])
    except Exception:
        pass
    finally:
        try:
            resp.close()
        except Exception:
            pass
    return code, body, ctype


# --------------------------------------------------------------------------- #
# Kind detection (magic bytes + content type)
# --------------------------------------------------------------------------- #
def _detect_kind(data: bytes, content_type: str = "") -> str:
    """Classify a fetched body: jpeg / png / webp / pdf / page / binary."""
    head = data[:16]
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"\xff\xd8"):
        return "jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if (len(head) >= 12 and head.startswith(b"RIFF")
            and head[8:12] == b"WEBP"):
        return "webp"
    low = (content_type or "").lower()
    if "text/html" in low:
        return "page"
    if data[:5].lstrip().lower().startswith((b"<html", b"<!doc")):
        return "page"
    if "image/jpeg" in low or "image/jpg" in low:
        return "jpeg"
    if "image/png" in low:
        return "png"
    if "image/webp" in low:
        return "webp"
    if "application/pdf" in low:
        return "pdf"
    return "binary"


# --------------------------------------------------------------------------- #
# TIFF core (shared by JPEG APP1 and WEBP EXIF chunk)
# --------------------------------------------------------------------------- #
_TIFF_TYPES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def _read_tiff_value(data: bytes, entry_off: int, tag: int, typ: int,
                     count: int, endian: str) -> Any:
    """Read one IFD entry value (bounds-checked). Returns None on garbage."""
    unit = _TIFF_TYPES.get(typ)
    if unit is None or count <= 0:
        return None
    size = unit * count
    if size <= 4:
        value_off = entry_off + 8
    else:
        if entry_off + 12 > len(data):
            return None
        value_off = struct.unpack(endian + "I",
                                  data[entry_off + 8:entry_off + 12])[0]
    if value_off < 0 or value_off + size > len(data):
        return None
    raw = data[value_off:value_off + size]
    try:
        if typ == 2:  # ASCII
            return raw.split(b"\x00")[0].decode("utf-8", "ignore").strip()
        if typ == 1 or typ == 7:  # BYTE / UNDEFINED
            vals = list(raw)
            return vals if count > 1 else (vals[0] if vals else None)
        if typ in (3, 4, 9):
            fmt = {3: "H", 4: "I", 9: "i"}[typ]
            vals = list(struct.unpack(endian + fmt * count, raw))
            return vals if count > 1 else vals[0]
        # RATIONAL (5) / SRATIONAL (10)
        fmt2 = "2I" if typ == 5 else "2i"
        pairs = struct.unpack(endian + fmt2 * count, raw)
        vals = []
        for i in range(0, len(pairs), 2):
            num, den = pairs[i], pairs[i + 1]
            vals.append(num / den if den else 0.0)
        return vals if count > 1 else vals[0]
    except Exception:
        return None


def _read_ifd(data: bytes, offset: int, endian: str) -> Dict[int, Any]:
    """Parse one IFD -> {tag: value}. Bounds-checked; never raises."""
    out: Dict[int, Any] = {}
    try:
        if offset < 0 or offset + 2 > len(data):
            return out
        count = struct.unpack(endian + "H", data[offset:offset + 2])[0]
        # sanity: IFD with absurd entry count is corrupt
        if count > 256:
            return out
        for i in range(count):
            # each IFD entry is 12 bytes: tag(2) type(2) count(4) value(4)
            entry_off = offset + 2 + i * 12
            if entry_off + 12 > len(data):
                break
            tag, typ, cnt = struct.unpack(
                endian + "HHI", data[entry_off:entry_off + 8])
            val = _read_tiff_value(data, entry_off, tag, typ, cnt, endian)
            if val is not None:
                out[tag] = val
    except Exception:
        pass
    return out


_IFD0_FIELDS = {
    0x010E: "ImageDescription", 0x010F: "Make", 0x0110: "Model",
    0x0112: "Orientation", 0x0131: "Software", 0x0132: "DateTime",
    0x013B: "Artist", 0x8298: "Copyright",
}
_EXIF_FIELDS = {
    0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
    0xA002: "PixelXDimension", 0xA003: "PixelYDimension",
    0x920A: "FocalLength", 0x8827: "ISO",
}


def _parse_tiff(data: bytes) -> Dict[str, Any]:
    """Parse a TIFF blob (start of JPEG APP1 payload or WEBP EXIF chunk)."""
    out: Dict[str, Any] = {}
    try:
        if len(data) < 8:
            return out
        if data[:2] == b"II":
            endian = "<"
        elif data[:2] == b"MM":
            endian = ">"
        else:
            return out
        ifd0_off = struct.unpack(endian + "I", data[4:8])[0]
        ifd0 = _read_ifd(data, ifd0_off, endian)
        for tag, name in _IFD0_FIELDS.items():
            if tag in ifd0:
                out[name] = ifd0[tag]
        # Exif sub-IFD
        exif_off = ifd0.get(0x8769)
        if isinstance(exif_off, int):
            sub = _read_ifd(data, exif_off, endian)
            for tag, name in _EXIF_FIELDS.items():
                if tag in sub:
                    out[name] = sub[tag]
        # GPS sub-IFD -> decimal degrees
        gps_off = ifd0.get(0x8825)
        if isinstance(gps_off, int):
            gps_ifd = _read_ifd(data, gps_off, endian)
            lat_ref = str(gps_ifd.get(1, "N") or "N").upper()
            lon_ref = str(gps_ifd.get(3, "E") or "E").upper()
            lat_vals = gps_ifd.get(2)
            lon_vals = gps_ifd.get(4)

            def _deg(vals: Any) -> Optional[float]:
                if not isinstance(vals, (list, tuple)) or len(vals) < 3:
                    return None
                try:
                    return float(vals[0]) + float(vals[1]) / 60.0 \
                        + float(vals[2]) / 3600.0
                except Exception:
                    return None

            lat = _deg(lat_vals)
            lon = _deg(lon_vals)
            if lat is not None and lon is not None:
                if lat_ref == "S":
                    lat = -lat
                if lon_ref == "W":
                    lon = -lon
                out["gps"] = {"lat": round(lat, 6), "lon": round(lon, 6)}
    except Exception:
        pass  # partial dict is OK
    return out


# --------------------------------------------------------------------------- #
# Format wrappers
# --------------------------------------------------------------------------- #
def _jpeg_exif(data: bytes) -> Dict[str, Any]:
    """Scan JPEG segments for an APP1 'Exif' block and parse its TIFF."""
    try:
        pos = 2
        length = len(data)
        while pos + 4 <= length:
            if data[pos] != 0xFF:
                break
            marker = data[pos + 1]
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                pos += 2
                continue
            if marker in (0xD9, 0xDA):  # EOI / SOS — no more metadata
                break
            seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
            if seg_len < 2:
                break
            payload = data[pos + 4:pos + 2 + seg_len]
            if marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
                return _parse_tiff(payload[6:])
            pos += 2 + seg_len
    except Exception:
        pass
    return {}


def _png_exif(data: bytes) -> Dict[str, Any]:
    """Walk PNG chunks for tEXt / iTXt (zTXt best-effort) metadata."""
    out: Dict[str, Any] = {}
    wanted = {"Software", "Author", "Copyright", "Comment", "Creation Time"}
    try:
        pos = 8
        length = len(data)
        while pos + 8 <= length:
            chunk_len = struct.unpack(">I", data[pos:pos + 4])[0]
            chunk_type = data[pos + 4:pos + 8]
            body = data[pos + 8:pos + 8 + chunk_len]
            if len(body) < chunk_len:
                break
            if chunk_type == b"IEND":
                break
            if chunk_type in (b"tEXt", b"iTXt", b"zTXt"):
                nul = body.find(b"\x00")
                if nul > 0:
                    keyword = body[:nul].decode("utf-8", "ignore").strip()
                    if chunk_type == b"tEXt":
                        value = body[nul + 1:].decode("utf-8", "ignore")
                    elif chunk_type == b"iTXt":
                        # keyword \0 comp_flag comp_method lang \0 trans \0 text
                        rest = body[nul + 1:]
                        parts = rest.split(b"\x00", 2)
                        if len(parts) >= 3:
                            value = parts[2].decode("utf-8", "ignore")
                        else:
                            value = ""
                    else:  # zTXt: keyword \0 method zlib-data
                        try:
                            value = zlib.decompress(
                                body[nul + 2:]).decode("utf-8", "ignore")
                        except Exception:
                            value = ""
                    if keyword in wanted and value.strip():
                        out[keyword] = value.strip()[:300]
            pos += 12 + chunk_len
    except Exception:
        pass
    return out


def _webp_exif(data: bytes) -> Dict[str, Any]:
    """Find the RIFF 'EXIF' chunk in a WEBP container and parse TIFF."""
    try:
        pos = 12
        length = len(data)
        while pos + 8 <= length:
            chunk_id = data[pos:pos + 4]
            chunk_len = struct.unpack("<I", data[pos + 4:pos + 8])[0]
            body = data[pos + 8:pos + 8 + chunk_len]
            if len(body) < chunk_len:
                break
            if chunk_id == b"EXIF":
                if body.startswith(b"Exif\x00\x00"):
                    body = body[6:]
                return _parse_tiff(body)
            pos += 8 + chunk_len + (chunk_len % 2)
    except Exception:
        pass
    return {}


def extract_exif(data: bytes) -> Dict[str, Any]:
    """Extract EXIF metadata from raw image bytes (PURE).

    Returns a dict with Make/Model/DateTime/Software/... plus a ``gps``
    sub-dict {lat, lon} when coordinates are embedded. JPEG, PNG and
    WEBP are supported; garbage input yields {} without raising.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) < 8:
        return {}
    data = bytes(data)
    try:
        if data.startswith(b"\xff\xd8"):
            return _jpeg_exif(data)
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return _png_exif(data)
        if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
            return _webp_exif(data)
        # raw TIFF header (some exports)
        if data[:2] in (b"II", b"MM"):
            return _parse_tiff(data)
    except Exception:
        pass
    return {}


# --------------------------------------------------------------------------- #
# Target normalization
# --------------------------------------------------------------------------- #
def _normalize_target(target: str) -> Tuple[str, str]:
    """Return ("handle", name) or ("url", absolute_url). Raises ValueError."""
    t = (target or "").strip()
    if not t:
        raise ValueError("empty target")
    if t.lower().startswith("handle:"):
        name = t[7:].strip()
        if not HANDLE_RE.fullmatch(name):
            raise ValueError("invalid handle: %r" % (name,))
        return "handle", name
    if re.match(r"^[a-z][a-z0-9+.\-]*://", t, re.I):
        scheme = t.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            raise ValueError("unsupported scheme: %r" % (scheme,))
        return "url", t
    # bare host/path -> assume https
    if t.lower().startswith("javascript:") or t.lower().startswith("data:"):
        raise ValueError("unsupported target: %r" % (t,))
    return "url", "https://" + t.lstrip("/")


# --------------------------------------------------------------------------- #
# Link-in-bio crawl
# --------------------------------------------------------------------------- #
def _platform_for_url(url: str) -> Optional[str]:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return None
    for frag, label in _LINK_PLATFORMS:
        if host == frag or host.endswith("." + frag):
            return label
    return None


def _collect_bio_links(h: str) -> Tuple[List[dict], Dict[str, str]]:
    links: List[dict] = []
    sources_status: Dict[str, str] = {}
    seen: set = set()
    for source, base in (("linktree", f"https://linktr.ee/{h}"),
                         ("aboutme", f"https://about.me/{h}")):
        code, body, _ctype = _fetch_bytes(base, cap=512 * 1024)
        if code is None:
            sources_status[source] = "error: no_response"
            continue
        if code in (404, 410):
            sources_status[source] = "http_404"
            continue
        if code != 200:
            sources_status[source] = "blocked" if code in (401, 403, 429) \
                else "http_%d" % code
            continue
        html = body.decode("utf-8", "ignore")
        found_any = False
        for href, label_html in _ANCHOR_RE.findall(html):
            href = href.strip()
            if not href or href.startswith(("#", "javascript:", "mailto:")):
                continue
            if href.startswith("//"):
                href = "https:" + href
            if not href.startswith("http"):
                continue
            host = (urlparse(href).hostname or "").lower()
            if "linktr.ee" in host or "about.me" in host:
                continue  # skip self links
            platform = _platform_for_url(href)
            if platform is None:
                continue
            key = (platform, href.split("#")[0])
            if key in seen:
                continue
            seen.add(key)
            label = re.sub(r"<[^>]+>", "", label_html or "").strip()[:30]
            links.append({"label": label, "url": href, "platform": platform})
            found_any = True
            if len(links) >= 30:
                break
        sources_status[source] = "ok" if found_any else "no_results"
        if len(links) >= 30:
            break
    return links, sources_status


# --------------------------------------------------------------------------- #
# Page image scanning
# --------------------------------------------------------------------------- #
def _scan_page_images(page_url: str, html: str) -> Tuple[List[dict], str]:
    candidates: List[str] = []
    seen: set = set()
    for regex in (_META_OG_RE, _META_OG_RE2, _IMG_SRC_RE):
        for match in regex.findall(html):
            absolute = urljoin(page_url, match.strip())
            if not absolute.startswith("http"):
                continue
            if absolute not in seen:
                seen.add(absolute)
                candidates.append(absolute)
            if len(candidates) >= 6:
                break
        if len(candidates) >= 6:
            break

    results: List[dict] = []
    if not candidates:
        return results, "no_results"

    def _one(url: str) -> dict:
        code, body, ctype = _fetch_bytes(url)
        entry: Dict[str, Any] = {"url": url, "has_exif": False,
                                 "exif": {}, "gps": None}
        if code != 200 or not body:
            entry["error"] = "http_%s" % code if code is not None \
                else "no_response"
            return entry
        kind = _detect_kind(body, ctype)
        exif: Dict[str, Any] = {}
        if kind in ("jpeg", "png", "webp"):
            exif = extract_exif(body)
        entry["exif"] = exif
        entry["has_exif"] = bool(exif)
        entry["gps"] = exif.get("gps")
        return entry

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(_one, url) for url in candidates]
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                pass
    # keep the original candidate order for stable output
    order = {url: i for i, url in enumerate(candidates)}
    results.sort(key=lambda e: order.get(e.get("url", ""), 99))
    return results, "ok"


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #
def inspect_media(target: str, *,
                  status_cb: Optional[Callable[[str, dict], None]] = None
                  ) -> dict:
    """Inspect an image/page URL (or ``handle:`` target) for leaks.

    Returns {target, kind, exif, gps, image, images, counts, links, risk,
    sources_status}. Raises ValueError for malformed targets.
    """
    kind, normalized = _normalize_target(target)
    reset_circuit_breaker()

    sources_status: Dict[str, str] = {}
    exif: Dict[str, Any] = {}
    gps: Optional[Dict[str, float]] = None
    image_info: Optional[Dict[str, Any]] = None
    images: List[dict] = []
    links: List[dict] = []
    counts = {"checked": 0, "with_exif": 0, "with_gps": 0}
    risk: List[str] = []
    result_kind = "unknown"

    if kind == "handle":
        links, link_status = _collect_bio_links(normalized)
        sources_status.update(link_status)
        result_kind = "handle"
    else:
        code, body, ctype = _fetch_bytes(normalized)
        if code is None:
            sources_status["target"] = "error: no_response"
        elif code == 200:
            sources_status["target"] = "ok"
            result_kind = _detect_kind(body, ctype)
            if result_kind == "page":
                try:
                    html = body.decode("utf-8", "ignore")
                except Exception:
                    html = ""
                images, status = _scan_page_images(normalized, html)
                sources_status["images"] = status
                counts["checked"] = len(images)
                for entry in images:
                    if entry.get("has_exif"):
                        counts["with_exif"] += 1
                    if entry.get("gps"):
                        counts["with_gps"] += 1
            elif result_kind in ("jpeg", "png", "webp"):
                exif = extract_exif(body)
                gps = exif.get("gps")
                image_info = {
                    "url": normalized,
                    "content_type": ctype,
                    "size": len(body),
                    "kind": result_kind,
                }
                counts["checked"] = 1
                if exif:
                    counts["with_exif"] = 1
                if gps:
                    counts["with_gps"] = 1
            else:
                # pdf / binary — no EXIF to extract
                sources_status["images"] = "skipped: kind=%s" % result_kind
        else:
            sources_status["target"] = "blocked" \
                if code in (401, 403, 405, 429, 999) else "http_%d" % code

    # ---- risk lines -------------------------------------------------------- #
    if gps:
        risk.append("GPS coordinates embedded — location leak")
    if exif.get("Make") or exif.get("Model"):
        risk.append("Camera make/model exposed")
    if exif.get("Software") or exif.get("Artist") or exif.get("DateTime"):
        risk.append("Device/software metadata exposed")
    for entry in images:
        entry_gps = entry.get("gps")
        entry_exif = entry.get("exif") or {}
        if entry_gps and "GPS coordinates embedded — location leak" \
                not in risk:
            risk.append("GPS coordinates embedded — location leak")
        if (entry_exif.get("Make") or entry_exif.get("Model")) \
                and "Camera make/model exposed" not in risk:
            risk.append("Camera make/model exposed")
    if not exif and not any(e.get("has_exif") for e in images) \
            and result_kind in ("jpeg", "png", "webp", "page"):
        risk.append("No EXIF found")

    if status_cb is not None:
        try:
            status_cb("media", {"target": normalized, "kind": result_kind,
                                "risk": len(risk)})
        except Exception:
            pass

    return {
        "target": normalized,
        "kind": result_kind,
        "exif": exif,
        "gps": gps,
        "image": image_info,
        "images": images,
        "counts": counts,
        "links": links,
        "risk": risk,
        "sources_status": sources_status,
    }


# friendly alias
lookup_media = inspect_media


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render_text(result: dict) -> None:
    """Print a colored human-readable media-inspection report."""
    target = result.get("target", "")
    kind = result.get("kind", "")
    exif = result.get("exif") or {}
    gps = result.get("gps")
    image = result.get("image")
    images = result.get("images") or []
    counts = result.get("counts") or {}
    links = result.get("links") or []
    risk = result.get("risk") or []
    sources_status = result.get("sources_status") or {}

    header("SUMMARY")
    print(f"  Target: {c('bold')}{c('cyan')}{target}{c('reset')}")
    print(f"  Kind: {kind}")
    for line in risk:
        if "GPS" in line:
            col = c("red")
        elif "No EXIF" in line:
            col = c("green")
        else:
            col = c("yellow")
        print(f"  {col}⚠ {line}{c('reset')}")

    # EXIF
    header("EXIF")
    if exif:
        for key in ("Make", "Model", "DateTime", "DateTimeOriginal",
                    "Software", "Artist", "Copyright", "ImageDescription"):
            val = exif.get(key)
            if val is None or (isinstance(val, str) and not val.strip()):
                continue
            print(f"  {c('cyan')}{key}{c('reset')}: {c('dim')}{val}"
                  f"{c('reset')}")
    else:
        print(f"  {c('gray')}none{c('reset')}")

    # GPS
    if gps:
        header("GPS")
        lat, lon = gps.get("lat"), gps.get("lon")
        print(f"  {c('red')}{lat}, {lon}{c('reset')}")
        print(f"  {c('gray')}https://www.openstreetmap.org/?mlat={lat}"
              f"&mlon={lon}{c('reset')}")

    # SCANNED IMAGES
    if images:
        header("SCANNED IMAGES")
        print(f"  {c('yellow')}{counts.get('with_exif', 0)} with EXIF / "
              f"{counts.get('checked', 0)} checked{c('reset')}")
        for entry in images:
            mark = (f"{c('red')}⚠ exif" if entry.get("has_exif")
                    else f"{c('green')}✓ clean")
            print(f"  {mark}{c('reset')} {c('dim')}{entry.get('url')}"
                  f"{c('reset')}")

    # LINKS
    if links:
        header("LINKS")
        for link in links:
            print(f"  {c('gray')}{link.get('platform'):<10}{c('reset')} "
                  f"{link.get('url')} {c('dim')}{link.get('label')}"
                  f"{c('reset')}")

    if image and not images:
        header("IMAGE")
        print(f"  {c('dim')}{image.get('url')} ({image.get('kind')}, "
              f"{image.get('size')} bytes){c('reset')}")

    header("SOURCE STATUS")
    line = ", ".join(f"{k}: {v}" for k, v in sorted(sources_status.items()))
    print(f"  {c('gray')}{line or 'n/a'}{c('reset')}")
