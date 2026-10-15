"""Offline tests for nexora.social.media: pure EXIF extraction (JPEG/PNG),
kind detection, target validation and hermetic inspection."""
from __future__ import annotations

import struct
import zlib

import pytest

import nexora.social.media as media_mod
from conftest import FakeResponse


# --------------------------------------------------------------------------- #
# Hand-crafted minimal JPEG with EXIF (little-endian TIFF + GPS 1°30'0"N)
# --------------------------------------------------------------------------- #
def _tiff_entry(tag: int, typ: int, count: int, value: bytes) -> bytes:
    assert len(value) == 4
    return struct.pack("<HHI", tag, typ, count) + value


def _rational(num: int, den: int) -> bytes:
    return struct.pack("<II", num, den)


def build_minimal_jpeg(lat_ref: bytes = b"N", lon_ref: bytes = b"E") -> bytes:
    make = b"TestCam\x00"          # 8 bytes -> offset
    when = b"2024:01:02 03:04:05\x00"  # 20 bytes -> offset
    # TIFF layout: header(8) + IFD0 then values.
    # IFD0 = count(2) + 3*entry(12) + next(4) = 42 bytes
    ifd0_size = 2 + 3 * 12 + 4
    make_off = 8 + ifd0_size
    when_off = make_off + len(make)
    gps_ifd_off = when_off + len(when)

    ifd = struct.pack("<H", 3)
    ifd += _tiff_entry(0x010F, 2, len(make), struct.pack("<I", make_off))
    ifd += _tiff_entry(0x0132, 2, len(when), struct.pack("<I", when_off))
    ifd += _tiff_entry(0x8825, 4, 1, struct.pack("<I", gps_ifd_off))
    ifd += struct.pack("<I", 0)  # next-IFD pointer

    # GPS IFD: tags 1-4 (lat ref, lat, lon ref, lon)
    # GPS IFD = count(2) + 4*entry(12) + next(4) = 54 bytes
    gps_ifd_size = 2 + 4 * 12 + 4
    lat_off = gps_ifd_off + gps_ifd_size
    lon_off = lat_off + 24
    gps = struct.pack("<H", 4)
    gps += _tiff_entry(1, 2, 2, lat_ref + b"\x00\x00\x00")
    gps += _tiff_entry(2, 5, 3, struct.pack("<I", lat_off))
    gps += _tiff_entry(3, 2, 2, lon_ref + b"\x00\x00\x00")
    gps += _tiff_entry(4, 5, 3, struct.pack("<I", lon_off))
    gps += struct.pack("<I", 0)
    lat = _rational(1, 1) + _rational(30, 1) + _rational(0, 1)
    lon = _rational(0, 1) + _rational(0, 1) + _rational(0, 1)

    tiff = b"II" + struct.pack("<HI", 42, 8) + ifd + make + when + gps \
        + lat + lon
    payload = b"Exif\x00\x00" + tiff
    app1 = b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload
    return b"\xff\xd8" + app1 + b"\xff\xd9"


def test_extract_exif_minimal_jpeg():
    exif = media_mod.extract_exif(build_minimal_jpeg())
    assert exif["Make"] == "TestCam"
    assert exif["DateTime"] == "2024:01:02 03:04:05"
    gps = exif["gps"]
    assert gps["lat"] == pytest.approx(1.5, abs=1e-6)  # 1°30'0"N
    assert gps["lon"] == pytest.approx(0.0, abs=1e-6)


def test_extract_exif_jpeg_south_west_negates():
    blob = build_minimal_jpeg(lat_ref=b"S", lon_ref=b"W")
    exif = media_mod.extract_exif(blob)
    assert exif["gps"]["lat"] == pytest.approx(-1.5, abs=1e-6)
    assert exif["gps"]["lon"] == pytest.approx(0.0, abs=1e-6)


# --------------------------------------------------------------------------- #
# PNG tEXt
# --------------------------------------------------------------------------- #
def _png_chunk(typ: bytes, body: bytes) -> bytes:
    crc = zlib.crc32(typ + body) & 0xFFFFFFFF
    return struct.pack(">I", len(body)) + typ + body \
        + struct.pack(">I", crc)


def build_png_with_text() -> bytes:
    ihdr = _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    text = _png_chunk(b"tEXt", b"Software\x00Pixlr 2.0")
    author = _png_chunk(b"tEXt", b"Author\x00Jane Doe")
    iend = _png_chunk(b"IEND", b"")
    return b"\x89PNG\r\n\x1a\n" + ihdr + text + author + iend


def test_extract_exif_png_text():
    exif = media_mod.extract_exif(build_png_with_text())
    assert exif["Software"] == "Pixlr 2.0"
    assert exif["Author"] == "Jane Doe"


def test_extract_exif_png_ztxt_best_effort():
    ihdr = _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    compressed = zlib.compress(b"Comment from the field")
    ztxt = _png_chunk(b"zTXt", b"Comment\x00\x00" + compressed)
    iend = _png_chunk(b"IEND", b"")
    blob = b"\x89PNG\r\n\x1a\n" + ihdr + ztxt + iend
    exif = media_mod.extract_exif(blob)
    assert exif.get("Comment") == "Comment from the field"


def test_extract_exif_garbage_does_not_raise():
    assert media_mod.extract_exif(b"\x00\x01\x02 garbage not an image") == {}
    assert media_mod.extract_exif(b"\xff\xd8\xff\xe1\x00\x10garbage") == {}
    assert media_mod.extract_exif(b"") == {}
    assert media_mod.extract_exif(b"\x89PNG\r\n\x1a\n\x00\x00") == {}


def test_extract_exif_truncated_jpeg_is_safe():
    # JPEG header then an APP1 claiming more bytes than exist
    blob = b"\xff\xd8\xff\xe1\xff\xffExif\x00\x00II*\x00"
    assert isinstance(media_mod.extract_exif(blob), dict)


# --------------------------------------------------------------------------- #
# Kind detection
# --------------------------------------------------------------------------- #
def test_detect_kind_magic_bytes():
    assert media_mod._detect_kind(build_minimal_jpeg()) == "jpeg"
    assert media_mod._detect_kind(build_png_with_text()) == "png"
    assert media_mod._detect_kind(b"<html><body>hi</body></html>") == "page"
    assert media_mod._detect_kind(b"<!DOCTYPE html><html></html>") == "page"
    assert media_mod._detect_kind(b"RIFF\x00\x00\x00\x00WEBPVP8 ") == "webp"
    assert media_mod._detect_kind(b"%PDF-1.7 ...") == "pdf"
    assert media_mod._detect_kind(b"\x00\x01\x02\x03", "image/png") == "png"
    assert media_mod._detect_kind(b"\x00\x01\x02\x03") == "binary"


# --------------------------------------------------------------------------- #
# Target normalization / validation
# --------------------------------------------------------------------------- #
def test_normalize_target_errors():
    with pytest.raises(ValueError):
        media_mod._normalize_target("")
    with pytest.raises(ValueError):
        media_mod._normalize_target("handle:")
    with pytest.raises(ValueError):
        media_mod._normalize_target("handle:bad handle")
    with pytest.raises(ValueError):
        media_mod._normalize_target("ftp://example.com/a.jpg")


def test_normalize_target_prepends_https():
    kind, url = media_mod._normalize_target("example.com/photo.jpg")
    assert kind == "url"
    assert url == "https://example.com/photo.jpg"
    kind, url = media_mod._normalize_target("https://example.com/a.jpg")
    assert url == "https://example.com/a.jpg"
    kind, name = media_mod._normalize_target("handle:johndoe")
    assert kind == "handle"
    assert name == "johndoe"


# --------------------------------------------------------------------------- #
# Hermetic inspection
# --------------------------------------------------------------------------- #
def test_inspect_media_image_url(monkeypatch):
    jpeg = build_minimal_jpeg()

    def fake_http(url, **kwargs):
        return FakeResponse(200, content=jpeg, url=url,
                            headers={"Content-Type": "image/jpeg"})

    monkeypatch.setattr(media_mod, "http_get", fake_http)
    result = media_mod.inspect_media("https://example.com/pic.jpg")
    assert result["kind"] == "jpeg"
    assert result["exif"]["Make"] == "TestCam"
    assert result["gps"]["lat"] == pytest.approx(1.5, abs=1e-6)
    assert result["counts"] == {"checked": 1, "with_exif": 1, "with_gps": 1}
    assert any("GPS" in r for r in result["risk"])
    assert result["sources_status"]["target"] == "ok"


def test_inspect_media_page_scans_images(monkeypatch):
    page = ('<html><head><meta property="og:image" '
            'content="/hero.jpg"></head>'
            '<body><img src="https://cdn.example.com/a.jpg"></body></html>')
    jpeg = build_minimal_jpeg()

    def fake_http(url, **kwargs):
        if url == "https://example.com/page":
            return FakeResponse(200, text=page, url=url,
                                headers={"Content-Type": "text/html"})
        return FakeResponse(200, content=jpeg, url=url,
                            headers={"Content-Type": "image/jpeg"})

    monkeypatch.setattr(media_mod, "http_get", fake_http)
    result = media_mod.inspect_media("https://example.com/page")
    assert result["kind"] == "page"
    assert result["counts"]["checked"] == 2
    assert result["counts"]["with_exif"] == 2
    assert result["counts"]["with_gps"] == 2
    urls = {img["url"] for img in result["images"]}
    assert urls == {"https://example.com/hero.jpg",
                    "https://cdn.example.com/a.jpg"}
    assert any("GPS" in r for r in result["risk"])


def test_inspect_media_clean_image_reports_no_exif(monkeypatch):
    def fake_http(url, **kwargs):
        return FakeResponse(200, content=b"\x00\x01\x02\x03clean",
                            url=url, headers={"Content-Type": "image/png"})

    monkeypatch.setattr(media_mod, "http_get", fake_http)
    result = media_mod.inspect_media("https://example.com/clean.png")
    assert result["exif"] == {}
    assert "No EXIF found" in result["risk"]


def test_inspect_media_handle_target_crawls_bio_links(monkeypatch):
    linktree = ('<html><body>'
                '<a href="https://x.com/johndoe">X</a>'
                '<a href="https://github.com/johndoe">GitHub</a>'
                '<a href="https://www.instagram.com/johndoe/">IG</a>'
                '<a href="https://linktr.ee/johndoe">self</a>'
                '<a href="#top">anchor</a>'
                '<a href="javascript:void(0)">js</a>'
                '</body></html>')
    about = '<html><body><a href="https://t.me/johndoe">Telegram</a></body></html>'

    def fake_http(url, **kwargs):
        if url.startswith("https://linktr.ee/"):
            return FakeResponse(200, text=linktree, url=url)
        if url.startswith("https://about.me/"):
            return FakeResponse(200, text=about, url=url)
        return FakeResponse(404, url=url)

    monkeypatch.setattr(media_mod, "http_get", fake_http)
    result = media_mod.inspect_media("handle:johndoe")
    assert result["kind"] == "handle"
    platforms = {l["platform"] for l in result["links"]}
    assert platforms == {"x", "github", "instagram", "telegram"}
    # self-referencing / javascript / anchor links are excluded
    assert all("linktr.ee" not in l["url"] for l in result["links"])
    assert result["sources_status"]["linktree"] == "ok"
    assert result["sources_status"]["aboutme"] == "ok"


def test_lookup_media_is_alias():
    assert media_mod.lookup_media is media_mod.inspect_media


def test_render_text_smoke(monkeypatch, capsys):
    jpeg = build_minimal_jpeg()

    def fake_http(url, **kwargs):
        return FakeResponse(200, content=jpeg, url=url,
                            headers={"Content-Type": "image/jpeg"})

    monkeypatch.setattr(media_mod, "http_get", fake_http)
    result = media_mod.inspect_media("https://example.com/pic.jpg")
    media_mod.render_text(result)
    out = capsys.readouterr().out
    assert "TestCam" in out
    assert "openstreetmap.org" in out
