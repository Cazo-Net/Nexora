"""Phone number intelligence — fully offline, key-free.

Uses the optional ``phonenumbers`` library (Google's libphonenumber port) for
parsing, validation, formatting, carrier, geolocation and timezones. No
network requests are made at all. When the library is missing the lookup still
returns a degraded result (digits + country guess from the dial prefix) and
``render_text`` prints an install hint.
"""
from __future__ import annotations

import re
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

from .net import reset_circuit_breaker
from .output import c, header
from .platforms import platforms_for_phone

try:
    import phonenumbers
    from phonenumbers import (NumberParseException, PhoneNumberType,
                              PhoneNumberFormat, carrier as pn_carrier,
                              geocoder as pn_geocoder, timezone as pn_timezone)
    _PN: Optional[Any] = phonenumbers
except Exception:  # ImportError or broken optional dependency
    _PN = None

# --------------------------------------------------------------------------- #
# Static maps (offline fallback + country/type names)
# --------------------------------------------------------------------------- #
# Longest-prefix map used to guess a country from the + dial code when the
# phonenumbers library is unavailable.
_DIAL_PREFIXES: Dict[str, str] = {
    "+1": "United States/Canada (NANP)",
    "+44": "United Kingdom",
    "+49": "Germany",
    "+33": "France",
    "+81": "Japan",
    "+86": "China",
    "+91": "India",
    "+7": "Russia/Kazakhstan",
    "+55": "Brazil",
    "+61": "Australia",
    "+39": "Italy",
    "+34": "Spain",
    "+31": "Netherlands",
    "+46": "Sweden",
    "+47": "Norway",
    "+45": "Denmark",
    "+48": "Poland",
    "+90": "Turkey",
    "+971": "United Arab Emirates",
    "+966": "Saudi Arabia",
    "+972": "Israel",
    "+82": "South Korea",
    "+65": "Singapore",
    "+60": "Malaysia",
    "+62": "Indonesia",
    "+66": "Thailand",
    "+63": "Philippines",
    "+84": "Vietnam",
    "+234": "Nigeria",
    "+27": "South Africa",
    "+20": "Egypt",
    "+254": "Kenya",
    "+256": "Uganda",
    "+255": "Tanzania",
    "+353": "Ireland",
    "+351": "Portugal",
    "+41": "Switzerland",
    "+43": "Austria",
    "+32": "Belgium",
    "+30": "Greece",
    "+36": "Hungary",
    "+40": "Romania",
    "+380": "Ukraine",
    "+385": "Croatia",
    "+386": "Slovenia",
    "+420": "Czech Republic",
    "+371": "Latvia",
    "+370": "Lithuania",
    "+372": "Estonia",
    "+358": "Finland",
    "+352": "Luxembourg",
    "+354": "Iceland",
    "+995": "Georgia",
    "+374": "Armenia",
    "+994": "Azerbaijan",
    "+998": "Uzbekistan",
    "+992": "Tajikistan",
    "+996": "Kyrgyzstan",
    "+993": "Turkmenistan",
    "+886": "Taiwan",
    "+852": "Hong Kong",
    "+853": "Macao",
}
_PREFIX_ORDER: List[Tuple[str, str]] = sorted(_DIAL_PREFIXES.items(),
                                              key=lambda kv: -len(kv[0]))

# ISO-3166 alpha-2 -> country name (small built-in map; no pycountry dep)
_REGION_COUNTRY: Dict[str, str] = {
    "US": "United States", "GB": "United Kingdom", "DE": "Germany",
    "FR": "France", "JP": "Japan", "CN": "China", "IN": "India",
    "RU": "Russia", "BR": "Brazil", "AU": "Australia", "IT": "Italy",
    "ES": "Spain", "NL": "Netherlands", "SE": "Sweden", "NO": "Norway",
    "DK": "Denmark", "PL": "Poland", "TR": "Turkey", "AE": "United Arab Emirates",
    "SA": "Saudi Arabia", "IL": "Israel", "KR": "South Korea", "SG": "Singapore",
    "MY": "Malaysia", "ID": "Indonesia", "TH": "Thailand", "PH": "Philippines",
    "VN": "Vietnam", "NG": "Nigeria", "ZA": "South Africa", "EG": "Egypt",
    "KE": "Kenya", "UG": "Uganda", "TZ": "Tanzania", "IE": "Ireland",
    "PT": "Portugal", "CH": "Switzerland", "AT": "Austria", "BE": "Belgium",
    "GR": "Greece", "HU": "Hungary", "RO": "Romania", "UA": "Ukraine",
    "HR": "Croatia", "SI": "Slovenia", "CZ": "Czech Republic", "LV": "Latvia",
    "LT": "Lithuania", "EE": "Estonia", "FI": "Finland", "LU": "Luxembourg",
    "IS": "Iceland", "GE": "Georgia", "AM": "Armenia", "AZ": "Azerbaijan",
    "UZ": "Uzbekistan", "KZ": "Kazakhstan", "TJ": "Tajikistan",
    "KG": "Kyrgyzstan", "TM": "Turkmenistan", "TW": "Taiwan", "HK": "Hong Kong",
    "MO": "Macao", "CA": "Canada", "MX": "Mexico", "AR": "Argentina",
    "CL": "Chile", "CO": "Colombia", "PE": "Peru", "VE": "Venezuela",
    "PK": "Pakistan", "BD": "Bangladesh", "LK": "Sri Lanka", "NP": "Nepal",
    "MM": "Myanmar", "KH": "Cambodia", "LA": "Laos", "BH": "Bahrain",
    "QA": "Qatar", "KW": "Kuwait", "OM": "Oman", "JO": "Jordan",
    "LB": "Lebanon", "IQ": "Iraq", "IR": "Iran", "SY": "Syria",
    "YE": "Yemen", "AF": "Afghanistan", "MN": "Mongolia", "KP": "North Korea",
}

_TYPE_NAMES: Dict[int, str] = {}
if _PN is not None:
    _TYPE_NAMES = {
        PhoneNumberType.FIXED_LINE: "fixed_line",
        PhoneNumberType.MOBILE: "mobile",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
        PhoneNumberType.TOLL_FREE: "toll_free",
        PhoneNumberType.PREMIUM_RATE: "premium_rate",
        PhoneNumberType.SHARED_COST: "shared_cost",
        PhoneNumberType.VOIP: "voip",
        PhoneNumberType.PERSONAL_NUMBER: "personal_number",
        PhoneNumberType.PAGER: "pager",
        PhoneNumberType.UAN: "uan",
        PhoneNumberType.VOICEMAIL: "voicemail",
    }


def _notify(status_cb: Optional[Callable[..., None]], source: str,
            info: Dict[str, Any]) -> None:
    """Invoke the optional progress callback; never let it break a scan."""
    if status_cb is None:
        return
    try:
        status_cb(source, info)
    except Exception:
        pass


def _safe_char(uni: str, fallback: str) -> str:
    """A unicode glyph that degrades to ASCII on consoles that can't encode it."""
    try:
        uni.encode(sys.stdout.encoding or "ascii")
        return uni
    except Exception:
        return fallback


def _guess_country(raw: str) -> Optional[str]:
    """Best-effort country guess from the + / 00 dial prefix."""
    s = (raw or "").strip()
    if not s:
        return None
    if s.startswith("00"):
        s = "+" + s[2:]
    if not s.startswith("+"):
        return None
    for prefix, name in _PREFIX_ORDER:
        if s.startswith(prefix):
            return name
    return None


def _attach_platforms(target: str, e164: Optional[str],
                      national: Optional[str],
                      sources_status: Dict[str, str],
                      status_cb: Optional[Callable[..., None]]) -> Dict[str, Any]:
    """Connected-platform map (deep links, dorks) — never raises."""
    try:
        plat = platforms_for_phone(target, e164=e164, national=national,
                                   status_cb=status_cb)
    except ValueError:
        plat = {"platforms": [], "dorks": [], "handle_candidates": [],
                "sources_status": {"platform-map": "skipped: not number-ish"}}
    sources_status.update(plat.get("sources_status") or {})
    return plat


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def lookup_phone(phone: str, *, status_cb: Optional[Callable[..., None]] = None) -> Dict[str, Any]:
    """Offline phone number intelligence (parsing, validation, carrier, region).

    Requires the optional ``phonenumbers`` package for full results; without it
    a degraded result is returned (no exception): extracted digits plus a
    country guess from the dial prefix and ``requires`` install instructions.
    With the library, raises ValueError only when the number fails to parse.
    Fully offline, key-free — no network requests are ever made.
    """
    reset_circuit_breaker()
    target = str(phone or "").strip()
    sources_status: Dict[str, str] = {}

    if _PN is None:
        digits = re.sub(r"\D", "", target)
        guess = _guess_country(target)
        sources_status["parser"] = "skipped: phonenumbers not installed"
        _notify(status_cb, "parser", {"status": sources_status["parser"]})
        plat = _attach_platforms(target, None, None, sources_status, status_cb)
        return {
            "phone": target,
            "e164": None,
            "international": None,
            "national": None,
            "rfc3966": None,
            "valid": False,
            "possible": False,
            "region": None,
            "country": None,
            "country_code": None,
            "national_number": None,
            "number_type": None,
            "is_mobile": False,
            "carrier": None,
            "location": None,
            "timezones": [],
            "requires": "pip install phonenumbers",
            "digits": digits,
            "country_guess": guess,
            "connected_platforms": plat.get("platforms") or [],
            "dorks": plat.get("dorks") or [],
            "handle_candidates": plat.get("handle_candidates") or [],
            "sources_status": sources_status,
        }

    try:
        n = phonenumbers.parse(target, None)
    except NumberParseException as e:
        raise ValueError(f"invalid phone number: {phone}") from e

    try:
        e164 = phonenumbers.format_number(n, PhoneNumberFormat.E164)
        international = phonenumbers.format_number(n, PhoneNumberFormat.INTERNATIONAL)
        national = phonenumbers.format_number(n, PhoneNumberFormat.NATIONAL)
        rfc3966 = phonenumbers.format_number(n, PhoneNumberFormat.RFC3966)
        valid = bool(phonenumbers.is_valid_number(n))
        possible = bool(phonenumbers.is_possible_number(n))
        region = phonenumbers.region_code_for_number(n)
        number_type = phonenumbers.number_type(n)
        type_name = _TYPE_NAMES.get(number_type, "unknown")
        # FIXED_LINE_OR_MOBILE numbers (e.g. the whole NANP) can be mobiles
        is_mobile = number_type in (PhoneNumberType.MOBILE,
                                    PhoneNumberType.FIXED_LINE_OR_MOBILE)
        carrier = pn_carrier.name_for_number(n, "en") or None
        location = pn_geocoder.description_for_number(n, "en") or None
        try:
            timezones: List[str] = list(pn_timezone.time_zones_for_number(n))
        except Exception:
            timezones = []
        sources_status["parser"] = "ok"
        _notify(status_cb, "parser", {"status": "ok", "detail": e164})
        plat = _attach_platforms(target, e164, national, sources_status,
                                 status_cb)
        return {
            "phone": target,
            "e164": e164,
            "international": international,
            "national": national,
            "rfc3966": rfc3966,
            "valid": valid,
            "possible": possible,
            "region": region,
            "country": _REGION_COUNTRY.get(region, "Unknown") if region else "Unknown",
            "country_code": getattr(n, "country_code", None),
            "national_number": getattr(n, "national_number", None),
            "number_type": type_name,
            "is_mobile": is_mobile,
            "carrier": carrier,
            "location": location,
            "timezones": timezones,
            "requires": None,
            "connected_platforms": plat.get("platforms") or [],
            "dorks": plat.get("dorks") or [],
            "handle_candidates": plat.get("handle_candidates") or [],
            "sources_status": sources_status,
        }
    except ValueError:
        raise
    except Exception as e:  # library internals must never crash the CLI
        sources_status["parser"] = f"error: {type(e).__name__}"
        _notify(status_cb, "parser", {"status": sources_status["parser"]})
        plat = _attach_platforms(target, None, None, sources_status, status_cb)
        return {
            "phone": target,
            "e164": None, "international": None, "national": None,
            "rfc3966": None, "valid": False, "possible": False,
            "region": None, "country": None, "country_code": None,
            "national_number": None, "number_type": None, "is_mobile": False,
            "carrier": None, "location": None, "timezones": [],
            "requires": None,
            "connected_platforms": plat.get("platforms") or [],
            "dorks": plat.get("dorks") or [],
            "handle_candidates": plat.get("handle_candidates") or [],
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


def _type_color(type_name: Optional[str]) -> str:
    if type_name in ("mobile", "fixed_line_or_mobile"):
        return c("green")
    if type_name == "fixed_line":
        return c("cyan")
    if type_name == "toll_free":
        return c("yellow")
    if type_name in ("premium_rate", "shared_cost"):
        return c("red")
    return c("gray")


def render_text(result: Dict[str, Any]) -> None:
    """Print a colored human-readable phone number report."""
    header("SUMMARY")
    number = result.get("international") or result.get("phone") or "?"
    print(f"  Number        {c('bold')}{number}{c('reset')}")

    if result.get("requires"):
        # degraded result: phonenumbers was not installed at lookup time
        print(f"  {c('red')}phonenumbers not installed — "
              f"pip install phonenumbers[phone]{c('reset')}")
        print(f"  Digits        {result.get('digits') or '-'}")
        guess = result.get("country_guess")
        print(f"  Country guess {guess if guess else c('gray') + 'Unknown' + c('reset')}"
              f"  {c('dim')}(from + dial prefix){c('reset')}")
    else:
        e164 = result.get("e164")
        print(f"  E.164         {e164 or '-'}")
        valid = bool(result.get("valid"))
        if valid:
            v_col, v_mark = c("green"), _safe_char("✓", "[ok]")
        else:
            v_col, v_mark = c("red"), _safe_char("✗", "[X]")
        print(f"  Valid         {v_col}{v_mark}{' valid' if valid else ' invalid'}{c('reset')}")
        print(f"  Possible      {'yes' if result.get('possible') else 'no'}")
        region = result.get("region")
        country = result.get("country")
        print(f"  Region        {region or '-'}"
              + (f" ({country})" if country and country != "Unknown" else ""))
        type_name = result.get("number_type")
        print(f"  Type          {_type_color(type_name)}{type_name or '-'}{c('reset')}")
        carrier = result.get("carrier")
        carrier_txt = carrier if carrier else c("gray") + "unknown" + c("reset")
        print(f"  Carrier       {carrier_txt}")
        print(f"  Location      {result.get('location') or '-'}")
        timezones = result.get("timezones") or []
        print(f"  Timezones     {', '.join(timezones) if timezones else '-'}")

    # -------------------------------------------------- CONNECTED PLATFORMS
    header("CONNECTED PLATFORMS")
    plats = result.get("connected_platforms") or []
    if not plats:
        print(f"  {c('gray')}(no platform map for this number){c('reset')}")
    else:
        for p in plats:
            if not isinstance(p, dict):
                continue
            print(f"  {c('cyan')}{str(p.get('platform') or '?'):<10}{c('reset')}"
                  f"{str(p.get('method') or ''):<12} {c('gray')}"
                  f"{p.get('url') or '-'}{c('reset')}")
            if p.get("note"):
                print(f"    {c('dim')}{p['note']}{c('reset')}")

    # --------------------------------------------------------- SEARCH DORKS
    header("SEARCH DORKS")
    dorks = result.get("dorks") or []
    if dorks:
        for d in dorks:
            print(f"  {c('gray')}{d}{c('reset')}")
    else:
        print(f"  {c('gray')}(none){c('reset')}")

    # ---------------------------------------------------- HANDLE CANDIDATES
    cands = result.get("handle_candidates") or []
    if cands:
        header("HANDLE CANDIDATES")
        print(f"  {c('gray')}{', '.join(cands)}"
              f"  (heuristic — try as username){c('reset')}")

    header("SOURCE STATUS")
    statuses = result.get("sources_status") or {}
    for name in sorted(statuses):
        value = str(statuses[name])
        print(f"  {name:<18}{_status_color(value)}{value}{c('reset')}")
