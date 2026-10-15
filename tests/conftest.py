"""Shared fixtures for the Nexora test suite.

* ``FakeResponse``   -- minimal stand-in for ``requests.Response``
* ``fake_dns``       -- programmable replacement for ``dns.resolver.resolve``
* ``no_network``     -- autouse guard: any real network access fails the test
* ``disable_colors`` -- autouse: every test starts with ANSI colors disabled
* ``reset_circuit_breaker`` -- autouse: no dead-host leakage between tests
"""
from __future__ import annotations

import json as _json
import socket
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

# Make ``nexora`` (and the sibling ``osint`` engine module) importable no
# matter where pytest is invoked from.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    import dns.resolver as dns_resolver  # type: ignore
except Exception:  # pragma: no cover -- dnspython is a hard dependency
    dns_resolver = None  # type: ignore

import nexora.net as nexora_net
import nexora.output as nexora_output


# --------------------------------------------------------------------------- #
# Fake HTTP response
# --------------------------------------------------------------------------- #
class FakeResponse:
    """Just enough of ``requests.Response`` for Nexora's collectors."""

    def __init__(
        self,
        status_code: int = 200,
        text: str = "",
        json_data: Any = None,
        headers: Optional[Dict[str, str]] = None,
        url: str = "",
        content: Optional[bytes] = None,
    ) -> None:
        self.status_code = status_code
        self.text = text
        self._json = json_data
        self.headers = dict(headers or {})
        self.url = url
        self.content = content if content is not None else text.encode("utf-8")
        self.history: List[Any] = []
        self.closed = False

    def json(self) -> Any:
        if self._json is not None:
            return self._json
        return _json.loads(self.text)

    def close(self) -> None:
        self.closed = True

    def iter_content(self, chunk_size: int = 1):
        data = self.content
        for start in range(0, len(data), chunk_size):
            yield data[start:start + chunk_size]

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(
                "HTTP %s for %s" % (self.status_code, self.url or "?"))


# --------------------------------------------------------------------------- #
# Fake DNS
# --------------------------------------------------------------------------- #
class _Rdata:
    """Minimal rdata stand-in covering what Nexora's DNS helpers read."""

    def __init__(self, value: Any, rdtype: str) -> None:
        self.rdtype = rdtype
        if rdtype == "MX" and isinstance(value, (tuple, list)):
            self.preference = int(value[0])
            self.value = str(value[1])
        else:
            self.preference = 10
            self.value = str(value)
        self.strings = [self.value]
        self.exchange = self.value
        self.target = self.value

    def __str__(self) -> str:
        return self.value

    def to_text(self) -> str:
        return self.value


class FakeDNS:
    """Programmable stand-in for ``dns.resolver.resolve``.

    Unconfigured names raise ``NoAnswer`` (the common real-world case),
    which every Nexora DNS helper translates into ``[]``.
    """

    def __init__(self) -> None:
        self.records: Dict[tuple, tuple] = {}
        self.calls: List[tuple] = []

    def set(self, name: str, rdtype: str, *values: Any) -> None:
        """Register canned rdata for ``name``/``rdtype``.

        MX values may be ``(preference, exchange)`` tuples.
        """
        key = (str(name).lower().rstrip("."), str(rdtype).upper())
        self.records[key] = tuple(values)

    def clear(self) -> None:
        self.records.clear()

    def resolve(self, name: str, rdtype: str = "A", *args: Any, **kwargs: Any):
        rdtype = str(rdtype).upper()
        self.calls.append((str(name), rdtype))
        key = (str(name).lower().rstrip("."), rdtype)
        values = self.records.get(key)
        if not values:
            if dns_resolver is not None:
                raise dns_resolver.NoAnswer()
            raise RuntimeError("no fake DNS record for %s %s" % key)
        return [_Rdata(v, rdtype) for v in values]


# --------------------------------------------------------------------------- #
# Autouse guards
# --------------------------------------------------------------------------- #
@pytest.fixture(autouse=True)
def no_network(request, monkeypatch):
    """Fail any test that touches the real network.

    Patches ``requests`` at the ``Session.request`` level, plus the socket
    and DNS escape hatches. Tests marked ``@pytest.mark.network`` skip the
    guard entirely.
    """
    if request.node.get_closest_marker("network"):
        yield
        return

    attempts: List[str] = []

    def _blocked_request(self, method, url, *args, **kwargs):
        attempts.append("%s %s" % (method, url))
        raise AssertionError("network access in test")

    def _blocked_getaddrinfo(*args, **kwargs):
        attempts.append("getaddrinfo %r" % (args[:1],))
        raise OSError("network access in test")

    def _blocked_gethostbyaddr(*args, **kwargs):
        # Blocked on purpose so reverse-DNS collectors degrade hermetically;
        # not recorded as a violation (tests rely on this guard).
        raise socket.herror("network access in test")

    def _blocked_dns_resolve(*args, **kwargs):
        attempts.append("dns %r" % (args[:2],))
        if dns_resolver is not None:
            raise dns_resolver.NoAnswer()
        raise AssertionError("network access in test")

    monkeypatch.setattr("requests.sessions.Session.request", _blocked_request)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked_getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyaddr", _blocked_gethostbyaddr)
    if dns_resolver is not None:
        monkeypatch.setattr(dns_resolver, "resolve", _blocked_dns_resolve)

    yield

    if attempts:
        pytest.fail("network access in test: " + "; ".join(attempts[:5]))


@pytest.fixture(autouse=True)
def disable_colors():
    nexora_output.enable_colors(False)
    yield
    nexora_output.enable_colors(False)


@pytest.fixture(autouse=True)
def reset_circuit_breaker():
    nexora_net.reset_circuit_breaker()
    yield
    nexora_net.reset_circuit_breaker()


# --------------------------------------------------------------------------- #
# Fake DNS fixture
# --------------------------------------------------------------------------- #
@pytest.fixture
def fake_dns(monkeypatch, no_network):
    """Install a programmable ``dns.resolver.resolve`` for one test."""
    resolver = FakeDNS()
    if dns_resolver is not None:
        monkeypatch.setattr(dns_resolver, "resolve", resolver.resolve)
    return resolver
