"""Tests for the SSRF-based internal port scanner (v0.6).

Tier-0: unit tests for probe_url, _classify, _match_banner (pure functions).
Tier-1: respx-mocked scan_ports exercising the full async probe loop.

All tests are hermetic: pytest-socket autouse fixture blocks real egress.
"""

from __future__ import annotations

import asyncio

import pytest
import respx
from httpx import Response
from scan_primitives import Scope

from wraith.engine import Target
from wraith.portscan import (
    DEFAULT_PORTS,
    SERVICE_BANNERS,
    PortProbe,
    PortState,
    _classify,
    _match_banner,
    probe_url,
    scan_ports,
)


# --------------------------------------------------------------------------- #
# Tier-0 — pure function unit tests
# --------------------------------------------------------------------------- #

def test_probe_url_basic():
    assert probe_url("127.0.0.1", 80) == "http://127.0.0.1:80/"
    assert probe_url("10.0.0.1", 6379) == "http://10.0.0.1:6379/"
    assert probe_url("192.168.1.1", 443) == "http://192.168.1.1:443/"


def test_probe_url_all_default_ports():
    for port in DEFAULT_PORTS:
        url = probe_url("127.0.0.1", port)
        assert url == f"http://127.0.0.1:{port}/"


def test_match_banner_redis():
    assert _match_banner("redis_version:7.0.1\nredis_mode:standalone") == "redis_version"


def test_match_banner_elasticsearch():
    assert _match_banner('{"cluster_name": "my-cluster", "status": "green"}') == "cluster_name"


def test_match_banner_ssh():
    assert _match_banner("SSH-2.0-OpenSSH_8.9") == "SSH-2.0-"


def test_match_banner_http_body():
    # <html appears earlier in SERVICE_BANNERS than <!DOCTYPE
    assert _match_banner("<!DOCTYPE html><html><body>Welcome</body></html>") == "<html"


def test_match_banner_none():
    assert _match_banner("") is None
    assert _match_banner("502 Bad Gateway") is None
    assert _match_banner("connection refused") is None


def test_match_banner_case_insensitive():
    assert _match_banner("REDIS_VERSION:7.0") == "redis_version"


@pytest.mark.parametrize("banner", SERVICE_BANNERS)
def test_service_banners_are_strings(banner):
    assert isinstance(banner, str) and banner


def test_classify_open_via_banner():
    state = _classify(0.1, 5.0, 200, "redis_version", 0.05)
    assert state is PortState.OPEN


def test_classify_filtered_via_timeout():
    # elapsed >= 85% of timeout
    state = _classify(4.3, 5.0, None, None, 0.05)
    assert state is PortState.FILTERED


def test_classify_closed_fast_5xx():
    # Fast 5xx response without banner → closed
    state = _classify(0.05, 5.0, 502, None, 0.06)
    assert state is PortState.CLOSED


def test_classify_open_2xx_no_banner():
    # Non-error status without banner → OPEN (HTTP service)
    state = _classify(0.3, 5.0, 200, None, 0.06)
    assert state is PortState.OPEN


def test_classify_unknown_slow_5xx():
    # Slow-ish 5xx response, no banner — ambiguous
    state = _classify(1.5, 5.0, 503, None, 0.06)
    assert state is PortState.UNKNOWN


# --------------------------------------------------------------------------- #
# Tier-1 — respx-mocked scan_ports
# --------------------------------------------------------------------------- #

def _make_scope(*hosts: str) -> Scope:
    from scan_primitives import Scope
    return Scope(list(hosts))


@respx.mock
def test_scan_ports_open_banner(respx_mock):
    """Port 6379 returns a Redis banner in the SSRF echo → OPEN, medium finding."""
    target = Target.from_url(
        "http://app.example.com/proxy?url=FUZZ",
        marker="FUZZ",
    )
    scope = _make_scope("app.example.com")

    # Calibration probe (port 65535) → fast 502
    respx_mock.get(
        "http://app.example.com/proxy",
        params={"url": "http://127.0.0.1:65535/"},
    ).mock(return_value=Response(502, text=""))

    # Port 6379 → 200 with Redis banner
    respx_mock.get(
        "http://app.example.com/proxy",
        params={"url": "http://127.0.0.1:6379/"},
    ).mock(return_value=Response(200, text="redis_version:7.2.1\nredis_mode:standalone\n"))

    findings = asyncio.run(
        scan_ports(target, scope, host="127.0.0.1", ports=(6379,), timeout=5.0)
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "medium"
    assert f.confidence == "high"
    assert "6379" in f.title
    assert f.evidence["banner_matched"] == "redis_version"
    assert f.evidence["state"] == "open"


@respx.mock
def test_scan_ports_closed_drops_finding(respx_mock):
    """Port that returns a fast 502 (closed) should not appear in findings."""
    target = Target.from_url(
        "http://app.example.com/proxy?url=FUZZ",
        marker="FUZZ",
    )
    scope = _make_scope("app.example.com")

    # Calibration probe
    respx_mock.get(
        "http://app.example.com/proxy",
        params={"url": "http://127.0.0.1:65535/"},
    ).mock(return_value=Response(502, text=""))

    # Port 22 → fast 502, no banner
    respx_mock.get(
        "http://app.example.com/proxy",
        params={"url": "http://127.0.0.1:22/"},
    ).mock(return_value=Response(502, text=""))

    findings = asyncio.run(
        scan_ports(target, scope, host="127.0.0.1", ports=(22,), timeout=5.0)
    )
    assert findings == []


@respx.mock
def test_scan_ports_multiple_ports(respx_mock):
    """Mix: one open (banner), one closed, one unknown (200, no banner)."""
    target = Target.from_url(
        "http://app.example.com/proxy?url=FUZZ",
        marker="FUZZ",
    )
    scope = _make_scope("app.example.com")

    # Calibration
    respx_mock.get(
        "http://app.example.com/proxy",
        params={"url": "http://127.0.0.1:65535/"},
    ).mock(return_value=Response(502, text=""))

    # Port 6379 → Redis banner
    respx_mock.get(
        "http://app.example.com/proxy",
        params={"url": "http://127.0.0.1:6379/"},
    ).mock(return_value=Response(200, text="redis_version:7.2.0\n"))

    # Port 22 → closed (fast 502)
    respx_mock.get(
        "http://app.example.com/proxy",
        params={"url": "http://127.0.0.1:22/"},
    ).mock(return_value=Response(502, text=""))

    # Port 8080 → 200 with HTML (OPEN via status code)
    respx_mock.get(
        "http://app.example.com/proxy",
        params={"url": "http://127.0.0.1:8080/"},
    ).mock(return_value=Response(200, text="<html><body>internal app</body></html>"))

    findings = asyncio.run(
        scan_ports(target, scope, host="127.0.0.1", ports=(6379, 22, 8080), timeout=5.0)
    )

    ports_found = {f.evidence["port"] for f in findings}
    assert 6379 in ports_found
    assert 8080 in ports_found
    assert 22 not in ports_found


@respx.mock
def test_scan_ports_marker_injection(respx_mock):
    """The FUZZ marker is correctly replaced by the probe URL."""
    target = Target.from_url(
        "http://app.example.com/proxy?url=FUZZ",
        marker="FUZZ",
    )
    scope = _make_scope("app.example.com")

    called_urls = []

    def capture(request, *args, **kwargs):
        called_urls.append(str(request.url))
        return Response(502, text="")

    respx_mock.get("http://app.example.com/proxy").mock(side_effect=capture)

    asyncio.run(
        scan_ports(target, scope, host="10.0.0.1", ports=(80,), timeout=5.0)
    )
    assert any("10.0.0.1%3A80" in u or "10.0.0.1:80" in u for u in called_urls)


@respx.mock
def test_scan_ports_empty_ports_returns_empty(respx_mock):
    """Empty port list yields no findings (calibration probe still fires)."""
    target = Target.from_url(
        "http://app.example.com/proxy?url=FUZZ",
        marker="FUZZ",
    )
    scope = _make_scope("app.example.com")

    respx_mock.get("http://app.example.com/proxy").mock(return_value=Response(502, text=""))

    findings = asyncio.run(
        scan_ports(target, scope, host="127.0.0.1", ports=(), timeout=5.0)
    )
    assert findings == []


# --------------------------------------------------------------------------- #
# CLI integration — _parse_ports
# --------------------------------------------------------------------------- #

def test_parse_ports_default():
    from wraith.cli import _parse_ports
    assert _parse_ports("default") == DEFAULT_PORTS


def test_parse_ports_csv():
    from wraith.cli import _parse_ports
    assert _parse_ports("80,443,8080") == (80, 443, 8080)


def test_parse_ports_range():
    from wraith.cli import _parse_ports
    assert _parse_ports("8080-8083") == (8080, 8081, 8082, 8083)
