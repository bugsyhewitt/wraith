"""Tests for the MCP / AI-infra SSRF catalog (V0.1-CRITERIA.md #6).

Pins the curated 5-entry catalog, the version gate, target construction for both
query and JSON-body sinks, and an end-to-end OOB-confirmed MCP scan.
"""

from __future__ import annotations

import asyncio
import re

import pytest
from scan_primitives import Scope
from werkzeug.wrappers import Response as WZResponse

import httpx

from wraith.engine import Target, run_scan
from wraith.mcp import (
    MCP_CATALOG,
    MCP_DISCOVERY_PATHS,
    MCP_SERVER_SIGNATURES,
    applicable,
    detect_mcp_server_response,
    mcp_ssrf_urls,
    mcp_target,
    scan_mcp,
    version_affected,
)
from wraith.oob import LocalCollaborator


@pytest.fixture(scope="session")
def httpserver_listen_address():
    return ("127.0.0.1", 0)


@pytest.fixture
def local_collab():
    collab = LocalCollaborator(domain="oob.local")
    try:
        yield collab
    finally:
        collab.close()


# --------------------------------------------------------------------------- #
# Catalog shape (exactly five, cited)
# --------------------------------------------------------------------------- #

def test_catalog_has_exactly_five_signatures():
    assert len(MCP_CATALOG) == 5
    ids = {s.id for s in MCP_CATALOG}
    assert ids == {
        "fetch-mcp",
        "markitdown-mcp",
        "mcp-atlassian",
        "litellm-rag-ingest",
        "langchain-recursiveurlloader",
    }


def test_every_signature_is_cited_and_gated():
    for sig in MCP_CATALOG:
        assert sig.references, f"{sig.id} has no references"
        assert sig.param and sig.param_in in {"query", "json"}
        assert sig.affected  # a version gate string (may be "*")


def test_named_cves_present():
    all_cves = {c for s in MCP_CATALOG for c in s.cve}
    assert {"CVE-2025-65513", "CVE-2026-27826", "CVE-2026-26019", "CVE-2026-27795"} <= all_cves


# --------------------------------------------------------------------------- #
# Version gate
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "version,spec,expected",
    [
        ("0.6.2", "<0.6.3", True),
        ("0.6.3", "<0.6.3", False),
        ("0.7.0", "<0.6.3", False),
        ("1.52.9", "<1.53.0", True),
        ("1.53.0", "<1.53.0", False),
        ("2.0.0", "*", True),
        (None, "<0.6.3", True),  # unknown version -> cannot rule out -> affected
        ("0.2.0", ">=0.1,<0.3", True),
        ("0.3.0", ">=0.1,<0.3", False),
    ],
)
def test_version_affected(version, spec, expected):
    assert version_affected(version, spec) is expected


def test_applicable_filters_by_version():
    # Fetch MCP is patched in 0.6.3; at 0.6.3 it drops out, but "*"-gated
    # MarkItDown always stays.
    at_063 = {s.id for s in applicable("0.6.3")}
    assert "fetch-mcp" not in at_063
    assert "markitdown-mcp" in at_063
    # No version -> all five apply.
    assert len(applicable(None)) == 5


# --------------------------------------------------------------------------- #
# Target construction (query vs JSON body)
# --------------------------------------------------------------------------- #

def test_mcp_target_query_injection():
    sig = next(s for s in MCP_CATALOG if s.id == "fetch-mcp")
    target = mcp_target(sig, "http://mcp.example.com")
    assert target.injection.vector() == "query:url"
    _, url, _, _ = target.build_request("http://169.254.169.254/")
    assert url.startswith("http://mcp.example.com/fetch?")
    assert "url=http%3A%2F%2F169.254.169.254%2F" in url


def test_mcp_target_json_body_injection():
    sig = next(s for s in MCP_CATALOG if s.id == "litellm-rag-ingest")
    target = mcp_target(sig, "http://mcp.example.com/")
    assert target.method == "POST"
    assert target.headers["Content-Type"] == "application/json"
    _, url, _, body = target.build_request("http://169.254.169.254/")
    assert url == "http://mcp.example.com/v1/rag/ingest"
    assert body == '{"file_url": "http://169.254.169.254/"}'


# --------------------------------------------------------------------------- #
# End-to-end: an OOB-confirmed MCP SSRF finding, tagged with the CVE
# --------------------------------------------------------------------------- #

def test_scan_mcp_confirms_fetch_mcp_via_oob(local_collab, httpserver):
    def handler(request):
        injected = request.args.get("url", "")
        m = re.search(r"wr[0-9a-f]{12}", injected)
        if m:
            try:
                httpx.get(local_collab.http_url_for(m.group(0)), timeout=2)
            except Exception:
                pass
        return WZResponse("ok")

    httpserver.expect_request("/fetch").respond_with_handler(handler)
    base = httpserver.url_for("/").rstrip("/")
    scope = Scope.from_entries(["127.0.0.1"])

    # Pin the version so only the query-based /fetch signatures fire against the
    # /fetch endpoint (keeps the assertion focused + the test fast).
    findings = asyncio.run(
        scan_mcp(base, scope, collaborator=local_collab, version="0.6.2", oob_timeout=3.0)
    )

    confirmed = [f for f in findings if f.is_confirmed()]
    assert confirmed, "no OOB-confirmed MCP finding"
    tagged = [f for f in confirmed if f.evidence.get("mcp_signature") == "fetch-mcp"]
    assert tagged, f"no fetch-mcp finding; got {[f.evidence.get('mcp_signature') for f in confirmed]}"
    f = tagged[0]
    assert "CVE-2025-65513" in f.evidence.get("cve", [])
    assert any("CVE-2025-65513" in r for r in f.references)
    assert f.oob_proof.startswith("http:")


# --------------------------------------------------------------------------- #
# MCP internal-SSRF discovery (v0.3)
# --------------------------------------------------------------------------- #

class TestMcpDiscoveryPaths:
    def test_discovery_paths_are_nonempty(self):
        assert MCP_DISCOVERY_PATHS
        assert all(p.startswith("/") for p in MCP_DISCOVERY_PATHS)

    def test_known_paths_present(self):
        paths = set(MCP_DISCOVERY_PATHS)
        assert "/mcp" in paths
        assert "/__mcp" in paths
        assert "/.well-known/mcp.json" in paths


class TestDetectMcpServerResponse:
    def test_returns_true_for_two_matching_signatures(self):
        body = '{"protocolVersion":"2024-11-05","capabilities":{"tools":{}}}'
        assert detect_mcp_server_response(body) is True

    def test_returns_false_for_one_matching_signature(self):
        body = '{"protocolVersion":"2024-11-05"}'
        assert detect_mcp_server_response(body) is False

    def test_returns_false_for_unrelated_json(self):
        assert detect_mcp_server_response('{"status":"ok","message":"hello"}') is False

    def test_returns_false_for_empty(self):
        assert detect_mcp_server_response("") is False

    @pytest.mark.parametrize(
        "body",
        [
            # MCP initialize response shape
            '{"protocolVersion":"2024-11-05","serverInfo":{"name":"test"}}',
            # MCP tools-list response shape
            '{"jsonrpc":"2.0","result":{"tools":[],"capabilities":{}}}',
            # MCP well-known metadata file
            '{"name":"my-mcp-server","capabilities":{"tools":{},"resources":{}}}',
        ],
    )
    def test_recognises_real_mcp_response_shapes(self, body):
        assert detect_mcp_server_response(body) is True

    def test_r5_no_exception_on_binary_garbage(self):
        # R5: response bytes are data -- must not raise even on non-UTF garbage.
        garbage = "\x00\xff\xfe protocolVersion capabilities \x00"
        # May be True or False but must not raise.
        result = detect_mcp_server_response(garbage)
        assert isinstance(result, bool)


class TestMcpSsrfUrls:
    def test_returns_one_entry_per_discovery_path(self):
        urls = mcp_ssrf_urls()
        assert len(urls) == len(MCP_DISCOVERY_PATHS)

    def test_default_host_is_loopback(self):
        urls = mcp_ssrf_urls()
        assert all("127.0.0.1" in u for _, u in urls)

    def test_custom_host_and_port_embedded(self):
        urls = mcp_ssrf_urls("10.0.0.5", 8080)
        assert all("10.0.0.5:8080" in u for _, u in urls)

    def test_discovery_paths_appear_in_urls(self):
        urls = mcp_ssrf_urls()
        url_strings = {u for _, u in urls}
        assert any("/mcp" in u for u in url_strings)
        assert any("/.well-known/mcp.json" in u for u in url_strings)

    def test_labels_are_unique(self):
        labels = [label for label, _ in mcp_ssrf_urls()]
        assert len(labels) == len(set(labels))


class TestRunScanMcpDiscovery:
    """Tier-2 (loopback httpserver) test: run_scan with mcp_discovery=True detects
    an echoed MCP server response and emits a finding."""

    def test_mcp_server_reached_via_ssrf_emits_finding(self, httpserver):
        """An SSRF-proxying target that echoes MCP server responses produces a finding."""
        from werkzeug.wrappers import Response as WZResponse

        mcp_body = (
            '{"protocolVersion":"2024-11-05","serverInfo":{"name":"internal-mcp"},'
            '"capabilities":{"tools":{},"resources":{}}}'
        )

        def proxy_handler(request):
            injected = request.args.get("url", "")
            if "/mcp" in injected:
                return WZResponse(mcp_body, content_type="application/json")
            return WZResponse("nothing", content_type="text/plain")

        httpserver.expect_request("/proxy").respond_with_handler(proxy_handler)
        base = httpserver.url_for("/proxy")
        scope = Scope.from_entries(["127.0.0.1"])
        target = Target.from_url(f"{base}?url=FUZZ", marker="FUZZ")

        findings = asyncio.run(
            run_scan(
                target,
                scope,
                mcp_discovery=True,
                mcp_discovery_host="127.0.0.1",
            )
        )

        mcp_findings = [f for f in findings if "MCP server" in f.title]
        assert mcp_findings, (
            f"no MCP-server finding; got titles: {[f.title for f in findings]}"
        )
        f = mcp_findings[0]
        assert f.cwe_id == 918
        assert f.severity == "high"
        assert "internal_url" in f.evidence

    def test_no_mcp_finding_when_discovery_disabled(self, httpserver):
        """Without mcp_discovery=True, MCP server responses are not classified."""
        from werkzeug.wrappers import Response as WZResponse

        mcp_body = (
            '{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},'
            '"serverInfo":{"name":"hidden"}}'
        )

        httpserver.expect_request("/proxy").respond_with_handler(
            lambda r: WZResponse(mcp_body, content_type="application/json")
        )
        base = httpserver.url_for("/proxy")
        scope = Scope.from_entries(["127.0.0.1"])
        target = Target.from_url(f"{base}?url=FUZZ", marker="FUZZ")

        findings = asyncio.run(run_scan(target, scope, mcp_discovery=False))
        mcp_findings = [f for f in findings if "MCP server" in f.title]
        assert not mcp_findings, "MCP finding emitted without mcp_discovery=True"
