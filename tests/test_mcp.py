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

from wraith.mcp import (
    MCP_CATALOG,
    applicable,
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
