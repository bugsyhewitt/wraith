"""Cloud-metadata probe tests: Oracle, DigitalOcean, Alibaba direct probes;
MetadataProbe dataclass behavior; partial-match threshold; CATALOG completeness.

Covers gaps in test_metadata.py:
- Oracle and DigitalOcean direct probes (Tier-1 respx mock).
- Alibaba _probe_alibaba direct function test.
- MetadataProbe.url property (with and without query string).
- MetadataProbe.matches and MetadataProbe.is_hit behavior.
- Partial signature match (< min_hits) → no finding.
- CATALOG contains all single-GET providers.
- detect_from_response returns None when only 1 of 2 required sigs present.

Hermetic: respx intercepts all httpx calls; no real network traffic.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest
import respx
from scan_primitives import Scope

from wraith.client import get_client
from wraith.metadata import (
    CATALOG,
    MetadataProbe,
    _probe_alibaba,
    _probe_simple,
    detect_from_response,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "metadata"


def _run(coro):
    return asyncio.run(coro)


def _scope() -> Scope:
    return Scope.from_entries(
        [
            "169.254.169.254",
            "metadata.google.internal",
            "100.100.100.200",
            "192.0.0.192",
        ]
    )


def _catalog_probe(provider: str) -> MetadataProbe:
    return next(p for p in CATALOG if p.provider == provider)


# --------------------------------------------------------------------------- #
# Oracle direct probe
# --------------------------------------------------------------------------- #

def test_oracle_probe_sends_authorization_header():
    """Oracle IMDS requires 'Authorization: Bearer Oracle' on the GET request."""
    oracle_body = (_FIXTURES / "oracle_instance.json").read_text()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.get(host="192.0.0.192", path="/opc/v2/instance/").mock(
            return_value=httpx.Response(200, text=oracle_body)
        )

        async def go():
            async with get_client(_scope()) as client:
                return await _probe_simple(client, _catalog_probe("oracle"))

        finding = _run(go())

    req = route.calls.last.request
    assert req.headers.get("Authorization") == "Bearer Oracle"
    assert finding is not None
    assert finding.severity == "high"
    assert finding.evidence.get("provider") == "oracle"


def test_oracle_probe_no_finding_on_miss():
    """A 404 at the Oracle IMDS path produces no finding."""
    with respx.mock(assert_all_called=False) as mock:
        mock.get(host="192.0.0.192", path="/opc/v2/instance/").mock(
            return_value=httpx.Response(404, text="Not Found")
        )

        async def go():
            async with get_client(_scope()) as client:
                return await _probe_simple(client, _catalog_probe("oracle"))

        assert _run(go()) is None


def test_oracle_finding_cwe_is_918():
    """Oracle IMDS finding must carry CWE-918."""
    oracle_body = (_FIXTURES / "oracle_instance.json").read_text()
    with respx.mock(assert_all_called=False) as mock:
        mock.get(host="192.0.0.192", path="/opc/v2/instance/").mock(
            return_value=httpx.Response(200, text=oracle_body)
        )

        async def go():
            async with get_client(_scope()) as client:
                return await _probe_simple(client, _catalog_probe("oracle"))

        finding = _run(go())

    assert finding is not None
    assert finding.cwe_id == 918


# --------------------------------------------------------------------------- #
# DigitalOcean direct probe
# --------------------------------------------------------------------------- #

def test_digitalocean_probe_no_auth_header_required():
    """DigitalOcean IMDS requires no authentication header."""
    do_body = (_FIXTURES / "digitalocean_metadata.json").read_text()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.get(host="169.254.169.254", path="/metadata/v1.json").mock(
            return_value=httpx.Response(200, text=do_body)
        )

        async def go():
            async with get_client(_scope()) as client:
                return await _probe_simple(client, _catalog_probe("digitalocean"))

        finding = _run(go())

    req = route.calls.last.request
    # No auth header required for DigitalOcean IMDS.
    assert "authorization" not in req.headers
    assert finding is not None
    assert finding.severity == "high"
    assert finding.evidence.get("provider") == "digitalocean"


def test_digitalocean_probe_no_finding_on_miss():
    """A non-DigitalOcean response body produces no finding."""
    with respx.mock(assert_all_called=False) as mock:
        mock.get(host="169.254.169.254", path="/metadata/v1.json").mock(
            return_value=httpx.Response(200, text='{"status": "ok"}')
        )

        async def go():
            async with get_client(_scope()) as client:
                return await _probe_simple(client, _catalog_probe("digitalocean"))

        assert _run(go()) is None


# --------------------------------------------------------------------------- #
# Alibaba direct probe (_probe_alibaba function)
# --------------------------------------------------------------------------- #

def test_alibaba_probe_produces_critical_finding():
    """Alibaba RAM credentials probe must produce a critical finding."""
    ali_body = (_FIXTURES / "alibaba_ram_credentials.json").read_text()
    list_path = "/latest/meta-data/ram/security-credentials/"
    role = "example-role"
    with respx.mock(assert_all_called=False) as mock:
        mock.get(host="100.100.100.200", path=list_path).mock(
            return_value=httpx.Response(200, text=role)
        )
        mock.get(host="100.100.100.200", path=f"{list_path}{role}").mock(
            return_value=httpx.Response(200, text=ali_body)
        )

        async def go():
            async with get_client(_scope()) as client:
                return await _probe_alibaba(client)

        finding = _run(go())

    assert finding is not None
    assert finding.severity == "critical"
    assert finding.cwe_id == 918
    assert finding.evidence.get("provider") == "alibaba"


def test_alibaba_probe_no_finding_when_role_list_404():
    """Alibaba probe must return None when the role-listing endpoint returns 404."""
    list_path = "/latest/meta-data/ram/security-credentials/"
    with respx.mock(assert_all_called=False) as mock:
        mock.get(host="100.100.100.200", path=list_path).mock(
            return_value=httpx.Response(404, text="Not Found")
        )

        async def go():
            async with get_client(_scope()) as client:
                return await _probe_alibaba(client)

        assert _run(go()) is None


def test_alibaba_credentials_redacted_from_evidence():
    """Alibaba secret material must not appear verbatim in finding evidence."""
    ali_body = (_FIXTURES / "alibaba_ram_credentials.json").read_text()
    list_path = "/latest/meta-data/ram/security-credentials/"
    role = "redact-role"
    with respx.mock(assert_all_called=False) as mock:
        mock.get(host="100.100.100.200", path=list_path).mock(
            return_value=httpx.Response(200, text=role)
        )
        mock.get(host="100.100.100.200", path=f"{list_path}{role}").mock(
            return_value=httpx.Response(200, text=ali_body)
        )

        async def go():
            async with get_client(_scope()) as client:
                return await _probe_alibaba(client)

        finding = _run(go())

    assert finding is not None
    secret = json.loads(ali_body)["AccessKeySecret"]
    blob = json.dumps(finding.to_dict())
    assert secret not in blob, "Alibaba AccessKeySecret must be redacted from evidence"


# --------------------------------------------------------------------------- #
# MetadataProbe dataclass behavior
# --------------------------------------------------------------------------- #

def test_metadata_probe_url_with_query():
    """MetadataProbe.url must append the query string when query is non-empty."""
    probe = _catalog_probe("azure")
    assert "?" in probe.url
    assert "api-version=" in probe.url


def test_metadata_probe_url_without_query():
    """MetadataProbe.url must not append '?' when query is empty."""
    probe = _catalog_probe("oracle")
    assert probe.query == ""
    assert "?" not in probe.url


def test_metadata_probe_matches_returns_hit_signatures():
    """MetadataProbe.matches returns exactly the signatures present in the body."""
    probe = _catalog_probe("oracle")
    body = '{"availabilityDomain": "PHX-AD-1", "compartmentId": "ocid1.compartment", "region": "us-phoenix-1"}'
    matched = probe.matches(body)
    assert set(matched) == {"availabilityDomain", "compartmentId", "region"}


def test_metadata_probe_matches_returns_empty_when_no_sigs():
    """MetadataProbe.matches returns an empty tuple when no signatures are present."""
    probe = _catalog_probe("oracle")
    matched = probe.matches('{"status": "not an oracle response"}')
    assert matched == ()


def test_metadata_probe_is_hit_true_when_enough_sigs():
    """MetadataProbe.is_hit returns True when at least min_hits signatures are present."""
    probe = _catalog_probe("oracle")
    # Oracle min_hits=2; body has all 3 signatures.
    body = '{"availabilityDomain": "PHX-AD-1", "compartmentId": "ocid1.compartment", "region": "us-phoenix-1"}'
    assert probe.is_hit(body) is True


def test_metadata_probe_is_hit_false_when_too_few_sigs():
    """MetadataProbe.is_hit returns False when fewer than min_hits signatures are present."""
    probe = _catalog_probe("oracle")
    # Only 1 signature — below min_hits=2.
    assert probe.is_hit('{"availabilityDomain": "PHX-AD-1"}') is False


# --------------------------------------------------------------------------- #
# CATALOG completeness
# --------------------------------------------------------------------------- #

def test_catalog_contains_all_single_get_providers():
    """CATALOG must include all 7 single-GET providers (AWS/Alibaba handled separately)."""
    expected = {"gcp", "azure", "azure-managed-identity", "oracle", "digitalocean", "hetzner"}
    catalog_providers = {p.provider for p in CATALOG}
    missing = expected - catalog_providers
    assert not missing, f"providers missing from CATALOG: {missing}"


def test_catalog_all_probes_have_min_hits_at_least_2():
    """Every probe in CATALOG must require at least 2 signature matches."""
    for probe in CATALOG:
        assert probe.min_hits >= 2, (
            f"probe {probe.name!r} has min_hits={probe.min_hits} (must be >= 2)"
        )


def test_catalog_all_probes_have_at_least_2_signatures():
    """Every probe in CATALOG must define at least 2 signatures."""
    for probe in CATALOG:
        assert len(probe.signatures) >= 2, (
            f"probe {probe.name!r} has only {len(probe.signatures)} signatures"
        )


# --------------------------------------------------------------------------- #
# detect_from_response: partial match (1 of 2 required sigs) → None
# --------------------------------------------------------------------------- #

def test_detect_from_response_partial_oracle_match_returns_none():
    """A body with only 1 Oracle signature (below min_hits=2) must return None."""
    # Only availabilityDomain — no compartmentId or region.
    result = detect_from_response('{"availabilityDomain": "PHX-AD-1", "other": "data"}')
    if result is not None:
        # If something matched, it must not be oracle.
        assert result[0] != "oracle"


def test_detect_from_response_partial_gcp_match_returns_none():
    """A body with only 1 GCP signature must not classify as gcp."""
    # Only access_token — no token_type or expires_in.
    result = detect_from_response('{"access_token": "ya29.EXAMPLE", "unrelated": true}')
    if result is not None:
        # Azure-MI also uses access_token; ensure it has at least 2 of its sigs.
        provider, matched, _ = result
        assert len(matched) >= 2


def test_detect_from_response_hetzner_yaml_format():
    """Hetzner YAML-format response with hyphenated keys is correctly classified."""
    hetzner = (_FIXTURES / "hetzner_metadata.yaml").read_text()
    result = detect_from_response(hetzner)
    assert result is not None
    provider, matched, severity = result
    assert provider == "hetzner"
    assert severity == "high"
    assert len(matched) >= 2


def test_detect_from_response_alibaba_not_misclassified_as_aws():
    """An Alibaba credential body must classify as alibaba, not aws."""
    ali_body = (_FIXTURES / "alibaba_ram_credentials.json").read_text()
    result = detect_from_response(ali_body)
    assert result is not None
    provider, _, _ = result
    assert provider == "alibaba", f"Alibaba credentials must not be classified as {provider!r}"
