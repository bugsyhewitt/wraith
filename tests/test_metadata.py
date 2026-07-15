"""Tier-1 mocked-HTTP tests for the cloud-metadata probes (V0.1-CRITERIA.md #3).

Uses ``respx`` (httpx interception) -- scan-primitives wraps httpx, so respx's
global transport patch intercepts ``ScanClient`` requests. The headline
assertions the contract mandates:

* the **IMDSv2 PUT-then-GET order** (respx records calls in order);
* the credentials GET carries ``x-aws-ec2-metadata-token`` -> proves v2, not v1;
* a critical, CWE-918 Finding is produced -- and the harvested creds are NEVER
  used (the secret bytes are redacted out of the evidence).

wraith declares no pytest-asyncio, so coroutines are driven with ``asyncio.run``
inside the respx context. Hermetic: respx means no socket opens (pytest-socket
lock stays satisfied).
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
    TOKEN_HEADER,
    TOKEN_PATH,
    TOKEN_TTL_HEADER,
    _probe_simple,
    detect_from_response,
    probe_aws,
    run_metadata_probes,
)


def _catalog_probe(provider: str):
    return next(p for p in CATALOG if p.provider == provider)

_FIXTURES = Path(__file__).parent / "fixtures" / "metadata"
_AWS_CREDS = (_FIXTURES / "aws_iam_credentials.json").read_text()
_IAM_LIST = "/latest/meta-data/iam/security-credentials/"
_ROLE = "example-role"


def _scope() -> Scope:
    return Scope.from_entries(
        [
            "169.254.169.254",
            "metadata.google.internal",
            "100.100.100.200",
            "192.0.0.192",
        ]
    )


def _run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------- #
# AWS IMDSv2 handshake: order + header echo (the contract's headline test)
# --------------------------------------------------------------------------- #

def test_imdsv2_put_then_get_and_token_header_echo():
    # An explicit order log (via respx side_effect) proves PUT-then-GET
    # positionally, independent of respx's global call-log. The token
    # data-dependency (creds GET header == the PUT's returned token) proves the
    # same order a second way: you cannot carry the token before you fetch it.
    token = "AQAEAEXAMPLETOKEN=="
    order: list[tuple[str, str]] = []

    def _log(text: str):
        def _se(request):
            order.append((request.method, request.url.path))
            return httpx.Response(200, text=text)

        return _se

    with respx.mock(assert_all_called=False) as mock:
        put = mock.put(host="169.254.169.254", path=TOKEN_PATH).mock(side_effect=_log(token))
        lst = mock.get(host="169.254.169.254", path=_IAM_LIST).mock(side_effect=_log(_ROLE))
        creds = mock.get(host="169.254.169.254", path=f"{_IAM_LIST}{_ROLE}").mock(
            side_effect=_log(_AWS_CREDS)
        )

        async def go():
            async with get_client(_scope()) as client:
                return await probe_aws(client, imdsv2=True)

        finding = _run(go())

    # 1) A finding was produced, critical + CWE-918.
    assert finding is not None
    assert finding.severity == "critical"
    assert finding.cwe_id == 918
    assert finding.variant == "imdsv2"

    # 2) Exact request order: token PUT, then role listing, then creds GET.
    assert order == [
        ("PUT", TOKEN_PATH),
        ("GET", _IAM_LIST),
        ("GET", f"{_IAM_LIST}{_ROLE}"),
    ]

    # 3) The PUT carried the TTL header (what a real IMDSv2 client sends).
    assert put.called and put.call_count == 1
    assert TOKEN_TTL_HEADER.lower() in put.calls.last.request.headers

    # 4) The credentials GET carried the session token header -> v2, not v1 --
    #    and its value is the token the PUT returned (order proof by dependency).
    creds_req = creds.calls.last.request
    assert creds_req.method == "GET"
    assert creds_req.headers.get(TOKEN_HEADER) == token
    assert lst.called


def test_imdsv2_finding_redacts_secret_material():
    """The harvested credentials must NOT be copied verbatim into evidence."""
    with respx.mock(assert_all_called=False) as mock:
        mock.put(host="169.254.169.254", path=TOKEN_PATH).mock(
            return_value=httpx.Response(200, text="TOKEN==")
        )
        mock.get(host="169.254.169.254", path=_IAM_LIST).mock(
            return_value=httpx.Response(200, text=_ROLE)
        )
        mock.get(host="169.254.169.254", path=f"{_IAM_LIST}{_ROLE}").mock(
            return_value=httpx.Response(200, text=_AWS_CREDS)
        )

        async def go():
            async with get_client(_scope()) as client:
                return await probe_aws(client, imdsv2=True)

        finding = _run(go())

    secret = json.loads(_AWS_CREDS)["SecretAccessKey"]
    blob = json.dumps(finding.to_dict())
    assert secret not in blob, "secret material leaked into finding evidence"
    assert "redacted" in finding.evidence["response_signature"]


def test_header_injection_variant_labels_and_cites_cve():
    with respx.mock(assert_all_called=False) as mock:
        mock.put(host="169.254.169.254", path=TOKEN_PATH).mock(
            return_value=httpx.Response(200, text="TOKEN==")
        )
        mock.get(host="169.254.169.254", path=_IAM_LIST).mock(
            return_value=httpx.Response(200, text=_ROLE)
        )
        mock.get(host="169.254.169.254", path=f"{_IAM_LIST}{_ROLE}").mock(
            return_value=httpx.Response(200, text=_AWS_CREDS)
        )

        async def go():
            async with get_client(_scope()) as client:
                return await probe_aws(client, imdsv2=True, header_injection=True)

        finding = _run(go())

    assert finding is not None
    assert finding.variant == "imdsv2-header-injection"
    assert any("CVE-2025-64709" in r for r in finding.references)


def test_imdsv1_sends_no_token_header():
    with respx.mock(assert_all_called=False) as mock:
        # Register the token PUT so we can assert it is NEVER called on the v1 path.
        put = mock.put(host="169.254.169.254", path=TOKEN_PATH).mock(
            return_value=httpx.Response(200, text="TOKEN==")
        )
        mock.get(host="169.254.169.254", path=_IAM_LIST).mock(
            return_value=httpx.Response(200, text=_ROLE)
        )
        creds = mock.get(host="169.254.169.254", path=f"{_IAM_LIST}{_ROLE}").mock(
            return_value=httpx.Response(200, text=_AWS_CREDS)
        )

        async def go():
            async with get_client(_scope()) as client:
                return await probe_aws(client, imdsv2=False)

        finding = _run(go())

    assert finding is not None
    assert finding.variant == "imdsv1"
    # No token PUT was issued and no token header rode along.
    assert not put.called
    assert TOKEN_HEADER.lower() not in creds.calls.last.request.headers


def test_no_finding_when_response_not_credential_shaped():
    with respx.mock(assert_all_called=False) as mock:
        mock.put(host="169.254.169.254", path=TOKEN_PATH).mock(
            return_value=httpx.Response(200, text="TOKEN==")
        )
        mock.get(host="169.254.169.254", path=_IAM_LIST).mock(
            return_value=httpx.Response(404, text="Not Found")
        )

        async def go():
            async with get_client(_scope()) as client:
                return await probe_aws(client, imdsv2=True)

        assert _run(go()) is None


# --------------------------------------------------------------------------- #
# Azure: Metadata:true present, X-Forwarded-For absent
# --------------------------------------------------------------------------- #

def test_azure_sends_metadata_header_and_omits_xff():
    azure = (_FIXTURES / "azure_instance.json").read_text()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.get(host="169.254.169.254", path="/metadata/instance").mock(
            return_value=httpx.Response(200, text=azure)
        )

        async def go():
            async with get_client(_scope()) as client:
                return await _probe_simple(client, _catalog_probe("azure"))

        finding = _run(go())

    req = route.calls.last.request
    assert req.headers.get("Metadata") == "true"
    assert "x-forwarded-for" not in req.headers  # contract: omit XFF for Azure
    assert "api-version=" in str(req.url)
    assert finding is not None and finding.severity == "high"
    assert finding.evidence.get("provider") == "azure"


def test_gcp_requires_metadata_flavor_header():
    gcp = (_FIXTURES / "gcp_token.json").read_text()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.get(
            host="metadata.google.internal",
            path="/computeMetadata/v1/instance/service-accounts/default/token",
        ).mock(return_value=httpx.Response(200, text=gcp))

        async def go():
            async with get_client(_scope()) as client:
                return await _probe_simple(client, _catalog_probe("gcp"))

        finding = _run(go())

    assert route.calls.last.request.headers.get("Metadata-Flavor") == "Google"
    assert finding is not None and finding.severity == "critical"
    assert finding.evidence.get("provider") == "gcp"


def test_out_of_scope_metadata_base_is_skipped_not_raised():
    # Scope authorises ONLY the app, not the metadata IPs -> direct probing skips
    # each provider (scan-primitives would raise before egress).
    scope = Scope.from_entries(["app.example.com"])
    with respx.mock(assert_all_called=False):

        async def go():
            async with get_client(scope) as client:
                return await run_metadata_probes(client)

        assert _run(go()) == []


# --------------------------------------------------------------------------- #
# Via-SSRF response classifier against every fixture
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "fixture,provider,severity",
    [
        ("aws_iam_credentials.json", "aws", "critical"),
        ("gcp_token.json", "gcp", "critical"),
        ("azure_instance.json", "azure", "high"),
        ("azure_managed_identity.json", "azure-managed-identity", "critical"),
        ("alibaba_ram_credentials.json", "alibaba", "critical"),
        ("oracle_instance.json", "oracle", "high"),
        ("digitalocean_metadata.json", "digitalocean", "high"),
        ("hetzner_metadata.yaml", "hetzner", "high"),
    ],
)
def test_detect_from_response_classifies_fixtures(fixture, provider, severity):
    body = (_FIXTURES / fixture).read_text()
    result = detect_from_response(body)
    assert result is not None
    got_provider, matched, got_severity = result
    assert got_provider == provider
    assert got_severity == severity
    assert len(matched) >= 2


def test_hetzner_probe_no_auth_required():
    """Hetzner IMDS requires no auth header and returns YAML."""
    hetzner = (_FIXTURES / "hetzner_metadata.yaml").read_text()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.get(host="169.254.169.254", path="/hetzner/v1/metadata").mock(
            return_value=httpx.Response(200, text=hetzner)
        )

        async def go():
            async with get_client(_scope()) as client:
                return await _probe_simple(client, _catalog_probe("hetzner"))

        finding = _run(go())

    req = route.calls.last.request
    # Hetzner IMDS: no auth header required.
    assert "authorization" not in req.headers
    assert finding is not None and finding.severity == "high"
    assert finding.evidence.get("provider") == "hetzner"


def test_hetzner_probe_no_finding_on_miss():
    """A non-Hetzner response at the path produces no finding."""
    with respx.mock(assert_all_called=False) as mock:
        mock.get(host="169.254.169.254", path="/hetzner/v1/metadata").mock(
            return_value=httpx.Response(404, text="Not Found")
        )

        async def go():
            async with get_client(_scope()) as client:
                return await _probe_simple(client, _catalog_probe("hetzner"))

        assert _run(go()) is None


def test_detect_from_response_none_for_benign_body():
    assert detect_from_response('{"status":"ok","items":[]}') is None


# --------------------------------------------------------------------------- #
# Azure managed identity: credential endpoint (v0.9.2)
# --------------------------------------------------------------------------- #

def test_azure_managed_identity_probe_sends_metadata_header_and_omits_xff():
    """Direct probe: Metadata:true must be present; X-Forwarded-For must be absent."""
    azure_mi = (_FIXTURES / "azure_managed_identity.json").read_text()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.get(
            host="169.254.169.254",
            path="/metadata/identity/oauth2/token",
        ).mock(return_value=httpx.Response(200, text=azure_mi))

        async def go():
            async with get_client(_scope()) as client:
                return await _probe_simple(client, _catalog_probe("azure-managed-identity"))

        finding = _run(go())

    req = route.calls.last.request
    assert req.headers.get("Metadata") == "true", "Metadata:true header required for Azure IMDS"
    assert "x-forwarded-for" not in req.headers, "X-Forwarded-For must be absent (Azure IMDS rejects it)"
    assert "api-version=" in str(req.url)
    assert finding is not None


def test_azure_managed_identity_probe_is_critical_severity():
    """Direct probe: managed identity token response must produce a critical finding."""
    azure_mi = (_FIXTURES / "azure_managed_identity.json").read_text()
    with respx.mock(assert_all_called=False) as mock:
        mock.get(
            host="169.254.169.254",
            path="/metadata/identity/oauth2/token",
        ).mock(return_value=httpx.Response(200, text=azure_mi))

        async def go():
            async with get_client(_scope()) as client:
                return await _probe_simple(client, _catalog_probe("azure-managed-identity"))

        finding = _run(go())

    assert finding is not None
    assert finding.severity == "critical", "managed identity token is a harvested credential → critical"
    assert finding.cwe_id == 918
    assert finding.evidence.get("provider") == "azure-managed-identity"


def test_azure_managed_identity_finding_title_is_human_readable():
    """Finding title should mention 'Azure managed-identity', not 'AZURE-MANAGED-IDENTITY'."""
    azure_mi = (_FIXTURES / "azure_managed_identity.json").read_text()
    with respx.mock(assert_all_called=False) as mock:
        mock.get(
            host="169.254.169.254",
            path="/metadata/identity/oauth2/token",
        ).mock(return_value=httpx.Response(200, text=azure_mi))

        async def go():
            async with get_client(_scope()) as client:
                return await _probe_simple(client, _catalog_probe("azure-managed-identity"))

        finding = _run(go())

    assert finding is not None
    # Should not contain the raw hyphenated provider key uppercased.
    assert "AZURE-MANAGED-IDENTITY" not in finding.title
    assert "managed-identity" in finding.title.lower()


def test_azure_managed_identity_classifier_not_confused_with_gcp():
    """A GCP token response must NOT be classified as azure-managed-identity.

    GCP tokens have access_token/token_type/expires_in but NO ``resource`` field.
    The classifier must distinguish them: azure-managed-identity requires ``resource``,
    GCP requires token_type+expires_in. Both should classify correctly.
    """
    gcp = (_FIXTURES / "gcp_token.json").read_text()
    azure_mi = (_FIXTURES / "azure_managed_identity.json").read_text()

    # GCP token: must classify as "gcp", not "azure-managed-identity".
    result = detect_from_response(gcp)
    assert result is not None
    provider, _, _ = result
    assert provider == "gcp", f"GCP token must classify as gcp, got {provider!r}"

    # Azure MI token: must classify as "azure-managed-identity", not "gcp".
    result = detect_from_response(azure_mi)
    assert result is not None
    provider, _, severity = result
    assert provider == "azure-managed-identity", (
        f"Azure MI token must classify as azure-managed-identity, got {provider!r}"
    )
    assert severity == "critical"


def test_azure_managed_identity_probe_no_finding_on_miss():
    """A non-credential response at the endpoint produces no finding."""
    with respx.mock(assert_all_called=False) as mock:
        mock.get(
            host="169.254.169.254",
            path="/metadata/identity/oauth2/token",
        ).mock(return_value=httpx.Response(400, text='{"error":"invalid_request"}'))

        async def go():
            async with get_client(_scope()) as client:
                return await _probe_simple(client, _catalog_probe("azure-managed-identity"))

        assert _run(go()) is None


def test_azure_managed_identity_in_metadata_ssrf_urls():
    """Azure managed identity URL must be present in the via-SSRF injection list."""
    from wraith.engine import METADATA_SSRF_URLS

    labels = [label for label, _url in METADATA_SSRF_URLS]
    assert "azure-managed-identity" in labels, (
        "azure-managed-identity must be in METADATA_SSRF_URLS for via-SSRF injection"
    )
    # Verify the URL points to the credential endpoint, not the instance endpoint.
    mi_url = next(url for label, url in METADATA_SSRF_URLS if label == "azure-managed-identity")
    assert "identity/oauth2/token" in mi_url
    assert "api-version=" in mi_url
