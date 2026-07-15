"""Cloud-metadata detection probes (V0.1-CRITERIA.md #3).

Detects SSRF that reaches a cloud instance-metadata service and returns a
**credential- or identity-shaped** response, then emits a
:class:`wraith.findings.Finding`. Covers:

* **AWS** -- IMDSv1 (unauthenticated GET) *and* the IMDSv2 PUT-token -> GET
  handshake, including the **header-injection variant** (the SSRF primitive
  controls request headers, so the ``X-aws-ec2-metadata-token`` header can be
  smuggled onto the server's outbound GET; cf. Typebot CVE-2025-64709).
* **GCP** -- ``metadata.google.internal`` token endpoint, ``Metadata-Flavor:
  Google``.
* **Azure** -- ``/metadata/instance`` with ``Metadata: true`` + ``api-version``;
  wraith deliberately does **not** send ``X-Forwarded-For`` (Azure IMDS rejects
  requests that carry it).
* **Alibaba** (``100.100.100.200``), **Oracle** (``192.0.0.192``),
  **DigitalOcean** (``169.254.169.254/metadata/v1.json``).

**Safety (contract + R5):** wraith detects and records credential-shaped
responses; it **never auto-uses** harvested credentials (no SDK calls, no
signing) and never evaluates response bytes -- they are captured verbatim as
Finding evidence and, for secrets, redacted to a short fingerprint.

Two probe shapes are provided:

* :func:`run_metadata_probes` -- *direct* probing (wraith -> metadata endpoint),
  used when wraith itself can reach the endpoint and by the Tier-1 handshake
  test. Out-of-scope bases are skipped (scan-primitives raises before egress).
* :func:`detect_from_response` -- classifies an arbitrary response body against
  every provider signature, for the *via-SSRF* path where the engine injects a
  metadata URL into the target app and inspects the app's echoed response.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import httpx
from scan_primitives import OutOfScopeError

from wraith.client import Response, ScanClient
from wraith.findings import CWE_SSRF, Finding

__all__ = [
    "MetadataProbe",
    "CATALOG",
    "AWS_IMDS_BASE",
    "AZURE_MI_PATH",
    "AZURE_MI_QUERY",
    "TOKEN_TTL_HEADER",
    "TOKEN_HEADER",
    "imdsv2_token",
    "probe_aws",
    "detect_from_response",
    "run_metadata_probes",
]

# AWS IMDS constants (shared by v1 / v2 / header-injection paths).
AWS_IMDS_BASE = "http://169.254.169.254"
_IAM_LIST_PATH = "/latest/meta-data/iam/security-credentials/"
TOKEN_PATH = "/latest/api/token"
TOKEN_TTL_HEADER = "X-aws-ec2-metadata-token-ttl-seconds"
TOKEN_HEADER = "X-aws-ec2-metadata-token"
DEFAULT_TOKEN_TTL = 21600

# Azure managed identity (IMDS credential endpoint) constants.
AZURE_MI_PATH = "/metadata/identity/oauth2/token"
AZURE_MI_QUERY = "api-version=2018-02-01&resource=https://management.azure.com/"

_CWE_REF = "https://cwe.mitre.org/data/definitions/918.html"


@dataclass(frozen=True, slots=True)
class MetadataProbe:
    """A single-GET metadata probe (header-based providers).

    AWS and Alibaba use a role-listing -> credentials flow instead (see
    :func:`probe_aws` / :func:`_probe_role_creds`); this dataclass covers the
    providers that expose credentials/identity at a single known path.
    """

    provider: str
    name: str
    base: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    query: str = ""
    signatures: tuple[str, ...] = ()
    min_hits: int = 2
    severity: str = "high"
    references: tuple[str, ...] = ()
    #: headers wraith must NOT send (e.g. Azure IMDS rejects X-Forwarded-For).
    forbid_headers: tuple[str, ...] = ()

    @property
    def url(self) -> str:
        u = f"{self.base}{self.path}"
        return f"{u}?{self.query}" if self.query else u

    def matches(self, text: str) -> tuple[str, ...]:
        """Return the subset of signatures present in ``text`` (data-only)."""
        return tuple(s for s in self.signatures if s in text)

    def is_hit(self, text: str) -> bool:
        return len(self.matches(text)) >= self.min_hits


# --------------------------------------------------------------------------- #
# The curated, per-provider catalog
# --------------------------------------------------------------------------- #

# AWS/Alibaba are role-creds flows handled separately; these are single-GET.
CATALOG: list[MetadataProbe] = [
    MetadataProbe(
        provider="gcp",
        name="gcp-service-account-token",
        base="http://metadata.google.internal",
        path="/computeMetadata/v1/instance/service-accounts/default/token",
        headers={"Metadata-Flavor": "Google"},
        signatures=("access_token", "token_type", "expires_in"),
        min_hits=2,
        severity="critical",
        references=(
            _CWE_REF,
            "https://cloud.google.com/compute/docs/metadata/overview",
        ),
    ),
    MetadataProbe(
        provider="azure",
        name="azure-instance-metadata",
        base="http://169.254.169.254",
        path="/metadata/instance",
        query="api-version=2021-02-01",
        headers={"Metadata": "true"},
        forbid_headers=("X-Forwarded-For",),
        signatures=("vmId", "subscriptionId", "resourceGroupName", "azEnvironment"),
        min_hits=2,
        severity="high",
        references=(
            _CWE_REF,
            "https://learn.microsoft.com/azure/virtual-machines/instance-metadata-service",
        ),
    ),
    # Azure managed identity: IMDS credential endpoint. Returns an OAuth2
    # access_token for the VM's managed identity — critical severity because
    # it is a harvested credential, not just identity metadata. The
    # ``resource`` field in the response is the key differentiator from GCP
    # tokens (which also carry ``access_token``/``token_type``/``expires_in``
    # but never ``resource``). Must appear before GCP in the via-SSRF
    # classifier dict (``_RESPONSE_SIGNATURES``) for this reason.
    MetadataProbe(
        provider="azure-managed-identity",
        name="azure-managed-identity-token",
        base="http://169.254.169.254",
        path=AZURE_MI_PATH,
        query=AZURE_MI_QUERY,
        headers={"Metadata": "true"},
        forbid_headers=("X-Forwarded-For",),
        # ``resource`` is ABSENT from GCP token responses — it is the
        # primary discriminator. ``access_token`` and ``token_type``
        # confirm this is a credential endpoint, not mere identity.
        signatures=("access_token", "resource", "token_type"),
        min_hits=2,
        severity="critical",
        references=(
            _CWE_REF,
            "https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token",
        ),
    ),
    MetadataProbe(
        provider="oracle",
        name="oracle-instance-metadata",
        base="http://192.0.0.192",
        path="/opc/v2/instance/",
        headers={"Authorization": "Bearer Oracle"},
        signatures=("availabilityDomain", "compartmentId", "region"),
        min_hits=2,
        severity="high",
        references=(_CWE_REF,),
    ),
    MetadataProbe(
        provider="digitalocean",
        name="digitalocean-metadata",
        base="http://169.254.169.254",
        path="/metadata/v1.json",
        signatures=("droplet_id", "region", "interfaces"),
        min_hits=2,
        severity="high",
        references=(_CWE_REF,),
    ),
    MetadataProbe(
        provider="hetzner",
        name="hetzner-instance-metadata",
        base="http://169.254.169.254",
        path="/hetzner/v1/metadata",
        # No auth header; response is YAML (content-type: text/yaml).
        # Hyphenated YAML keys are distinctive vs JSON-format providers.
        signatures=("availability-zone:", "instance-id:", "public-ipv4:"),
        min_hits=2,
        severity="high",
        references=(
            _CWE_REF,
            "https://docs.hetzner.cloud/#server-metadata",
        ),
    ),
]

# Signatures for the via-SSRF response classifier + role-creds flows. AWS and
# Alibaba both use "AccessKeyId"; the DISTINCTIVE markers disambiguate them
# (AWS: SecretAccessKey; Alibaba: AccessKeySecret + SecurityToken).
_AWS_CRED_SIGS = ("AccessKeyId", "SecretAccessKey")
_ALIBABA_CRED_SIGS = ("AccessKeyId", "AccessKeySecret", "SecurityToken")

# Substrings that mark a *credential* (not just identity) -> bump to critical
# and redact from evidence. Data-only markers, never evaluated.
_SECRET_MARKERS = (
    "SecretAccessKey",
    "AccessKeySecret",
    "SecurityToken",
    "access_token",
)


# Human-readable labels for provider keys that contain hyphens or need
# a title that differs from the default ``"<PROVIDER> instance-metadata"``
# format. Extend this dict when adding new non-standard provider keys.
_TITLE_LABELS: dict[str, str] = {
    "azure-managed-identity": "Azure managed-identity credential",
}


def _finding_id(*parts: str) -> str:
    digest = hashlib.sha1("|".join(parts).encode()).hexdigest()[:10]
    return f"wraith-{digest}"


def _redact_evidence(text: str, matched: tuple[str, ...]) -> str:
    """Summarise a credential response WITHOUT copying secret material.

    Records which signatures fired and the body length; never the secret bytes.
    R5: input is untrusted data -- only measured, never evaluated.
    """
    return (
        f"credential-shaped response: matched signatures "
        f"{', '.join(matched)}; body_len={len(text)} (secret values redacted)"
    )


def _make_finding(
    *,
    provider: str,
    name: str,
    url: str,
    matched: tuple[str, ...],
    severity: str,
    variant: str,
    vector: str,
    references: tuple[str, ...],
    request_summary: str,
    oob_proof: str | None = None,
) -> Finding:
    label = _TITLE_LABELS.get(provider, f"{provider.upper()} instance-metadata")
    title = f"SSRF to {label} endpoint"
    return Finding(
        id=_finding_id(provider, url, variant),
        tool="wraith",
        title=title,
        severity=severity,
        confidence="high",
        target=url,
        vector=vector,
        variant=variant,
        cwe_id=CWE_SSRF,
        evidence={
            "provider": provider,
            "probe": name,
            "request": request_summary,
            "response_signature": _redact_evidence("", matched)
            if any(m in _SECRET_MARKERS for m in matched)
            else f"identity-shaped response: matched {', '.join(matched)}",
        },
        oob_proof=oob_proof,
        references=list(references),
    )


# --------------------------------------------------------------------------- #
# AWS IMDS: v1, v2 handshake, header-injection variant
# --------------------------------------------------------------------------- #

async def imdsv2_token(
    client: ScanClient,
    base: str = AWS_IMDS_BASE,
    *,
    ttl: int = DEFAULT_TOKEN_TTL,
) -> str:
    """IMDSv2 step 1: PUT the token endpoint, return the session token text.

    Sends only the TTL header on the PUT (what a real IMDSv2 client does). The
    returned token is attached to the follow-up GET(s) to prove v2 (not v1).
    """
    resp = await client.request(
        "PUT",
        f"{base}{TOKEN_PATH}",
        headers={TOKEN_TTL_HEADER: str(ttl)},
    )
    return resp.text.strip()


async def _aws_iam_creds(
    client: ScanClient,
    base: str,
    *,
    token: str | None,
) -> tuple[Response | None, str | None, Response | None]:
    """List IAM roles then fetch the first role's credentials.

    ``token`` (when present) is attached via :data:`TOKEN_HEADER` on every GET,
    which is what distinguishes an IMDSv2 (or header-injection) probe from v1.
    """
    headers = {TOKEN_HEADER: token} if token else {}
    listing = await client.get(f"{base}{_IAM_LIST_PATH}", headers=headers)
    body = listing.text.strip()
    if listing.status_code != 200 or not body:
        return listing, None, None
    role = body.splitlines()[0].strip()
    creds = await client.get(f"{base}{_IAM_LIST_PATH}{role}", headers=headers)
    return listing, role, creds


async def probe_aws(
    client: ScanClient,
    base: str = AWS_IMDS_BASE,
    *,
    imdsv2: bool = True,
    header_injection: bool = False,
) -> Finding | None:
    """Probe AWS IMDS for exposed IAM credentials.

    * ``imdsv2=True`` -> PUT-token then GET-with-token (the modern path).
    * ``imdsv2=False`` -> unauthenticated GET (IMDSv1, if still enabled).
    * ``header_injection=True`` -> tags the finding as the header-injection
      variant (CVE-2025-64709): the token header is smuggled onto the server's
      outbound request via an SSRF header-control primitive. Wire behaviour is
      identical (PUT then GET-with-token); the label + reference differ.

    Returns a critical :class:`Finding` when credentials are exposed, else None.
    NEVER uses the harvested credentials.
    """
    token = await imdsv2_token(client, base) if imdsv2 else None
    _listing, role, creds = await _aws_iam_creds(client, base, token=token)
    if creds is None or creds.status_code != 200:
        return None
    matched = tuple(s for s in _AWS_CRED_SIGS if s in creds.text)
    if len(matched) < 2:
        return None

    if header_injection:
        variant, refs = (
            "imdsv2-header-injection",
            (_CWE_REF, "https://nvd.nist.gov/vuln/detail/CVE-2025-64709"),
        )
    elif imdsv2:
        variant, refs = "imdsv2", (_CWE_REF,)
    else:
        variant, refs = "imdsv1", (_CWE_REF,)

    return _make_finding(
        provider="aws",
        name=f"aws-{variant}",
        url=f"{base}{_IAM_LIST_PATH}{role}",
        matched=matched,
        severity="critical",
        variant=variant,
        vector="metadata:aws-imds",
        references=refs,
        request_summary=(
            f"GET {_IAM_LIST_PATH}{role}"
            + (f" [{TOKEN_HEADER} present]" if token else " [no token: IMDSv1]")
        ),
    )


async def _probe_alibaba(client: ScanClient) -> Finding | None:
    """Alibaba RAM role credentials (role-listing -> creds, no token header)."""
    base = "http://100.100.100.200"
    list_path = "/latest/meta-data/ram/security-credentials/"
    listing = await client.get(f"{base}{list_path}")
    body = listing.text.strip()
    if listing.status_code != 200 or not body:
        return None
    role = body.splitlines()[0].strip()
    creds = await client.get(f"{base}{list_path}{role}")
    matched = tuple(s for s in _ALIBABA_CRED_SIGS if s in creds.text)
    if len(matched) < 2:
        return None
    return _make_finding(
        provider="alibaba",
        name="alibaba-ram-credentials",
        url=f"{base}{list_path}{role}",
        matched=matched,
        severity="critical",
        variant="ram-role",
        vector="metadata:alibaba",
        references=(_CWE_REF,),
        request_summary=f"GET {list_path}{role}",
    )


async def _probe_simple(client: ScanClient, probe: MetadataProbe) -> Finding | None:
    resp = await client.get(probe.url, headers=probe.headers)
    if resp.status_code != 200 or not probe.is_hit(resp.text):
        return None
    matched = probe.matches(resp.text)
    return _make_finding(
        provider=probe.provider,
        name=probe.name,
        url=probe.url,
        matched=matched,
        severity=probe.severity,
        variant=probe.provider,
        vector=f"metadata:{probe.provider}",
        references=probe.references,
        request_summary=f"GET {probe.path}"
        + (f" [{', '.join(probe.headers)}]" if probe.headers else ""),
    )


async def run_metadata_probes(
    client: ScanClient,
    *,
    aws_header_injection: bool = False,
) -> list[Finding]:
    """Directly probe every provider; return findings for credential/identity hits.

    Out-of-scope bases raise :class:`OutOfScopeError` in scan-primitives before
    any socket opens; those providers are skipped (a scope may authorise only
    the app, not the metadata IPs). Order: AWS (v2, then v1 fallback), Alibaba,
    then the single-GET catalog.
    """
    findings: list[Finding] = []

    # AWS: prefer IMDSv2; fall back to IMDSv1 if v2 yielded nothing.
    try:
        aws = await probe_aws(
            client, imdsv2=True, header_injection=aws_header_injection
        )
        if aws is None:
            aws = await probe_aws(client, imdsv2=False)
        if aws is not None:
            findings.append(aws)
    except (OutOfScopeError, httpx.HTTPError):
        # Out-of-scope base raises before egress; an unreachable endpoint (you
        # are not on that cloud) raises a transport error. Either way: skip it.
        pass

    try:
        ali = await _probe_alibaba(client)
        if ali is not None:
            findings.append(ali)
    except (OutOfScopeError, httpx.HTTPError):
        # Out-of-scope base raises before egress; an unreachable endpoint (you
        # are not on that cloud) raises a transport error. Either way: skip it.
        pass

    for probe in CATALOG:
        try:
            f = await _probe_simple(client, probe)
        except (OutOfScopeError, httpx.HTTPError):
            continue
        if f is not None:
            findings.append(f)

    return findings


# --------------------------------------------------------------------------- #
# Via-SSRF response classifier (used by the engine)
# --------------------------------------------------------------------------- #

# provider -> (signatures, min_hits, severity) for classifying an app response
# that echoed a metadata body back through the SSRF.
_RESPONSE_SIGNATURES: dict[str, tuple[tuple[str, ...], int, str]] = {
    # Alibaba is checked before AWS: its 3-marker signature is more specific, so
    # an Alibaba body (which also carries AccessKeyId) is not misread as AWS.
    "alibaba": (_ALIBABA_CRED_SIGS, 2, "critical"),
    "aws": (_AWS_CRED_SIGS, 2, "critical"),
    # azure-managed-identity MUST precede gcp: both responses carry
    # "access_token" / "token_type" / "expires_in", but Azure managed-identity
    # responses also carry "resource" whereas GCP responses do not. Checking
    # "resource" first prevents Azure MI tokens from being misclassified as GCP.
    "azure-managed-identity": (("access_token", "resource"), 2, "critical"),
    "gcp": (("access_token", "token_type", "expires_in"), 2, "critical"),
    "azure": (("vmId", "subscriptionId", "resourceGroupName", "azEnvironment"), 2, "high"),
    "oracle": (("availabilityDomain", "compartmentId", "region"), 2, "high"),
    "digitalocean": (("droplet_id", "region", "interfaces"), 2, "high"),
    # Hetzner: YAML-format response; hyphenated keys do not collide with any JSON provider.
    "hetzner": (("availability-zone:", "instance-id:", "public-ipv4:"), 2, "high"),
}


def detect_from_response(text: str) -> tuple[str, tuple[str, ...], str] | None:
    """Classify a response body against every provider signature.

    Returns ``(provider, matched_signatures, severity)`` for the first provider
    whose ``min_hits`` threshold is met, else ``None``. This is the via-SSRF
    detector: the target app fetched a metadata URL and echoed the body, and
    wraith classifies that echoed body. R5: ``text`` is untrusted data -- only
    substring-tested, never evaluated.
    """
    for provider, (sigs, min_hits, severity) in _RESPONSE_SIGNATURES.items():
        matched = tuple(s for s in sigs if s in text)
        if len(matched) >= min_hits:
            return provider, matched, severity
    return None
