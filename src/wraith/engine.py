"""Scan orchestration: injection-point handling + the concurrent detect/confirm loop.

Ties the pieces together for ``wraith scan`` (V0.1-CRITERIA.md #1, #4, #7):

* **Input flexibility (#1).** A :class:`Target` is built from a URL (``-u``) or a
  raw HTTP request file (``-r``, SSRFmap parity). The injection point is
  explicitly markable -- a ``--marker`` token placed anywhere (query / header /
  body / path), or a named ``--param`` query parameter.
* **Detect + confirm.** For each internal SSRF target (an OOB canary and/or the
  cloud-metadata URLs) the filter-bypass :mod:`wraith.mutators` catalog is
  generated, each variant is injected at the marked point and dispatched through
  the scope-enforced :class:`~scan_primitives.ScanClient`, and the response is
  classified: a cloud-metadata credential/identity signature
  (:func:`wraith.metadata.detect_from_response`) confirms via response
  signature, while an OOB callback confirms blind SSRF (DNS-only still counts).
* **Async/concurrent (#7).** Requests run under an ``asyncio.Semaphore``.

R5: response bytes are DATA -- classified by substring match, captured as
evidence, never evaluated.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from scan_primitives import OutOfScopeError

from wraith.client import ScanClient, get_client
from wraith.findings import CWE_SSRF, Finding
from wraith.metadata import detect_from_response
from wraith.mcp import detect_mcp_server_response, mcp_ssrf_urls
from wraith.mutators import Variant, build_variants
from wraith.oob import Canary, Collaborator

__all__ = ["InjectionPoint", "Target", "parse_http_request", "run_scan", "METADATA_SSRF_URLS"]

# Internal metadata URLs injected via the SSRF primitive (the app fetches them
# and may echo the body back). Header-gated providers (GCP/Azure) are included
# but only return data when the SSRF also controls headers; AWS-v1/Alibaba/DO
# expose data to a plain URL fetch.
METADATA_SSRF_URLS: list[tuple[str, str]] = [
    ("aws", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("alibaba", "http://100.100.100.200/latest/meta-data/ram/security-credentials/"),
    ("digitalocean", "http://169.254.169.254/metadata/v1.json"),
    ("gcp", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    ("azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("oracle", "http://192.0.0.192/opc/v2/instance/"),
]


@dataclass(frozen=True, slots=True)
class InjectionPoint:
    """Where the payload goes.

    kind: ``"marker"`` (replace a token anywhere) | ``"query"`` (a named query
    param). name: the marker token or the query-param name.
    """

    kind: str
    name: str

    def vector(self) -> str:
        return f"{self.kind}:{self.name}"


@dataclass(slots=True)
class Target:
    """A parsed request + injection point; produces concrete requests per payload."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    injection: InjectionPoint = field(default_factory=lambda: InjectionPoint("marker", "FUZZ"))

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        method: str = "GET",
        marker: str = "FUZZ",
        param: str | None = None,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> "Target":
        if param:
            injection = InjectionPoint("query", param)
        else:
            injection = InjectionPoint("marker", marker)
        return cls(method, url, dict(headers or {}), body, injection)

    @classmethod
    def from_request_file(
        cls,
        path: str,
        *,
        marker: str = "FUZZ",
        param: str | None = None,
        scheme: str = "http",
    ) -> "Target":
        text = open(path, "r", encoding="utf-8", errors="replace").read()
        method, url, headers, body = parse_http_request(text, scheme=scheme)
        injection = (
            InjectionPoint("query", param) if param else InjectionPoint("marker", marker)
        )
        return cls(method, url, headers, body, injection)

    def build_request(self, payload: str) -> tuple[str, str, dict[str, str], str | None]:
        """Return ``(method, url, headers, body)`` with ``payload`` injected."""
        if self.injection.kind == "query":
            return self.method, _set_query_param(self.url, self.injection.name, payload), dict(self.headers), self.body
        # marker: replace the token everywhere it appears.
        token = self.injection.name
        url = self.url.replace(token, payload)
        headers = {k: v.replace(token, payload) for k, v in self.headers.items()}
        body = self.body.replace(token, payload) if self.body is not None else None
        return self.method, url, headers, body


def _set_query_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return urlunsplit(parts._replace(query=urlencode(pairs)))


def parse_http_request(
    text: str, *, scheme: str = "http"
) -> tuple[str, str, dict[str, str], str | None]:
    """Parse a raw HTTP request (SSRFmap parity) into (method, url, headers, body).

    The absolute URL is reconstructed from the ``Host`` header + request-target;
    ``:443`` in Host upgrades the scheme to https. The request-target may already
    be absolute (``http://...``), in which case it is used verbatim.
    """
    normalized = text.replace("\r\n", "\n")
    head, _, body = normalized.partition("\n\n")
    lines = head.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("empty request file")
    request_line = lines[0].split()
    if len(request_line) < 2:
        raise ValueError(f"malformed request line: {lines[0]!r}")
    method, target = request_line[0], request_line[1]

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip()] = value.strip()

    if "://" in target:
        url = target
    else:
        host = headers.get("Host") or headers.get("host") or ""
        use_scheme = "https" if host.endswith(":443") else scheme
        url = f"{use_scheme}://{host}{target}"

    return method, url, headers, (body if body else None)


# --------------------------------------------------------------------------- #
# Finding builders
# --------------------------------------------------------------------------- #

def _fid(*parts: str) -> str:
    return "wraith-" + hashlib.sha1("|".join(parts).encode()).hexdigest()[:10]


def _signature_finding(
    target: Target, variant: Variant, provider: str, matched: tuple[str, ...], severity: str
) -> Finding:
    vector = target.injection.vector()
    return Finding(
        id=_fid("sig", provider, vector),
        tool="wraith",
        title=f"SSRF to {provider.upper()} metadata via {vector} injection point",
        severity=severity,
        confidence="high",
        target=target.url,
        vector=vector,
        variant=f"{variant.name}",
        cwe_id=CWE_SSRF,
        evidence={
            "provider": provider,
            "injected_payload": variant.value,
            "response_signature": f"matched {', '.join(matched)} (secret values not stored)",
        },
        references=["https://cwe.mitre.org/data/definitions/918.html"],
    )


def _mcp_server_finding(target: Target, variant: Variant, internal_url: str) -> Finding:
    vector = target.injection.vector()
    return Finding(
        id=_fid("mcp-server", internal_url, vector),
        tool="wraith",
        title=f"SSRF reaches internal MCP server at {internal_url}",
        severity="high",
        confidence="medium",
        target=target.url,
        vector=vector,
        variant=variant.name,
        cwe_id=CWE_SSRF,
        evidence={
            "internal_url": internal_url,
            "injected_payload": variant.value,
            "detection": "MCP protocol signatures matched in echoed response",
        },
        references=[
            "https://cwe.mitre.org/data/definitions/918.html",
            "https://modelcontextprotocol.io/specification",
        ],
    )


def _oob_finding(target: Target, variant: Variant, canary: Canary, oob_result) -> Finding:
    vector = target.injection.vector()
    flag = " (HTTP egress likely filtered)" if oob_result.http_egress_filtered else ""
    return Finding(
        id=_fid("oob", canary.token),
        tool="wraith",
        title=f"Confirmed blind SSRF via {vector} injection point{flag}",
        severity="high",
        confidence="high",
        target=target.url,
        vector=vector,
        variant=variant.name,
        cwe_id=CWE_SSRF,
        evidence={
            "injected_payload": variant.value,
            "oob_protocol": oob_result.protocol,
            "canary": canary.host,
        },
        oob_proof=oob_result.proof,
        references=["https://cwe.mitre.org/data/definitions/918.html"],
    )


# --------------------------------------------------------------------------- #
# The scan loop
# --------------------------------------------------------------------------- #

async def run_scan(
    target: Target,
    scope,
    *,
    rate_limit: float | None = None,
    proxy: str | None = None,
    timeout: float = 10.0,
    concurrency: int = 10,
    cloud_metadata: bool = False,
    mcp_discovery: bool = False,
    mcp_discovery_host: str = "127.0.0.1",
    mcp_discovery_port: int | None = None,
    collaborator: Collaborator | None = None,
    extra_targets: list[tuple[str, str]] | None = None,
    client: ScanClient | None = None,
    oob_timeout: float = 5.0,
) -> list[Finding]:
    """Run the SSRF detect+confirm scan and return deduped findings.

    Builds internal SSRF targets (an OOB canary if a collaborator is given, plus
    the cloud-metadata URLs when ``cloud_metadata`` is set, plus MCP server
    discovery paths when ``mcp_discovery`` is set, plus any ``extra_targets``),
    mutates each into the filter-bypass catalog, injects and dispatches every
    variant concurrently, and classifies responses. Then polls the collaborator
    for OOB callbacks. ``client`` may be injected (tests); otherwise one is
    constructed from ``scope``.

    Args:
        mcp_discovery: When True, inject MCP well-known paths at
            ``mcp_discovery_host``/``mcp_discovery_port`` as internal SSRF
            targets. Responses are classified by :func:`wraith.mcp.detect_mcp_server_response`.
        mcp_discovery_host: Internal host to probe for MCP servers (default: 127.0.0.1).
        mcp_discovery_port: TCP port for the MCP discovery host (default: None → no port).
    """
    # 1) Assemble internal targets: (label, url, canary|None).
    targets: list[tuple[str, str, Canary | None]] = []
    canary: Canary | None = None
    if collaborator is not None:
        canary = collaborator.new_canary()
        targets.append(("oob-canary", canary.url, canary))
    if cloud_metadata:
        targets += [(f"metadata-{p}", url, None) for p, url in METADATA_SSRF_URLS]
    if mcp_discovery:
        targets += [
            (label, url, None)
            for label, url in mcp_ssrf_urls(mcp_discovery_host, mcp_discovery_port)
        ]
    for label, url in extra_targets or []:
        targets.append((label, url, None))
    if not targets:
        # No confirmation channel selected: still exercise the mutator engine
        # against a loopback baseline so a bare `scan` does something meaningful.
        targets.append(("loopback", "http://127.0.0.1/", None))

    # 2) Build the (variant, internal_url, canary) work list.
    work: list[tuple[Variant, str, Canary | None]] = []
    decoy = target.host or "localhost"
    for _label, url, tgt_canary in targets:
        for variant in build_variants(url, decoy=decoy):
            work.append((variant, url, tgt_canary))

    own_client = client is None
    client = client or get_client(scope, rate_limit=rate_limit, proxy=proxy, timeout=timeout)
    sem = asyncio.Semaphore(max(1, concurrency))
    findings: dict[str, Finding] = {}

    async def _dispatch(variant: Variant, internal_url: str) -> None:
        method, url, headers, body = target.build_request(variant.value)
        try:
            async with sem:
                resp = await client.request(method, url, headers=headers or None, content=body)
        except OutOfScopeError:
            return  # payload steered the request out of scope; skip (no egress)
        except Exception:
            return  # transport error against this variant; try the rest
        hit = detect_from_response(resp.text)
        if hit is not None:
            provider, matched, severity = hit
            f = _signature_finding(target, variant, provider, matched, severity)
            findings.setdefault(f.id, f)
        if mcp_discovery and detect_mcp_server_response(resp.text):
            f = _mcp_server_finding(target, variant, internal_url)
            findings.setdefault(f.id, f)

    try:
        await asyncio.gather(*(_dispatch(v, iu) for v, iu, _c in work))

        # 3) OOB confirmation: poll for callbacks against the canary.
        if collaborator is not None and canary is not None:
            result = collaborator.wait_for(canary.token, timeout=oob_timeout)
            if result.confirmed:
                # Attribute to the first variant that carried the canary URL.
                variant = next(
                    (v for v, _iu, c in work if c is canary), work[0][0] if work else None
                )
                if variant is not None:
                    f = _oob_finding(target, variant, canary, result)
                    findings.setdefault(f.id, f)
    finally:
        if own_client:
            await client.aclose()

    return sorted(findings.values(), key=lambda f: f.id)
