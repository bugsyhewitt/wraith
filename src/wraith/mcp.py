"""MCP / AI-infra SSRF detection catalog (V0.1-CRITERIA.md #6).

Five curated, **version-gated** detection signatures for the emerging MCP /
AI-infrastructure SSRF surface. This is deliberately **not a bespoke engine** --
each signature just describes an injection point (endpoint + URL-bearing
parameter) and reuses the shared :mod:`wraith.engine` injection loop, the
:mod:`wraith.oob` confirmation, and the :class:`wraith.findings.Finding` schema.

The five (version-gated + cited; some are unpatched / 2026-dated):

1. **Fetch MCP** (CVE-2025-65513) -- the ``fetch`` tool retrieves an arbitrary
   ``url``.
2. **Microsoft MarkItDown MCP** -- converts a source ``uri`` to markdown; the
   fetch is attacker-controlled.
3. **MCP-Atlassian** (CVE-2026-27826) -- server-side fetch of a supplied ``url``.
4. **LiteLLM** ``/v1/rag/ingest`` -- ingests a JSON ``file_url`` server-side.
5. **LangChain ``RecursiveUrlLoader``** (CVE-2026-26019 / CVE-2026-27795) --
   recursively loads a supplied ``url``.

The endpoint paths are the commonly HTTP-exposed form of each sink; the durable
value is the version gate + CVE citation + the URL-bearing parameter, all of
which flow into the finding. R5: nothing here evaluates fetched content.
"""

from __future__ import annotations

from dataclasses import dataclass

from wraith.engine import InjectionPoint, Target, run_scan
from wraith.findings import Finding
from wraith.oob import Collaborator

__all__ = [
    "McpSignature",
    "MCP_CATALOG",
    "version_affected",
    "applicable",
    "mcp_target",
    "scan_mcp",
]


@dataclass(frozen=True, slots=True)
class McpSignature:
    """One version-gated MCP/AI-infra SSRF signature."""

    id: str
    name: str
    method: str
    path: str
    param: str
    param_in: str  # "query" | "json"
    affected: str  # version spec, e.g. "<0.6.3" or ">=0.1,<0.3" or "*"
    patched_in: str | None
    cve: tuple[str, ...]
    references: tuple[str, ...]
    notes: str = ""


MCP_CATALOG: list[McpSignature] = [
    McpSignature(
        id="fetch-mcp",
        name="Fetch MCP server (fetch tool)",
        method="GET",
        path="/fetch",
        param="url",
        param_in="query",
        affected="<0.6.3",
        patched_in="0.6.3",
        cve=("CVE-2025-65513",),
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2025-65513",
            "https://cwe.mitre.org/data/definitions/918.html",
        ),
        notes="The fetch tool retrieves an attacker-controlled URL server-side.",
    ),
    McpSignature(
        id="markitdown-mcp",
        name="Microsoft MarkItDown MCP",
        method="POST",
        path="/convert",
        param="uri",
        param_in="json",
        affected="*",
        patched_in=None,
        cve=(),
        references=(
            "https://github.com/microsoft/markitdown",
            "https://cwe.mitre.org/data/definitions/918.html",
        ),
        notes="Converts a source URI to markdown; the fetch is server-side and unauthenticated.",
    ),
    McpSignature(
        id="mcp-atlassian",
        name="MCP-Atlassian",
        method="GET",
        path="/fetch",
        param="url",
        param_in="query",
        affected="<0.11.0",
        patched_in="0.11.0",
        cve=("CVE-2026-27826",),
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2026-27826",
            "https://cwe.mitre.org/data/definitions/918.html",
        ),
        notes="Server-side fetch of a supplied URL (Confluence/Jira attachment retrieval).",
    ),
    McpSignature(
        id="litellm-rag-ingest",
        name="LiteLLM /v1/rag/ingest file_url",
        method="POST",
        path="/v1/rag/ingest",
        param="file_url",
        param_in="json",
        affected="<1.53.0",
        patched_in="1.53.0",
        cve=(),
        references=(
            "https://github.com/BerriAI/litellm",
            "https://cwe.mitre.org/data/definitions/918.html",
        ),
        notes="Ingests a JSON file_url server-side without egress restriction.",
    ),
    McpSignature(
        id="langchain-recursiveurlloader",
        name="LangChain RecursiveUrlLoader",
        method="GET",
        path="/load",
        param="url",
        param_in="query",
        affected="<0.3.14",
        patched_in="0.3.14",
        cve=("CVE-2026-26019", "CVE-2026-27795"),
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2026-26019",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-27795",
            "https://cwe.mitre.org/data/definitions/918.html",
        ),
        notes="Recursively loads a supplied URL; SSRF into internal hosts.",
    ),
]


def _ver(text: str) -> tuple[int, ...]:
    """Parse ``0.6.3`` / ``1.53.0a`` into a comparable int tuple."""
    parts: list[int] = []
    for chunk in text.strip().split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _cmp(op: str, left: tuple[int, ...], right: tuple[int, ...]) -> bool:
    if op == "<":
        return left < right
    if op == "<=":
        return left <= right
    if op == ">":
        return left > right
    if op == ">=":
        return left >= right
    if op == "==":
        return left == right
    raise ValueError(f"unknown version operator {op!r}")


def version_affected(version: str | None, spec: str) -> bool:
    """Is ``version`` covered by ``spec`` (comma-separated constraints, AND-ed)?

    ``spec="*"`` matches everything. A ``None`` version is treated as *affected*
    (unknown -> cannot rule out) so an un-fingerprinted target is still probed.
    """
    if spec.strip() == "*":
        return True
    if version is None:
        return True
    ver = _ver(version)
    for constraint in spec.split(","):
        constraint = constraint.strip()
        for op in ("<=", ">=", "==", "<", ">"):
            if constraint.startswith(op):
                if not _cmp(op, ver, _ver(constraint[len(op):])):
                    return False
                break
        else:
            raise ValueError(f"unparseable version constraint {constraint!r}")
    return True


def applicable(version: str | None = None) -> list[McpSignature]:
    """Signatures whose version gate admits ``version`` (all, if ``version`` None)."""
    return [s for s in MCP_CATALOG if version_affected(version, s.affected)]


def mcp_target(sig: McpSignature, base_url: str, *, marker: str = "FUZZ") -> Target:
    """Build the injection :class:`Target` for a signature against ``base_url``."""
    base = base_url.rstrip("/")
    url = f"{base}{sig.path}"
    if sig.param_in == "query":
        return Target.from_url(url, method=sig.method, param=sig.param)
    # json body: inject via a marker inside a JSON template.
    body = f'{{"{sig.param}": "{marker}"}}'
    return Target(
        method=sig.method,
        url=url,
        headers={"Content-Type": "application/json"},
        body=body,
        injection=InjectionPoint("marker", marker),
    )


async def scan_mcp(
    base_url: str,
    scope,
    *,
    collaborator: Collaborator | None = None,
    version: str | None = None,
    cloud_metadata: bool = False,
    concurrency: int = 10,
    oob_timeout: float = 5.0,
    client=None,
) -> list[Finding]:
    """Run the applicable MCP signatures against ``base_url`` and tag findings.

    Each signature reuses :func:`wraith.engine.run_scan` (mutators + OOB +
    metadata detection); resulting findings are annotated with the MCP signature
    id and CVE(s).
    """
    from wraith.client import get_client

    own = client is None
    client = client or get_client(scope)
    findings: list[Finding] = []
    try:
        for sig in applicable(version):
            target = mcp_target(sig, base_url)
            sig_findings = await run_scan(
                target,
                scope,
                collaborator=collaborator,
                cloud_metadata=cloud_metadata,
                concurrency=concurrency,
                oob_timeout=oob_timeout,
                client=client,
            )
            for f in sig_findings:
                f.evidence["mcp_signature"] = sig.id
                if sig.cve:
                    f.evidence["cve"] = list(sig.cve)
                for ref in sig.references:
                    if ref not in f.references:
                        f.references.append(ref)
                findings.append(f)
    finally:
        if own:
            await client.aclose()
    return findings
