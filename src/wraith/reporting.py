"""HackerOne-markdown output for wraith, built on the shared h1-reporter lib.

wraith's internal :class:`wraith.findings.Finding` is SSRF-shaped (target /
vector / variant / evidence / oob_proof). The HackerOne submission body is not
wraith's concern -- that formatting lives in the suite-wide ``h1_reporter``
library so every necromancer tool produces a consistent report. This module is
the thin adapter that maps a wraith finding into an ``h1_reporter.Finding``,
exactly as ferryman's ``reporting.py`` does (wraith is the suite's second real
h1-reporter adopter, per the pinned contract in scan-primitives/SPEC.md).
"""

from __future__ import annotations

from typing import Iterable

from h1_reporter import Finding as H1Finding
from h1_reporter import render_h1md

from wraith.findings import Finding

# Business-impact framing for the SSRF surface, keyed by injection-point family
# (the token before the first ``:`` in a finding's vector). SSRF's impact is the
# reach it grants into otherwise-unreachable internal surface.
_IMPACT_DEFAULT = (
    "Server-Side Request Forgery (CWE-918) lets an attacker coerce the server "
    "into making requests to attacker-chosen destinations. Depending on network "
    "position this reaches cloud metadata endpoints (credential theft), internal "
    "services, and localhost-only admin surfaces that are otherwise unreachable."
)
_IMPACT_BY_VECTOR_CLASS = {
    "header": (
        "An SSRF primitive that controls request headers can complete "
        "token-gated metadata handshakes (e.g. AWS IMDSv2 PUT-then-GET), broadening "
        "the blast radius from blind fetch to credential disclosure."
    ),
}


def _vector_class(vector: str) -> str:
    return (vector or "").split(":", 1)[0].strip() or "unknown"


def _describe(f: Finding) -> str:
    """Prose description of the finding for the report body."""
    parts = [f"SSRF reached `{f.target}` via the `{f.vector}` injection point."]
    if f.variant:
        parts.append(f"Filter-bypass variant: `{f.variant}`.")
    if f.oob_proof:
        parts.append(
            "Confirmed out-of-band -- the server initiated a callback to the "
            "wraith canary (see evidence), proving the request left the host."
        )
    else:
        parts.append("Classified blind (no out-of-band callback observed).")
    return " ".join(parts)


def _reproduction_steps(f: Finding) -> list[str]:
    steps = [
        f"Issue the request to `{f.target}` with the payload placed at the "
        f"`{f.vector}` injection point"
        + (f" using variant `{f.variant}`." if f.variant else "."),
    ]
    if f.oob_proof:
        steps.append(
            "Observe the out-of-band interaction recorded against the canary "
            f"token: {f.oob_proof}."
        )
    steps.append("Compare the response signature against the evidence captured below.")
    return steps


def _evidence_blocks(f: Finding) -> list[str]:
    """Render the evidence dict (+ oob proof) as fenced-code-block strings.

    R5: this content is untrusted response data captured for the report -- it is
    formatted as text, never evaluated.
    """
    blocks: list[str] = []
    if f.evidence:
        blocks.append("\n".join(f"{key}: {value}" for key, value in f.evidence.items()))
    if f.oob_proof:
        blocks.append(f"OOB proof: {f.oob_proof}")
    return blocks


def _to_h1_finding(f: Finding) -> H1Finding:
    """Map one wraith finding into the shared h1_reporter Finding shape."""
    impact = _IMPACT_BY_VECTOR_CLASS.get(_vector_class(f.vector), _IMPACT_DEFAULT)
    return H1Finding(
        title=f.title,
        severity=f.severity,
        description=_describe(f),
        reproduction_steps=_reproduction_steps(f),
        business_impact=impact,
        evidence=_evidence_blocks(f),
    )


def to_h1md(findings: Iterable[Finding]) -> str:
    """Render wraith findings to HackerOne-flavored markdown."""
    mapped = [_to_h1_finding(f) for f in findings]
    return render_h1md(mapped, title="wraith SSRF findings")
