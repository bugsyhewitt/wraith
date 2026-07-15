"""Structured finding model for wraith.

A :class:`Finding` is the single unit of output every wraith check emits. It
implements the **pinned Finding contract** shared across the three new offensive
tools (wraith / doppelganger / reaper) so that when the schema is later extracted
into a dedicated ``web-finding-schema`` library the move is a rename, not a
rewrite. The authoritative shape lives (temporarily) in the appendix of
``projects/scan-primitives/SPEC.md``; this module implements it byte-for-byte.

Key contract points reproduced here:

* **Severity casing is lowercase** to match the real ``h1-reporter`` taxonomy
  (``info`` / ``low`` / ``medium`` / ``high`` / ``critical``).
* **Confidence** is ``low`` / ``medium`` / ``high``.
* ``cwe_id`` defaults to **918** (Server-Side Request Forgery) -- wraith's whole
  reason to exist. Other tools override it (request smuggling = 444,
  race condition = 362).
* ``evidence`` is a free-form ``dict`` (request summary/bytes + response
  signature). Per suite rule **R5**, evidence is *data* captured from an
  untrusted response -- it is never evaluated or executed.
* ``oob_proof`` carries the out-of-band callback token evidence (a DNS or HTTP
  interaction) that upgrades a blind SSRF to a CONFIRMED one -- wraith's primary
  differentiator over the dead-ancestor SSRFmap.

Findings serialise cleanly to JSON via :meth:`Finding.to_dict` and feed the two
suite adapters: :mod:`wraith.sarif` (SARIF 2.1.0) and :mod:`wraith.reporting`
(HackerOne markdown through ``h1-reporter``).
"""

from __future__ import annotations

import dataclasses
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

# Severity ordering, lowest to highest. Lowercase to match the h1-reporter
# taxonomy. Used for stable sorting and for validating caller input.
SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

# Confidence ordering, lowest to highest.
CONFIDENCES: tuple[str, ...] = ("low", "medium", "high")

# Type aliases mirroring the pinned contract's string-literal unions.
Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]

# CWE anchor for Server-Side Request Forgery -- the wraith default.
CWE_SSRF = 918

# Canonical reference URL for CWE-918 — use instead of inlining the string.
CWE_SSRF_REF = "https://cwe.mitre.org/data/definitions/918.html"


def _finding_id(*parts: str) -> str:
    """Stable short ID shared across wraith modules: ``wraith-<10-hex-sha1>``.

    Canonical implementation so engine, metadata, and portscan all produce
    IDs with the same algorithm. Parts are pipe-joined before hashing so
    ``_finding_id("a", "b")`` never collides with ``_finding_id("a|b")``.
    """
    return "wraith-" + hashlib.sha1("|".join(parts).encode()).hexdigest()[:10]


def _now_iso() -> str:
    """Return an ISO-8601 UTC timestamp for a freshly created finding."""
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Finding:
    """A single SSRF finding, shaped to the pinned suite Finding contract.

    Attributes:
        id: Stable identifier for this finding (unique within a run). Used as the
            SARIF ``partialFingerprints`` value so re-scans dedupe cleanly.
        tool: Emitting tool -- ``"wraith"`` here (the contract is shared with
            ``doppelganger`` and ``reaper``).
        title: Short human headline (becomes the report/SARIF message).
        severity: One of :data:`SEVERITIES` (lowercase h1-reporter taxonomy).
        confidence: One of :data:`CONFIDENCES`.
        target: The URL or host the finding is about.
        vector: The injection point / technique, e.g. ``"query:url"``,
            ``"header:X-Forwarded-For"``, ``"body:webhook"``, ``"path:0"``.
        variant: The payload / mutator variant that fired, e.g.
            ``"dword-decimal:2852039166"`` or ``None`` when not applicable.
        cwe_id: CWE identifier; defaults to :data:`CWE_SSRF` (918).
        evidence: Free-form dict of request summary/bytes + response signature.
            **R5: untrusted response data -- never evaluated.**
        oob_proof: Out-of-band callback token evidence (DNS/HTTP interaction)
            that CONFIRMS a blind SSRF, or ``None`` for a non-OOB finding.
        references: External references (CVEs, advisories, technique write-ups).
        created_at: ISO-8601 UTC creation timestamp (auto-populated).

    Raises:
        ValueError: if ``severity`` or ``confidence`` is outside the allowed set.
    """

    id: str
    tool: str
    title: str
    severity: Severity
    confidence: Confidence
    target: str
    vector: str
    variant: str | None = None
    cwe_id: int | None = CWE_SSRF
    evidence: dict[str, Any] = field(default_factory=dict)
    oob_proof: str | None = None
    references: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now_iso)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"invalid severity {self.severity!r}; expected one of {SEVERITIES}"
            )
        if self.confidence not in CONFIDENCES:
            raise ValueError(
                f"invalid confidence {self.confidence!r}; expected one of {CONFIDENCES}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict for this finding.

        Round-trips through the constructor: ``Finding(**f.to_dict())`` rebuilds
        an equal finding, which keeps SARIF/h1md/JSON emission and multi-file
        re-attribution lossless.
        """
        return dataclasses.asdict(self)

    def is_confirmed(self) -> bool:
        """True when an out-of-band interaction proves the SSRF (not blind).

        A DNS-only callback still counts as CONFIRMED per V0.1-CRITERIA.md #4.
        """
        return bool(self.oob_proof)
