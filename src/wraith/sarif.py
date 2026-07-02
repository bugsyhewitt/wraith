"""SARIF 2.1.0 output for wraith.

SARIF (Static Analysis Results Interchange Format) is the standard machine
output for security scanners: GitHub's Security tab, the VS Code Problems panel,
and most CI SAST dashboards ingest it natively. Emitting SARIF lets wraith
findings appear alongside professional SAST tooling.

This module mirrors the shape ferryman/autopsy/ossuary already ship (``$schema``,
``version``, ``runs[].tool.driver{name, version, rules}``, ``results[]``) and
follows the adapter contract pinned in ``projects/scan-primitives/SPEC.md``:

* ``severity`` -> SARIF ``level`` (``critical`` / ``high`` -> ``error``,
  ``medium`` -> ``warning``, ``low`` / ``info`` -> ``note``);
* a 0-100 ``rank`` so consumers order findings the way wraith does;
* ``ruleId = "<tool>/<vector-class>"`` (the vector class is the injection-point
  family -- the token before the first ``:`` in ``vector``, e.g. ``query``);
* ``partialFingerprints`` seeded from the finding ``id`` for stable dedupe;
* ``result.locations`` built from the finding ``target``.

[Worker decision: unlike ferryman's ``to_sarif`` (which returns a JSON *string*),
this returns a ``dict`` -- the pinned contract in SPEC.md specifies
``to_sarif(findings) -> dict``. Callers that need bytes ``json.dumps`` the dict
themselves. This keeps the return value composable and directly assertable in
tests.]
"""

from __future__ import annotations

from typing import Any, Iterable

from wraith import __version__
from wraith.findings import Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemas/sarif-schema-2.1.0.json"
)

_INFORMATION_URI = "https://github.com/bugsyhewitt/wraith"

# wraith severity -> SARIF result.level (the coarse SARIF enum).
_LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# wraith severity -> SARIF rank (0.0..100.0; higher = more severe).
_RANK_BY_SEVERITY = {
    "critical": 100.0,
    "high": 80.0,
    "medium": 50.0,
    "low": 20.0,
    "info": 5.0,
}


def _level_for(severity: str) -> str:
    return _LEVEL_BY_SEVERITY.get(severity, "warning")


def _rank_for(severity: str) -> float:
    return _RANK_BY_SEVERITY.get(severity, 50.0)


def _vector_class(f: Finding) -> str:
    """The injection-point family: the token before the first ``:`` in vector.

    ``"query:url"`` -> ``"query"``, ``"header:X-Forwarded-For"`` -> ``"header"``,
    a bare ``"path"`` -> ``"path"``. Empty vectors fall back to ``"unknown"``.
    """
    vector = f.vector or ""
    head = vector.split(":", 1)[0].strip()
    return head or "unknown"


def _rule_id(f: Finding) -> str:
    """Stable rule id: ``<tool>/<vector-class>`` (e.g. ``wraith/query``)."""
    return f"{f.tool}/{_vector_class(f)}"


def _result_for(f: Finding) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "severity": f.severity,
        "confidence": f.confidence,
        "vector": f.vector,
    }
    if f.variant is not None:
        properties["variant"] = f.variant
    if f.cwe_id is not None:
        properties["cwe"] = f.cwe_id
    if f.oob_proof is not None:
        properties["oob_proof"] = f.oob_proof
    if f.references:
        properties["references"] = list(f.references)
    if f.evidence:
        properties["evidence"] = dict(f.evidence)

    return {
        "ruleId": _rule_id(f),
        "level": _level_for(f.severity),
        "rank": _rank_for(f.severity),
        "message": {"text": f.title or _rule_id(f)},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": f.target}}}
        ],
        "partialFingerprints": {"wraithFindingId/v1": f.id},
        "properties": properties,
    }


def _rules_for(findings: list[Finding]) -> list[dict[str, Any]]:
    """One SARIF reportingDescriptor per distinct rule id, sorted for stability."""
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(_rule_id(f), f)
    rules: list[dict[str, Any]] = []
    for rule_id in sorted(seen):
        f = seen[rule_id]
        rule: dict[str, Any] = {
            "id": rule_id,
            "name": rule_id.replace("/", "_"),
            "shortDescription": {
                "text": f"{f.tool} SSRF finding via {_vector_class(f)} injection point"
            },
            "defaultConfiguration": {"level": _level_for(f.severity)},
            "properties": {"vector_class": _vector_class(f)},
        }
        if f.cwe_id is not None:
            # SARIF taxa/relationships would be richer; a properties tag keeps the
            # CWE anchor discoverable without pulling in the taxonomy machinery.
            rule["properties"]["cwe"] = f.cwe_id
        rules.append(rule)
    return rules


def to_sarif(findings: Iterable[Finding]) -> dict[str, Any]:
    """Render wraith findings to a SARIF 2.1.0 document (as a ``dict``)."""
    findings = list(findings)
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wraith",
                        "version": __version__,
                        "informationUri": _INFORMATION_URI,
                        "rules": _rules_for(findings),
                    }
                },
                "results": [_result_for(f) for f in findings],
            }
        ],
    }
