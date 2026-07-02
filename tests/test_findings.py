"""Tests for the pinned Finding contract and its two suite adapters.

These are the real, passing unit tests for the scaffolding pass (V0.1-CRITERIA.md
"Testability > Tier 0"). They pin three things:

1. :class:`wraith.findings.Finding` construction + validation against the pinned
   contract in projects/scan-primitives/SPEC.md (lowercase severity, confidence,
   cwe_id default 918, all fields, round-trip).
2. Finding -> SARIF 2.1.0 shape (:func:`wraith.sarif.to_sarif` returns a dict).
3. Finding -> HackerOne markdown round-trip (:func:`wraith.reporting.to_h1md`).
"""

from __future__ import annotations

import dataclasses

import pytest

from wraith import __version__
from wraith.findings import CONFIDENCES, CWE_SSRF, SEVERITIES, Finding
from wraith.reporting import to_h1md
from wraith.sarif import SARIF_VERSION, to_sarif

# --- Finding construction + validation -----------------------------------


def test_severities_and_confidences_are_pinned():
    # Lowercase h1-reporter taxonomy, ordered low -> high.
    assert SEVERITIES == ("info", "low", "medium", "high", "critical")
    assert CONFIDENCES == ("low", "medium", "high")


def test_finding_defaults_match_contract(sample_finding: Finding):
    # cwe_id defaults to 918 (SSRF) when not overridden.
    minimal = Finding(
        id="x",
        tool="wraith",
        title="t",
        severity="info",
        confidence="low",
        target="https://h/",
        vector="query:url",
    )
    assert minimal.cwe_id == CWE_SSRF == 918
    assert minimal.variant is None
    assert minimal.oob_proof is None
    assert minimal.evidence == {}
    assert minimal.references == []
    # created_at is auto-populated as an ISO-8601 string.
    assert isinstance(minimal.created_at, str) and minimal.created_at


def test_finding_has_all_contract_fields():
    field_names = {f.name for f in dataclasses.fields(Finding)}
    assert field_names == {
        "id",
        "tool",
        "title",
        "severity",
        "confidence",
        "target",
        "vector",
        "variant",
        "cwe_id",
        "evidence",
        "oob_proof",
        "references",
        "created_at",
    }


def test_finding_rejects_bad_severity():
    with pytest.raises(ValueError):
        Finding(
            id="x",
            tool="wraith",
            title="t",
            severity="HIGH",  # wrong case -> invalid; taxonomy is lowercase
            confidence="high",
            target="https://h/",
            vector="query:url",
        )


def test_finding_rejects_bad_confidence():
    with pytest.raises(ValueError):
        Finding(
            id="x",
            tool="wraith",
            title="t",
            severity="high",
            confidence="certain",  # not in CONFIDENCES
            target="https://h/",
            vector="query:url",
        )


def test_finding_round_trips_through_dict(sample_finding: Finding):
    rebuilt = Finding(**sample_finding.to_dict())
    assert rebuilt == sample_finding


def test_is_confirmed_tracks_oob_proof(sample_finding: Finding):
    assert sample_finding.is_confirmed() is True
    blind = Finding(
        id="y",
        tool="wraith",
        title="t",
        severity="medium",
        confidence="low",
        target="https://h/",
        vector="query:url",
    )
    assert blind.is_confirmed() is False


# --- Finding -> SARIF 2.1.0 ------------------------------------------------


def test_to_sarif_returns_dict_envelope():
    doc = to_sarif([])
    assert isinstance(doc, dict)  # contract: to_sarif -> dict, not a JSON string
    assert doc["version"] == SARIF_VERSION == "2.1.0"
    assert "$schema" in doc and "sarif" in doc["$schema"]
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "wraith"
    assert driver["version"] == __version__
    # No findings -> no results and no rules.
    assert doc["runs"][0]["results"] == []
    assert driver["rules"] == []


def test_to_sarif_result_count_matches_findings(sample_findings: list[Finding]):
    doc = to_sarif(sample_findings)
    assert len(doc["runs"][0]["results"]) == len(sample_findings)


def test_to_sarif_severity_maps_to_level_and_rank():
    findings = [
        Finding(id="1", tool="wraith", title="c", severity="critical", confidence="high", target="h", vector="query:a"),
        Finding(id="2", tool="wraith", title="h", severity="high", confidence="high", target="h", vector="query:b"),
        Finding(id="3", tool="wraith", title="m", severity="medium", confidence="medium", target="h", vector="query:c"),
        Finding(id="4", tool="wraith", title="l", severity="low", confidence="low", target="h", vector="query:d"),
        Finding(id="5", tool="wraith", title="i", severity="info", confidence="low", target="h", vector="query:e"),
    ]
    results = to_sarif(findings)["runs"][0]["results"]
    assert [r["level"] for r in results] == ["error", "error", "warning", "note", "note"]
    ranks = [r["rank"] for r in results]
    assert ranks == sorted(ranks, reverse=True)  # monotonic, highest first
    assert all(0 <= r["rank"] <= 100 for r in results)
    assert [r["properties"]["severity"] for r in results] == [
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ]


def test_to_sarif_rule_id_is_tool_slash_vector_class(sample_finding: Finding):
    doc = to_sarif([sample_finding])
    result = doc["runs"][0]["results"][0]
    # vector "query:url" -> vector-class "query" -> ruleId "wraith/query".
    assert result["ruleId"] == "wraith/query"
    declared = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert result["ruleId"] in declared


def test_to_sarif_rule_per_distinct_rule_id(sample_findings: list[Finding]):
    doc = to_sarif(sample_findings)
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    # query:url + query:target share the "query" class; header:Location is its own.
    assert rule_ids == {"wraith/query", "wraith/header"}


def test_to_sarif_fingerprint_and_location_from_finding(sample_finding: Finding):
    result = to_sarif([sample_finding])["runs"][0]["results"][0]
    assert result["partialFingerprints"]["wraithFindingId/v1"] == sample_finding.id
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == sample_finding.target
    # The CWE anchor and OOB proof survive into properties.
    assert result["properties"]["cwe"] == 918
    assert result["properties"]["oob_proof"] == sample_finding.oob_proof


# --- Finding -> HackerOne markdown ----------------------------------------


def test_to_h1md_round_trips_finding_detail(sample_finding: Finding):
    md = to_h1md([sample_finding])
    assert isinstance(md, str)
    assert md.startswith("# wraith SSRF findings")
    assert "**Total findings:** 1" in md
    assert f"## Finding 1: {sample_finding.title}" in md
    assert "**Severity:** HIGH" in md  # h1-reporter upper-cases severity
    assert sample_finding.target in md
    assert sample_finding.variant in md
    # OOB proof + response signature evidence make it into the report body.
    assert sample_finding.oob_proof in md
    assert "iam/security-credentials/" in md
    # CWE-918 impact framing is present.
    assert "CWE-918" in md


def test_to_h1md_orders_by_severity(sample_findings: list[Finding]):
    md = to_h1md(sample_findings)
    # Most-severe first: high before medium before low.
    assert md.index("## Finding 1:") < md.index("## Finding 2:") < md.index("## Finding 3:")
    high_pos = md.index("SSRF to AWS IMDS")
    low_pos = md.index("Open dict:// port probe")
    assert high_pos < low_pos


def test_to_h1md_empty_reports_zero():
    md = to_h1md([])
    assert "**Total findings:** 0" in md
    assert "_No findings._" in md
    assert md.endswith("\n") and not md.endswith("\n\n")
