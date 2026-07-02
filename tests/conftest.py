"""Shared pytest fixtures for wraith.

Scaffolding pass: the fixtures here are finding-shaped, not target-shaped -- the
hermetic HTTP/DNS fixture servers described in V0.1-CRITERIA.md "Testability"
(respx, pytest-httpserver, an in-process dnslib OOB listener) arrive with the
v0.1 detection build. What is wired now:

* an autouse egress lock (criteria "Testability > Enforcement"): if
  ``pytest-socket`` is installed (it is in the ``dev``/``test`` extra) all
  non-ship_gate tests run with sockets disabled so any accidental real network
  call fails loudly. The lock is a no-op when pytest-socket is absent, so the
  finding/SARIF/h1md unit tests still run on a bare ``pip install pytest``.
* sample :class:`wraith.findings.Finding` fixtures for the adapter tests.
"""

from __future__ import annotations

import pytest

from wraith.findings import Finding

try:  # pytest-socket is an opt-in dev/test dependency.
    import pytest_socket

    _HAVE_PYTEST_SOCKET = True
except ImportError:  # pragma: no cover - exercised only on a bare install
    _HAVE_PYTEST_SOCKET = False


@pytest.fixture(autouse=True)
def _egress_lock(request: pytest.FixtureRequest):
    """Disable real sockets on the unit tier (criteria: enforce no egress).

    ship_gate tests build/install in subprocesses and are exempt. Unix sockets
    stay allowed so subprocess/IPC machinery is unaffected.
    """
    if request.node.get_closest_marker("ship_gate") or not _HAVE_PYTEST_SOCKET:
        yield
        return
    pytest_socket.disable_socket(allow_unix_socket=True)
    try:
        yield
    finally:
        pytest_socket.enable_socket()


@pytest.fixture
def sample_finding() -> Finding:
    """A representative CONFIRMED cloud-metadata SSRF finding."""
    return Finding(
        id="wraith-0001",
        tool="wraith",
        title="SSRF to AWS IMDS via url query parameter",
        severity="high",
        confidence="high",
        target="https://app.example.com/proxy?url=http://169.254.169.254/latest/meta-data/",
        vector="query:url",
        variant="dword-decimal:2852039166",
        evidence={
            "request": "GET /proxy?url=http://2852039166/latest/meta-data/ HTTP/1.1",
            "response_signature": "iam/security-credentials/",
        },
        oob_proof="dns:wr41th-a1b2c3.oob.example.net",
        references=[
            "https://cwe.mitre.org/data/definitions/918.html",
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html",
        ],
    )


@pytest.fixture
def sample_findings(sample_finding: Finding) -> list[Finding]:
    """A small mixed-severity batch for adapter/ordering assertions."""
    blind = Finding(
        id="wraith-0002",
        tool="wraith",
        title="Blind SSRF via Location redirect header",
        severity="medium",
        confidence="medium",
        target="https://app.example.com/webhook",
        vector="header:Location",
        oob_proof="dns:wr41th-d4e5f6.oob.example.net",
    )
    low = Finding(
        id="wraith-0003",
        tool="wraith",
        title="Open dict:// port probe response-time delta",
        severity="low",
        confidence="low",
        target="https://app.example.com/fetch",
        vector="query:target",
    )
    return [sample_finding, blind, low]
