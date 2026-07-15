"""SSRF-based internal port scanner (v0.6).

Probes a set of TCP ports on an internal host via SSRF injection and
classifies them using response-time and response-content differentials.

After confirming SSRF, operators typically want to discover which internal
ports are reachable through the injection point. This module automates that
recon by firing ``http://<host>:<port>/`` at the marked injection point for
each target port and classifying the results:

* **OPEN**: service banner detected in the echoed response, or response
  characteristics differ markedly from the closed-port baseline.
* **FILTERED**: the probe timed out — the SSRF sink couldn't connect
  within the configured timeout.
* **CLOSED**: fast error response consistent with TCP RST (connection
  refused).
* **UNKNOWN**: ambiguous (no banner, no clear timing signal); emitted
  as a low-confidence ``info`` finding for the operator to triage.

Classification accuracy depends on whether the SSRF sink echoes response
bodies. When it does (e.g. a ``/proxy?url=`` endpoint), banner detection
is reliable. When it doesn't, timing-based classification is approximate.

R5: response bytes are DATA — substring-matched for service banners,
never evaluated as code.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum

from scan_primitives import OutOfScopeError

from wraith.client import ScanClient, get_client
from wraith.engine import Target
from wraith.findings import CWE_SSRF, Finding

__all__ = [
    "PortState",
    "PortProbe",
    "scan_ports",
    "DEFAULT_PORTS",
    "SERVICE_BANNERS",
    "probe_url",
]

# Default port set: web, remote-access, databases, cloud-native, AI-infra.
DEFAULT_PORTS: tuple[int, ...] = (
    21, 22, 25, 80, 443,
    2375, 2376,      # Docker daemon (HTTP API)
    3306, 5432,      # MySQL, PostgreSQL
    5672, 15672,     # RabbitMQ AMQP + management UI
    6379,            # Redis
    8080, 8443, 8888,  # Alternate HTTP/HTTPS
    9000,            # FastCGI/php-fpm, SonarQube
    9200, 9300,      # Elasticsearch HTTP + transport
    10250,           # Kubernetes kubelet API
    11211,           # Memcached
    27017,           # MongoDB
)

# Service banner substrings.
# R5: these are classification literals for substring-matching, never evaluated.
SERVICE_BANNERS: tuple[str, ...] = (
    # Redis
    "redis_version", "redis_mode", "+PONG", "+OK",
    # MongoDB
    "MongoDB", "mongod", "ismaster",
    # Elasticsearch
    "elasticsearch", "cluster_name", "cluster_uuid",
    # MySQL / MariaDB
    "mysql_native_password", "MariaDB", "5.5.", "5.6.", "5.7.", "8.0.", "8.4.",
    # PostgreSQL
    "PostgreSQL", "pg_catalog", "FATAL:  ",
    # Memcached
    "STAT version", "STAT pid", "STORED",
    # RabbitMQ
    "rabbitmq", "AMQP",
    # Kubernetes kubelet
    "kubelet", "\"kind\": \"Pod\"",
    # Docker daemon
    "\"ApiVersion\"", "\"ServerVersion\"",
    # SSH
    "SSH-2.0-", "SSH-1.", "OpenSSH",
    # FTP
    "220 ", "230 ", "331 ",
    # SMTP
    "220 ESMTP", "Postfix", "Exim", "sendmail",
    # HTTP service (SSRF echoed the inner HTTP response body)
    "<html", "<!DOCTYPE", "<!doctype",
)

# Timeout value (seconds) used as a sentinel for the FILTERED classification.
# The underlying ScanClient may use a shorter timeout; if the probe completes
# at or beyond this threshold we treat it as filtered/unreachable.
_FILTERED_THRESHOLD = 0.85   # fraction of the timeout at which we call it filtered


class PortState(str, Enum):
    OPEN = "open"
    FILTERED = "filtered"
    CLOSED = "closed"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class PortProbe:
    """Result of a single port probe through the SSRF injection point."""

    port: int
    state: PortState
    elapsed: float
    status_code: int | None = None
    body_snippet: str = ""        # first 512 chars; R5 — data, not instructions
    banner_matched: str | None = None  # which banner substring matched


def probe_url(host: str, port: int) -> str:
    """Build the internal probe URL for one port."""
    return f"http://{host}:{port}/"


def _match_banner(body: str) -> str | None:
    """Return the first matching banner substring or None.

    R5: pure substring search on response data — no code evaluation.
    """
    lbody = body.lower()
    for banner in SERVICE_BANNERS:
        if banner.lower() in lbody:
            return banner
    return None


def _classify(
    elapsed: float,
    timeout: float,
    status_code: int | None,
    banner: str | None,
    baseline_elapsed: float,
) -> PortState:
    """Classify a port probe result from timing + content signals."""
    if banner is not None:
        return PortState.OPEN

    # If the probe consumed most of the timeout it was likely filtered.
    if elapsed >= timeout * _FILTERED_THRESHOLD:
        return PortState.FILTERED

    # Fast response (well under timeout) without a banner:
    # if the SSRF sink returned a 5xx quickly, the internal connection probably
    # failed with TCP RST → closed.
    if status_code is not None and status_code >= 500 and elapsed < baseline_elapsed * 1.5:
        return PortState.CLOSED

    # Non-error status on a port probe is suspicious — could be an HTTP service.
    if status_code is not None and status_code < 400:
        return PortState.OPEN

    return PortState.UNKNOWN


def _fid(*parts: str) -> str:
    return "wraith-ps-" + hashlib.sha1("|".join(parts).encode()).hexdigest()[:10]


def _port_finding(target: Target, probe: PortProbe, host: str) -> Finding:
    severity = "medium" if probe.state is PortState.OPEN else "info"
    confidence = "high" if probe.banner_matched else "low"
    banner_note = f"; banner={probe.banner_matched!r}" if probe.banner_matched else ""
    return Finding(
        id=_fid(target.url, host, str(probe.port)),
        tool="wraith",
        title=f"SSRF reaches internal port {host}:{probe.port} ({probe.state.value}{banner_note})",
        severity=severity,
        confidence=confidence,
        target=target.url,
        vector=target.injection.vector(),
        variant=f"portscan:{host}:{probe.port}",
        cwe_id=CWE_SSRF,
        evidence={
            "host": host,
            "port": probe.port,
            "state": probe.state.value,
            "elapsed_s": round(probe.elapsed, 3),
            "status_code": probe.status_code,
            "body_snippet": probe.body_snippet[:256],
            "banner_matched": probe.banner_matched,
            "note": (
                "Banner detected in echoed response — port is reachable and "
                "service responded." if probe.banner_matched else
                "Anomalous response vs closed-port baseline; manual verification required."
            ),
        },
        references=[
            "https://cwe.mitre.org/data/definitions/918.html",
            "https://portswigger.net/web-security/ssrf",
        ],
    )


async def scan_ports(
    target: Target,
    scope,
    *,
    host: str = "127.0.0.1",
    ports: tuple[int, ...] = DEFAULT_PORTS,
    concurrency: int = 10,
    timeout: float = 5.0,
    rate_limit: float | None = None,
    proxy: str | None = None,
    client: ScanClient | None = None,
) -> list[Finding]:
    """Probe ``ports`` on ``host`` via SSRF injection and return findings.

    Fires ``http://<host>:<port>/`` at the marked injection point for each port.
    Uses a calibration probe (port 65535) to establish a baseline elapsed time,
    then classifies each port relative to that baseline.

    Args:
        target: Parsed request + injection point (from :class:`~wraith.engine.Target`).
        scope: Scope allowlist enforced before any request.
        host: Internal host to port-scan through the SSRF (default: 127.0.0.1).
        ports: Tuple of ports to probe (default: :data:`DEFAULT_PORTS`).
        concurrency: Max concurrent in-flight probes.
        timeout: Per-probe request timeout in seconds.
        rate_limit: Max requests/second (None = unlimited).
        proxy: Proxy URL for the underlying client.
        client: Injected ScanClient (tests); a fresh client is built otherwise.

    Returns:
        Findings for ports classified as OPEN or UNKNOWN (CLOSED/FILTERED are
        dropped as non-actionable recon noise).
    """
    own_client = client is None
    client = client or get_client(scope, rate_limit=rate_limit, proxy=proxy, timeout=timeout)
    sem = asyncio.Semaphore(max(1, concurrency))

    async def _probe(port: int) -> PortProbe:
        url = probe_url(host, port)
        method, req_url, headers, body = target.build_request(url)
        t0 = time.monotonic()
        status_code = None
        body_text = ""
        try:
            async with sem:
                resp = await client.request(method, req_url, headers=headers or None, content=body)
            status_code = resp.status_code
            body_text = resp.text
        except OutOfScopeError:
            # Payload steered request out of scope — treat as filtered.
            elapsed = time.monotonic() - t0
            return PortProbe(port=port, state=PortState.FILTERED, elapsed=elapsed)
        except asyncio.TimeoutError:
            elapsed = time.monotonic() - t0
            return PortProbe(port=port, state=PortState.FILTERED, elapsed=elapsed)
        except Exception:
            elapsed = time.monotonic() - t0
            return PortProbe(
                port=port, state=PortState.UNKNOWN, elapsed=elapsed,
                status_code=status_code,
            )
        elapsed = time.monotonic() - t0
        banner = _match_banner(body_text)
        snippet = body_text[:512]
        return PortProbe(
            port=port,
            state=PortState.UNKNOWN,  # will be overwritten by _classify
            elapsed=elapsed,
            status_code=status_code,
            body_snippet=snippet,
            banner_matched=banner,
        )

    try:
        # 1) Calibration: probe a port very unlikely to be open to get the
        #    baseline "closed" response time from this SSRF sink.
        baseline = await _probe(65535)
        baseline_elapsed = baseline.elapsed if baseline.elapsed > 0 else timeout

        # 2) Probe all target ports concurrently.
        probes = await asyncio.gather(*(_probe(p) for p in ports))
    finally:
        if own_client:
            await client.aclose()

    # 3) Classify each probe and collect findings.
    findings: list[Finding] = []
    for probe in probes:
        probe.state = _classify(
            probe.elapsed, timeout, probe.status_code,
            probe.banner_matched, baseline_elapsed,
        )
        if probe.state in (PortState.OPEN, PortState.UNKNOWN):
            findings.append(_port_finding(target, probe, host))

    return sorted(findings, key=lambda f: f.id)
