"""Protocol modules: ``dict://`` read-only recon + ``gopher://`` payload generator.

V0.1-CRITERIA.md #5 -- **read-only + generator only**:

* :func:`gopher_payload` / :func:`resp_encode` / :func:`fastcgi_encode` -- pure
  byte encoders that build a ``gopher://`` payload (Redis RESP or FastCGI), with
  correct ``%0d%0a`` CRLF and a single/double URL-encode toggle. This EMITS a
  payload for the operator; it does **not** fire it. Weaponized sequences
  (Redis cron/SSH/``MODULE LOAD``, FastCGI php-fpm RCE) are explicitly
  NOT-in-v0.1 -- deferred to a sandboxed ``--exploit`` gate.
* :func:`dict_recon` -- read-only ``dict://`` recon through an SSRF primitive
  (port/banner, Redis ``INFO``, Memcached ``stats``). Read-only by definition;
  it changes no target state.

R5: response bytes classified for a service banner are DATA -- substring-matched
into evidence, never evaluated.
"""

from __future__ import annotations

import asyncio
from urllib.parse import quote

from wraith.client import ScanClient, get_client
from wraith.findings import CWE_SSRF, Finding

__all__ = [
    "resp_encode",
    "fastcgi_encode",
    "gopher_payload",
    "dict_url",
    "DICT_SERVICES",
    "detect_service",
    "dict_recon",
]

# --------------------------------------------------------------------------- #
# gopher:// payload generator (pure byte encoders)
# --------------------------------------------------------------------------- #

def resp_encode(commands: list[list[str]]) -> bytes:
    """Encode Redis commands as the RESP wire protocol.

    ``[["SET", "k", "v"]]`` -> ``b"*3\\r\\n$3\\r\\nSET\\r\\n$1\\r\\nk\\r\\n$1\\r\\nv\\r\\n"``.
    """
    out = bytearray()
    for args in commands:
        out += f"*{len(args)}\r\n".encode()
        for arg in args:
            raw = arg.encode() if isinstance(arg, str) else arg
            out += f"${len(raw)}\r\n".encode() + raw + b"\r\n"
    return bytes(out)


def _fcgi_record(rec_type: int, request_id: int, content: bytes) -> bytes:
    """One FastCGI record (version 1) with 8-byte-aligned padding."""
    length = len(content)
    padding = (8 - length % 8) % 8
    header = bytes(
        [
            1,  # FCGI version
            rec_type,
            (request_id >> 8) & 0xFF,
            request_id & 0xFF,
            (length >> 8) & 0xFF,
            length & 0xFF,
            padding,
            0,  # reserved
        ]
    )
    return header + content + b"\x00" * padding


def _fcgi_nv(name: str, value: str) -> bytes:
    def enc_len(n: int) -> bytes:
        if n < 128:
            return bytes([n])
        return bytes([(n >> 24) | 0x80, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])

    nb, vb = name.encode(), value.encode()
    return enc_len(len(nb)) + enc_len(len(vb)) + nb + vb


def fastcgi_encode(params: dict[str, str], stdin: bytes = b"") -> bytes:
    """Encode a FastCGI responder request (BEGIN_REQUEST + PARAMS + STDIN).

    A generic byte encoder for the operator to review. It injects no PHP and
    fires nothing -- weaponized php-fpm RCE is NOT-in-v0.1.
    """
    request_id = 1
    begin = _fcgi_record(1, request_id, bytes([0, 1, 0, 0, 0, 0, 0, 0]))  # role=responder
    param_data = b"".join(_fcgi_nv(k, v) for k, v in params.items())
    params_rec = _fcgi_record(4, request_id, param_data) + _fcgi_record(4, request_id, b"")
    stdin_rec = _fcgi_record(5, request_id, stdin) + _fcgi_record(5, request_id, b"")
    return begin + params_rec + stdin_rec


def gopher_payload(
    host: str,
    port: int,
    data: bytes,
    *,
    item_type: str = "_",
    double_encode: bool = False,
) -> str:
    """Wrap raw ``data`` bytes into a ``gopher://`` URL.

    Every byte is percent-encoded (so CRLF becomes the required ``%0d%0a``).
    ``double_encode`` re-encodes the percent signs (``%0d`` -> ``%250d``) for
    filters that decode twice.
    """
    encoded = "".join(f"%{b:02x}" for b in data)
    if double_encode:
        encoded = encoded.replace("%", "%25")
    return f"gopher://{host}:{port}/{item_type}{encoded}"


# --------------------------------------------------------------------------- #
# dict:// read-only recon
# --------------------------------------------------------------------------- #

def dict_url(host: str, port: int, *args: str) -> str:
    """Build a ``dict://`` URL. ``dict_url("h", 6379, "INFO")`` -> ``dict://h:6379/INFO``.

    Multiple args map to a space-joined command line (``a:b`` -> ``a b``), the
    convention curl-backed fetchers use for ``dict://``.
    """
    path = ":".join(quote(a, safe="") for a in args)
    return f"dict://{host}:{port}/{path}"


# (service, port, command-args, banner signatures)
DICT_SERVICES: list[tuple[str, int, tuple[str, ...], tuple[str, ...]]] = [
    ("redis", 6379, ("INFO",), ("redis_version", "# Server", "connected_clients")),
    ("memcached", 11211, ("stats",), ("STAT ", "STAT pid", "STAT version")),
]


def detect_service(text: str) -> tuple[str, tuple[str, ...]] | None:
    """Classify a banner/response against known service signatures (data-only)."""
    for service, _port, _cmd, sigs in DICT_SERVICES:
        matched = tuple(s for s in sigs if s in text)
        if len(matched) >= 2:
            return service, matched
    return None


async def dict_recon(
    target,
    scope,
    *,
    host: str = "127.0.0.1",
    client: ScanClient | None = None,
    rate_limit: float | None = None,
    proxy: str | None = None,
    timeout: float = 10.0,
) -> list[Finding]:
    """Read-only ``dict://`` recon through an SSRF injection point.

    Injects a ``dict://`` recon URL for each known service into ``target``'s
    injection point, dispatches through the scope-enforced client, and emits a
    Finding when the echoed response carries a service banner. Read-only: only
    ``INFO`` / ``stats`` are sent; no state-changing command is generated.
    """
    own = client is None
    client = client or get_client(scope, rate_limit=rate_limit, proxy=proxy, timeout=timeout)
    findings: list[Finding] = []
    try:
        for service, port, cmd, _sigs in DICT_SERVICES:
            payload = dict_url(host, port, *cmd)
            method, url, headers, body = target.build_request(payload)
            try:
                resp = await client.request(method, url, headers=headers or None, content=body)
            except Exception:
                continue
            hit = detect_service(resp.text)
            if hit is not None:
                svc, matched = hit
                vector = target.injection.vector()
                findings.append(
                    Finding(
                        id=f"wraith-dict-{svc}",
                        tool="wraith",
                        title=f"SSRF dict:// recon exposed {svc} on {host}:{port}",
                        severity="medium",
                        confidence="high",
                        target=target.url,
                        vector=vector,
                        variant=f"dict:{svc}",
                        cwe_id=CWE_SSRF,
                        evidence={
                            "service": svc,
                            "injected_payload": payload,
                            "banner_signature": f"matched {', '.join(matched)}",
                        },
                        references=["https://cwe.mitre.org/data/definitions/918.html"],
                    )
                )
    finally:
        if own:
            await client.aclose()
    return findings
