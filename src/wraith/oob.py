"""Out-of-band (OOB) confirmation engine (V0.1-CRITERIA.md #4).

The primary gap over the dead-ancestor SSRFmap: blind SSRF is the *default*
case, so every payload is paired with a unique OOB canary and confirmed via an
out-of-band interaction (DNS or HTTP). Two collaborators implement one
:class:`Collaborator` interface:

* :class:`LocalCollaborator` -- an in-process, self-hostable listener: a
  ``dnslib`` DNS server (records QNAMEs) + a threaded HTTP capture server, both
  on loopback. This is what the Tier-2 test drives end to end and what an
  operator runs on their own box (the "self-host config").
* :class:`InteractshClient` -- a real **interactsh-compatible** client: RSA
  register, ``/poll`` with RSA-OAEP(SHA-256)-wrapped AES-256-CFB decryption,
  interactsh's ``<correlation-id><random>.<domain>`` canary scheme. Works
  against a public or self-hosted interactsh server.

Confirmation rule (contract): **a DNS-only callback still counts as CONFIRMED**,
with the finding flagged ``http_egress_filtered`` ("HTTP egress likely
filtered"). An HTTP callback is the stronger proof.

R5 / safety: the collaborator is wraith's own trusted infra (not a scan target),
so its polling does not go through the scope-enforced client. Captured
interaction bytes are DATA -- recorded as evidence, never evaluated.
"""

from __future__ import annotations

import base64
import json
import secrets
import string
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Protocol, runtime_checkable

__all__ = [
    "Canary",
    "Interaction",
    "OobResult",
    "Collaborator",
    "classify",
    "LocalCollaborator",
    "InteractshConfig",
    "InteractshClient",
]


@dataclass(frozen=True, slots=True)
class Canary:
    """A unique OOB canary: a token and the hostname/URL that embeds it."""

    token: str
    host: str

    @property
    def url(self) -> str:
        return f"http://{self.host}/{self.token}"


@dataclass(frozen=True, slots=True)
class Interaction:
    """One recorded out-of-band interaction against a canary."""

    token: str
    protocol: str  # "dns" | "http"
    source: str  # remote address that reached the collaborator
    detail: str  # QNAME, request line, or raw request (data only, never eval'd)
    at: str  # ISO-8601 timestamp


@dataclass(frozen=True, slots=True)
class OobResult:
    """The confirmation verdict for a single canary token."""

    token: str
    confirmed: bool
    protocol: str | None  # "http" (preferred) or "dns"
    proof: str | None  # e.g. "dns:<host>" / "http:<host>" -> Finding.oob_proof
    http_egress_filtered: bool  # DNS-only hit -> HTTP egress likely filtered
    interactions: list[Interaction] = field(default_factory=list)


def classify(token: str, interactions: list[Interaction], host: str | None = None) -> OobResult:
    """Reduce a token's interactions to a confirmation verdict.

    HTTP beats DNS. A DNS-only hit is CONFIRMED but flags
    ``http_egress_filtered`` per the contract ("HTTP egress likely filtered").
    """
    mine = [i for i in interactions if i.token == token]
    if not mine:
        return OobResult(token, False, None, None, False, [])
    label = host or (mine[0].detail.split()[0] if mine[0].detail else token)
    http = next((i for i in mine if i.protocol == "http"), None)
    if http is not None:
        return OobResult(token, True, "http", f"http:{label}", False, mine)
    return OobResult(token, True, "dns", f"dns:{label}", True, mine)


# --------------------------------------------------------------------------- #
# Shared collaborator behaviour
# --------------------------------------------------------------------------- #

@runtime_checkable
class Collaborator(Protocol):
    """The OOB collaborator interface the engine depends on."""

    @property
    def domain(self) -> str: ...

    def new_canary(self) -> Canary: ...

    def poll(self) -> list[Interaction]: ...

    def result_for(self, token: str) -> OobResult: ...

    def wait_for(self, token: str, *, timeout: float = ..., interval: float = ...) -> OobResult: ...

    def close(self) -> None: ...


class _BaseCollaborator:
    """Interaction store + polling/wait loop shared by both collaborators."""

    def __init__(self) -> None:
        self._interactions: list[Interaction] = []
        self._issued: dict[str, str] = {}  # token -> host
        self._lock = threading.Lock()

    def _record(self, interaction: Interaction) -> None:
        with self._lock:
            self._interactions.append(interaction)

    def _match_token(self, name: str) -> str:
        """Return the issued token whose canary appears in ``name`` (label/prefix)."""
        low = name.lower()
        labels = low.split(".")
        with self._lock:
            issued = list(self._issued)
        for token in issued:
            if token in labels or low.startswith(token):
                return token
        return ""

    def snapshot(self) -> list[Interaction]:
        with self._lock:
            return list(self._interactions)

    # poll() is the refresh point; the network-backed client overrides it.
    def poll(self) -> list[Interaction]:
        return self.snapshot()

    def result_for(self, token: str) -> OobResult:
        host = self._issued.get(token)
        return classify(token, self.poll(), host=host)

    def wait_for(
        self, token: str, *, timeout: float = 5.0, interval: float = 0.05
    ) -> OobResult:
        """Poll until the token is confirmed or ``timeout`` elapses (late-hit window)."""
        deadline = time.monotonic() + timeout
        while True:
            result = self.result_for(token)
            if result.confirmed or time.monotonic() >= deadline:
                return result
            time.sleep(interval)


# --------------------------------------------------------------------------- #
# LocalCollaborator: in-process dnslib DNS + threaded HTTP capture
# --------------------------------------------------------------------------- #

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _cfb(iv: bytes):
    """AES-CFB mode, from whichever location this cryptography version exposes.

    cryptography>=49 relocated CFB to ``hazmat.decrepit`` (it is legacy, but it
    is the interactsh wire format, so wraith must speak it). Try the new home
    first, fall back to the classic location for older cryptography.
    """
    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB
    except ImportError:  # pragma: no cover - older cryptography
        from cryptography.hazmat.primitives.ciphers.modes import CFB
    return CFB(iv)


class LocalCollaborator(_BaseCollaborator):
    """Self-hosted OOB listener: a loopback ``dnslib`` DNS server + HTTP capture.

    The DNS server answers every A query with ``127.0.0.1`` and records the
    QNAME; the HTTP server records the Host + path of every request. Both extract
    the matching canary token. Ideal for hermetic tests and for an operator who
    controls a resolver that can be pointed at this listener.
    """

    def __init__(
        self,
        domain: str = "oob.local",
        *,
        host: str = "127.0.0.1",
        dns: bool = True,
        http: bool = True,
    ) -> None:
        super().__init__()
        self._domain = domain
        self._host = host
        self._dns_server = None
        self._dns_port = 0
        self._http_server: ThreadingHTTPServer | None = None
        self._http_port = 0
        if dns:
            self._start_dns()
        if http:
            self._start_http()

    @property
    def domain(self) -> str:
        return self._domain

    @property
    def dns_port(self) -> int:
        return self._dns_port

    @property
    def http_port(self) -> int:
        return self._http_port

    def http_url_for(self, token: str) -> str:
        """A loopback URL that reaches the HTTP capture server for ``token``.

        Useful when a caller must drive the capture server directly (tests, or an
        operator whose SSRF target can reach this box on loopback) rather than via
        public DNS resolution of the canary host.
        """
        return f"http://{self._host}:{self._http_port}/{token}"

    def new_canary(self) -> Canary:
        token = "wr" + secrets.token_hex(6)
        host = f"{token}.{self._domain}"
        with self._lock:
            self._issued[token] = host
        return Canary(token=token, host=host)

    # -- DNS ---------------------------------------------------------------- #
    def _start_dns(self) -> None:
        from dnslib import QTYPE, RR, A
        from dnslib.server import BaseResolver, DNSServer

        collaborator = self

        class _Resolver(BaseResolver):
            def resolve(self, request, handler):
                qname = str(request.q.qname).rstrip(".")
                try:
                    source = handler.client_address[0]
                except Exception:  # pragma: no cover - defensive
                    source = ""
                token = collaborator._match_token(qname)
                collaborator._record(
                    Interaction(token, "dns", source, qname, _now_iso())
                )
                reply = request.reply()
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("127.0.0.1"), ttl=1))
                return reply

        server = DNSServer(_Resolver(), address=self._host, port=0)
        server.start_thread()
        self._dns_server = server
        # Recover the OS-assigned port from the underlying socketserver.
        self._dns_port = server.server.server_address[1]

    # -- HTTP --------------------------------------------------------------- #
    def _start_http(self) -> None:
        collaborator = self

        class _Handler(BaseHTTPRequestHandler):
            def _capture(self) -> None:
                host = self.headers.get("Host", "").split(":")[0]
                name = host or self.path.lstrip("/")
                token = collaborator._match_token(name) or collaborator._match_token(
                    self.path.lstrip("/")
                )
                collaborator._record(
                    Interaction(
                        token,
                        "http",
                        self.client_address[0],
                        f"{self.command} {self.path} Host:{host}",
                        _now_iso(),
                    )
                )
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = _capture
            do_POST = _capture

            def log_message(self, *args) -> None:  # silence the default stderr log
                return

        server = ThreadingHTTPServer((self._host, 0), _Handler)
        self._http_port = server.server_address[1]
        self._http_server = server
        threading.Thread(target=server.serve_forever, daemon=True).start()

    def close(self) -> None:
        if self._dns_server is not None:
            self._dns_server.stop()
            self._dns_server = None
        if self._http_server is not None:
            self._http_server.shutdown()
            self._http_server.server_close()
            self._http_server = None


# --------------------------------------------------------------------------- #
# InteractshClient: real interactsh-compatible protocol client
# --------------------------------------------------------------------------- #

@dataclass
class InteractshConfig:
    """Self-host / server config for the interactsh-compatible client.

    Args:
        server: interactsh server base URL (public ``https://oast.pro`` or a
            self-hosted deployment ``https://interact.mycorp.net``).
        domain: canary domain served by that server; defaults to the server host.
        token: optional ``Authorization`` token for an auth-gated self-hosted
            server.
    """

    server: str
    domain: str | None = None
    token: str | None = None

    def resolved_domain(self) -> str:
        if self.domain:
            return self.domain
        from urllib.parse import urlsplit

        return urlsplit(self.server).hostname or self.server


_CORR_ALPHABET = string.ascii_lowercase + string.digits


class InteractshClient(_BaseCollaborator):
    """interactsh-protocol client: register, poll, and decrypt interactions.

    Speaks the documented interactsh wire protocol so it interoperates with a
    real (public or self-hosted) interactsh server: an RSA public key is
    registered under a 20-char correlation id; ``/poll`` returns AES-256-CFB
    ciphertexts plus the AES key wrapped with RSA-OAEP(SHA-256); this client
    unwraps and decrypts them into :class:`Interaction` records.

    ``http_client`` is injectable (an ``httpx.Client``) so tests can respx-mock
    ``/register`` and ``/poll`` without a live server.
    """

    def __init__(self, config: InteractshConfig, *, http_client=None) -> None:
        super().__init__()
        import httpx
        from cryptography.hazmat.primitives.asymmetric import rsa

        self._config = config
        self._domain = config.resolved_domain()
        self._http = http_client or httpx.Client(timeout=10.0)
        self._owns_http = http_client is None
        self._correlation_id = "".join(secrets.choice(_CORR_ALPHABET) for _ in range(20))
        self._secret = secrets.token_hex(16)
        self._private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._registered = False

    @property
    def domain(self) -> str:
        return self._domain

    @property
    def correlation_id(self) -> str:
        return self._correlation_id

    def _public_key_b64(self) -> str:
        from cryptography.hazmat.primitives import serialization

        pem = self._private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64.b64encode(pem).decode()

    def register(self) -> None:
        """Register this client's public key with the interactsh server."""
        headers = {"Content-Type": "application/json"}
        if self._config.token:
            headers["Authorization"] = self._config.token
        resp = self._http.post(
            f"{self._config.server}/register",
            headers=headers,
            json={
                "public-key": self._public_key_b64(),
                "secret-key": self._secret,
                "correlation-id": self._correlation_id,
            },
        )
        resp.raise_for_status()
        self._registered = True

    def new_canary(self) -> Canary:
        if not self._registered:
            self.register()
        rand = "".join(secrets.choice(_CORR_ALPHABET) for _ in range(13))
        full_id = f"{self._correlation_id}{rand}"
        host = f"{full_id}.{self._domain}"
        with self._lock:
            self._issued[full_id] = host
        return Canary(token=full_id, host=host)

    def _decrypt(self, aes_key_b64: str, data_b64: str) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

        aes_key = self._private.decrypt(
            base64.b64decode(aes_key_b64),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        blob = base64.b64decode(data_b64)
        iv, body = blob[:16], blob[16:]
        decryptor = Cipher(algorithms.AES(aes_key), _cfb(iv)).decryptor()
        return decryptor.update(body) + decryptor.finalize()

    def poll(self) -> list[Interaction]:
        """Fetch new interactions from the server, decrypt, record, return all."""
        headers = {}
        if self._config.token:
            headers["Authorization"] = self._config.token
        resp = self._http.get(
            f"{self._config.server}/poll",
            params={"id": self._correlation_id, "secret": self._secret},
            headers=headers,
        )
        resp.raise_for_status()
        payload = resp.json()
        aes_key = payload.get("aes_key")
        for item in payload.get("data") or []:
            try:
                plaintext = self._decrypt(aes_key, item)
                record = json.loads(plaintext)
            except Exception:  # pragma: no cover - malformed/foreign item, skip
                continue
            full_id = record.get("full-id") or record.get("unique-id") or ""
            token = self._match_token(full_id) or full_id
            self._record(
                Interaction(
                    token=token,
                    protocol=record.get("protocol", "dns"),
                    source=record.get("remote-address", ""),
                    detail=record.get("raw-request", record.get("q-type", "")),
                    at=record.get("timestamp", _now_iso()),
                )
            )
        return self.snapshot()

    def close(self) -> None:
        if self._owns_http:
            self._http.close()
