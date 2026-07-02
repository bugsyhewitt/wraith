"""Tier-2 OOB confirmation tests (V0.1-CRITERIA.md #4 + Testability Tier 2).

Real loopback fixtures under the ``--allow-hosts=127.0.0.1`` socket lock:

* the in-process ``dnslib`` DNS listener + HTTP capture of
  :class:`wraith.oob.LocalCollaborator`, driving the contract's full
  deterministic chain: *mutate -> resolve via the local resolver -> hit the
  loopback internal mock -> unique-token DNS query recorded -> CONFIRMED*;
* a **DNS-only** hit counts as CONFIRMED and is flagged
  ``http_egress_filtered`` ("HTTP egress likely filtered");
* the interactsh-compatible client's crypto round-trip (RSA-OAEP(SHA-256) +
  AES-256-CFB) against a respx-mocked ``/register`` + ``/poll``.
"""

from __future__ import annotations

import asyncio
import base64
import json
import secrets

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from dnslib import DNSRecord
from scan_primitives import Scope

from wraith.client import get_client
from wraith.mutators import build_variants
from wraith.oob import (
    Interaction,
    InteractshClient,
    InteractshConfig,
    LocalCollaborator,
    _cfb,
    classify,
)


@pytest.fixture(scope="session")
def httpserver_listen_address():
    # Force pytest-httpserver onto 127.0.0.1 so it is reachable under the
    # loopback-only socket lock (and matches a "127.0.0.1" scope entry).
    # Session-scoped to match pytest-httpserver's session-scoped make_httpserver.
    return ("127.0.0.1", 0)


@pytest.fixture
def local_collab():
    collab = LocalCollaborator(domain="oob.local")
    try:
        yield collab
    finally:
        collab.close()


# --------------------------------------------------------------------------- #
# classify(): the DNS-only == CONFIRMED rule
# --------------------------------------------------------------------------- #

def test_classify_no_interaction_is_unconfirmed():
    res = classify("tok", [])
    assert res.confirmed is False
    assert res.proof is None


def test_classify_dns_only_is_confirmed_and_flags_http_filtered():
    ix = [Interaction("tok", "dns", "203.0.113.9", "tok.oob.local", "t")]
    res = classify("tok", ix, host="tok.oob.local")
    assert res.confirmed is True
    assert res.protocol == "dns"
    assert res.proof == "dns:tok.oob.local"
    assert res.http_egress_filtered is True  # contract: "HTTP egress likely filtered"


def test_classify_http_beats_dns_and_is_not_flagged():
    ix = [
        Interaction("tok", "dns", "203.0.113.9", "tok.oob.local", "t"),
        Interaction("tok", "http", "203.0.113.9", "GET / Host:tok.oob.local", "t"),
    ]
    res = classify("tok", ix, host="tok.oob.local")
    assert res.confirmed is True
    assert res.protocol == "http"
    assert res.proof == "http:tok.oob.local"
    assert res.http_egress_filtered is False


# --------------------------------------------------------------------------- #
# LocalCollaborator: unique token per canary
# --------------------------------------------------------------------------- #

def test_new_canary_is_unique_per_probe(local_collab):
    a = local_collab.new_canary()
    b = local_collab.new_canary()
    assert a.token != b.token
    assert a.host == f"{a.token}.oob.local"
    assert a.token in a.url


# --------------------------------------------------------------------------- #
# The contract's full deterministic chain (Tier 2)
# --------------------------------------------------------------------------- #

def test_full_chain_mutate_resolve_loopback_and_dns_confirm(local_collab, httpserver):
    """mutate -> resolve via local resolver -> hit loopback mock -> token recorded."""
    # An "internal" target served on loopback (the SSRF destination wraith reaches).
    httpserver.expect_request("/latest/meta-data/").respond_with_data("ok")
    internal_url = httpserver.url_for("/latest/meta-data/")

    # 1) MUTATE: generate the filter-bypass catalog for the internal target,
    #    using the unique OOB canary as the decoy host so a payload embeds it.
    canary = local_collab.new_canary()
    variants = build_variants(internal_url, decoy=canary.host)
    assert variants, "mutator produced no variants"
    assert any(canary.host in v.value for v in variants)

    # 2) HIT LOOPBACK INTERNAL MOCK: reach the internal target through the
    #    scope-enforced client (proves wraith reaches internal loopback surface).
    scope = Scope.from_entries(["127.0.0.1"])

    async def reach():
        async with get_client(scope) as client:
            resp = await client.get(internal_url)
            return resp.status_code, resp.text

    status, body = asyncio.run(reach())
    assert status == 200 and body == "ok"

    # 3) RESOLVE VIA LOCAL RESOLVER: the vulnerable server would resolve the
    #    canary; simulate that by querying the in-process dnslib listener.
    answer = DNSRecord.question(canary.host).send(
        "127.0.0.1", local_collab.dns_port, tcp=False, timeout=3
    )
    assert answer, "no DNS answer from the local resolver"

    # 4) UNIQUE-TOKEN DNS QUERY RECORDED -> CONFIRMED (DNS-only).
    result = local_collab.wait_for(canary.token, timeout=3.0)
    assert result.confirmed is True
    assert result.protocol == "dns"
    assert result.http_egress_filtered is True
    assert result.proof == f"dns:{canary.host}"
    assert any(ix.detail == canary.host for ix in result.interactions)


def test_http_callback_confirms_without_filter_flag(local_collab):
    canary = local_collab.new_canary()
    # Simulate the vulnerable server fetching the canary URL over HTTP.
    resp = httpx.get(
        f"http://127.0.0.1:{local_collab.http_port}/{canary.token}",
        headers={"Host": canary.host},
        timeout=3,
    )
    assert resp.status_code == 200
    result = local_collab.wait_for(canary.token, timeout=3.0)
    assert result.confirmed is True
    assert result.protocol == "http"
    assert result.http_egress_filtered is False


def test_wait_for_times_out_when_no_interaction(local_collab):
    canary = local_collab.new_canary()
    result = local_collab.wait_for(canary.token, timeout=0.2, interval=0.02)
    assert result.confirmed is False


# --------------------------------------------------------------------------- #
# InteractshClient: real protocol crypto round-trip (respx-mocked server)
# --------------------------------------------------------------------------- #

def _server_encrypt(public_key, interaction: dict) -> dict:
    """Emulate an interactsh server: AES-256-CFB body + RSA-OAEP(SHA-256) key."""
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    plaintext = json.dumps(interaction).encode()
    encryptor = Cipher(algorithms.AES(aes_key), _cfb(iv)).encryptor()
    body = encryptor.update(plaintext) + encryptor.finalize()
    enc_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return {
        "aes_key": base64.b64encode(enc_key).decode(),
        "data": [base64.b64encode(iv + body).decode()],
    }


def test_interactsh_client_registers_and_decrypts_dns_interaction():
    config = InteractshConfig(server="https://interact.test", domain="interact.test")
    with respx.mock(assert_all_called=False) as mock:
        register = mock.post(host="interact.test", path="/register").mock(
            return_value=httpx.Response(200, json={"message": "registration successful"})
        )
        client = InteractshClient(config)
        try:
            canary = client.new_canary()  # triggers register()

            interaction = {
                "protocol": "dns",
                "full-id": canary.token,
                "unique-id": canary.token,
                "q-type": "A",
                "remote-address": "198.51.100.23",
                "raw-request": ";; QUESTION\n",
                "timestamp": "2026-07-02T00:00:00Z",
            }
            payload = _server_encrypt(client._private.public_key(), interaction)
            mock.get(host="interact.test", path="/poll").mock(
                return_value=httpx.Response(200, json=payload)
            )

            result = client.wait_for(canary.token, timeout=1.0, interval=0.05)
        finally:
            client.close()

    assert register.called
    assert canary.host.endswith(".interact.test")
    assert canary.token.startswith(client.correlation_id)
    assert result.confirmed is True
    assert result.protocol == "dns"
    assert result.http_egress_filtered is True
    assert result.interactions[0].source == "198.51.100.23"


def test_interactsh_client_decrypts_http_interaction():
    config = InteractshConfig(server="https://interact.test")
    with respx.mock(assert_all_called=False) as mock:
        mock.post(host="interact.test", path="/register").mock(
            return_value=httpx.Response(200, json={})
        )
        client = InteractshClient(config)
        try:
            canary = client.new_canary()
            interaction = {
                "protocol": "http",
                "full-id": canary.token,
                "remote-address": "198.51.100.9",
                "raw-request": "GET / HTTP/1.1\n",
                "timestamp": "2026-07-02T00:00:00Z",
            }
            payload = _server_encrypt(client._private.public_key(), interaction)
            mock.get(host="interact.test", path="/poll").mock(
                return_value=httpx.Response(200, json=payload)
            )
            result = client.wait_for(canary.token, timeout=1.0, interval=0.05)
        finally:
            client.close()

    assert result.confirmed is True
    assert result.protocol == "http"
    assert result.http_egress_filtered is False
