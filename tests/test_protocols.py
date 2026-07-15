"""Tests for the dict:// recon + gopher:// generator (V0.1-CRITERIA.md #5).

Tier-0 exact-byte assertions on the RESP / FastCGI / gopher encoders (correct
``%0d%0a``, single/double URL-encode toggle), plus a Tier-2 loopback integration
of the read-only dict:// recon. The generator EMITS payloads only -- these tests
never fire a weaponized sequence.
"""

from __future__ import annotations

import asyncio

import pytest
from scan_primitives import Scope
from werkzeug.wrappers import Response as WZResponse

from wraith import protocols as p
from wraith.engine import Target


@pytest.fixture(scope="session")
def httpserver_listen_address():
    return ("127.0.0.1", 0)


# --------------------------------------------------------------------------- #
# RESP + gopher exact bytes
# --------------------------------------------------------------------------- #

def test_resp_encode_exact():
    assert p.resp_encode([["SET", "wraith", "test"]]) == (
        b"*3\r\n$3\r\nSET\r\n$6\r\nwraith\r\n$4\r\ntest\r\n"
    )
    assert p.resp_encode([["INFO"]]) == b"*1\r\n$4\r\nINFO\r\n"


def test_resp_encode_multiple_commands():
    assert p.resp_encode([["PING"], ["INFO"]]) == b"*1\r\n$4\r\nPING\r\n*1\r\n$4\r\nINFO\r\n"


def test_gopher_payload_crlf_is_percent_0d0a():
    payload = p.gopher_payload("127.0.0.1", 6379, p.resp_encode([["INFO"]]))
    assert payload == "gopher://127.0.0.1:6379/_%2a%31%0d%0a%24%34%0d%0a%49%4e%46%4f%0d%0a"
    assert "%0d%0a" in payload  # the contract's "correct %0d%0a"
    assert payload.startswith("gopher://127.0.0.1:6379/_")


def test_gopher_double_encode_toggle():
    single = p.gopher_payload("127.0.0.1", 6379, b"\r\n")
    double = p.gopher_payload("127.0.0.1", 6379, b"\r\n", double_encode=True)
    assert single == "gopher://127.0.0.1:6379/_%0d%0a"
    assert double == "gopher://127.0.0.1:6379/_%250d%250a"


def test_gopher_item_type_override():
    assert p.gopher_payload("h", 70, b"A", item_type="1") == "gopher://h:70/1%41"


# --------------------------------------------------------------------------- #
# FastCGI encoder
# --------------------------------------------------------------------------- #

def test_fastcgi_begin_request_header_and_alignment():
    data = p.fastcgi_encode({"SCRIPT_FILENAME": "/var/www/index.php", "REQUEST_METHOD": "GET"})
    # First record: version=1, type=1 (BEGIN_REQUEST), id=1, content-length=8.
    assert list(data[:8]) == [1, 1, 0, 1, 0, 8, 0, 0]
    # BEGIN_REQUEST body: role=1 (responder), flags=0.
    assert list(data[8:16]) == [0, 1, 0, 0, 0, 0, 0, 0]
    # Every record is 8-byte aligned.
    assert len(data) % 8 == 0


# --------------------------------------------------------------------------- #
# dict:// URL builder + service detector
# --------------------------------------------------------------------------- #

def test_dict_url_builder():
    assert p.dict_url("127.0.0.1", 6379, "INFO") == "dict://127.0.0.1:6379/INFO"
    assert p.dict_url("127.0.0.1", 6379, "CONFIG", "GET", "*") == (
        "dict://127.0.0.1:6379/CONFIG:GET:%2A"
    )


def test_detect_service_redis_and_memcached():
    redis = "redis_version:7.2.0\r\n# Server\r\nconnected_clients:3"
    assert p.detect_service(redis) == ("redis", ("redis_version", "# Server", "connected_clients"))
    memc = "STAT pid 123\r\nSTAT version 1.6\r\n"
    svc, matched = p.detect_service(memc)
    assert svc == "memcached" and len(matched) >= 2
    assert p.detect_service("nothing here") is None


# --------------------------------------------------------------------------- #
# dict:// recon end-to-end (read-only) through a loopback app
# --------------------------------------------------------------------------- #

def test_dict_recon_detects_redis_banner(httpserver):
    def handler(request):
        injected = request.args.get("url", "")
        if injected.startswith("dict://") and ":6379/" in injected:
            return WZResponse("redis_version:7.2.0\r\n# Server\r\nconnected_clients:1\r\n")
        return WZResponse("")

    httpserver.expect_request("/fetch").respond_with_handler(handler)
    target = Target.from_url(httpserver.url_for("/fetch"), param="url")
    scope = Scope.from_entries(["127.0.0.1"])

    findings = asyncio.run(p.dict_recon(target, scope, host="127.0.0.1"))
    redis = [f for f in findings if f.variant == "dict:redis"]
    assert redis, f"no redis dict finding; got {[f.variant for f in findings]}"
    assert redis[0].cwe_id == 918
    assert redis[0].severity == "medium"
    assert "dict://127.0.0.1:6379/INFO" in redis[0].evidence["injected_payload"]


# --------------------------------------------------------------------------- #
# ldap:// URL builder + signature detection (Tier-0)
# --------------------------------------------------------------------------- #

def test_ldap_url_root_dse():
    assert p.ldap_url("127.0.0.1") == "ldap://127.0.0.1:389/"
    assert p.ldap_url("10.0.0.1", 636) == "ldap://10.0.0.1:636/"


def test_ldap_url_with_base_dn():
    url = p.ldap_url("127.0.0.1", base_dn="dc=corp,dc=example")
    assert url.startswith("ldap://127.0.0.1:389/")
    assert "dc%3Dcorp" in url or "dc=corp" in url


def test_detect_ldap_response_hit():
    ldif = (
        "dn:\n"
        "objectClass: top\n"
        "namingContexts: dc=example,dc=com\n"
        "supportedLDAPVersion: 3\n"
        "subschemaSubentry: cn=Subschema\n"
    )
    result = p.detect_ldap_response(ldif)
    assert result is not None
    assert len(result) >= 2
    assert "namingContexts:" in result


def test_detect_ldap_response_miss():
    assert p.detect_ldap_response("just some HTTP response body") is None
    assert p.detect_ldap_response("") is None
    # Only one LDAP signature present — below threshold
    assert p.detect_ldap_response("namingContexts: dc=example") is None


def test_detect_service_recognises_ldap():
    ldif = "dn:\nobjectClass: top\nnamingContexts: dc=corp,dc=com\nsupportedLDAPVersion: 3\n"
    result = p.detect_service(ldif)
    assert result is not None
    svc, matched = result
    assert svc == "ldap"
    assert len(matched) >= 2


# --------------------------------------------------------------------------- #
# ldap:// recon end-to-end (Tier-2 loopback)
# --------------------------------------------------------------------------- #

def test_ldap_recon_detects_directory(httpserver):
    _LDIF = (
        "dn:\n"
        "objectClass: top\n"
        "objectClass: OpenLDAProotDSE\n"
        "namingContexts: dc=internal,dc=corp\n"
        "supportedLDAPVersion: 3\n"
        "subschemaSubentry: cn=Subschema\n"
    )

    def handler(request):
        injected = request.args.get("url", "")
        if injected.startswith("ldap://") and ":389" in injected:
            return WZResponse(_LDIF, content_type="text/plain")
        return WZResponse("")

    httpserver.expect_request("/fetch").respond_with_handler(handler)
    target = Target.from_url(httpserver.url_for("/fetch"), param="url")
    scope = Scope.from_entries(["127.0.0.1"])

    findings = asyncio.run(p.ldap_recon(target, scope, host="127.0.0.1", port=389))
    assert findings, "no ldap finding produced"
    f = findings[0]
    assert f.variant == "ldap:rootdse"
    assert f.cwe_id == 918
    assert f.severity == "high"
    assert "ldap://127.0.0.1:389/" in f.evidence["injected_payload"]
    assert "namingContexts:" in f.evidence["banner_signature"]


def test_ldap_recon_no_hit(httpserver):
    httpserver.expect_request("/fetch").respond_with_data("nothing interesting")
    target = Target.from_url(httpserver.url_for("/fetch"), param="url")
    scope = Scope.from_entries(["127.0.0.1"])

    findings = asyncio.run(p.ldap_recon(target, scope, host="127.0.0.1"))
    assert findings == []


# --------------------------------------------------------------------------- #
# tftp:// URL builder + signature detection (Tier-0)
# --------------------------------------------------------------------------- #

def test_tftp_url_default():
    assert p.tftp_url("127.0.0.1") == "tftp://127.0.0.1:69/etc/passwd"


def test_tftp_url_custom_file_and_port():
    assert p.tftp_url("10.0.0.1", "/boot.ini", 69) == "tftp://10.0.0.1:69/boot.ini"
    assert p.tftp_url("10.0.0.1", "config.txt") == "tftp://10.0.0.1:69/config.txt"


def test_detect_tftp_response_passwd_hit():
    passwd = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin\n"
    result = p.detect_tftp_response(passwd, filename="/etc/passwd")
    assert result is not None
    assert len(result) >= 2
    # R5: the raw bytes were data-only substring-matched, never eval'd
    assert "root:" in result or "/bin/" in result


def test_detect_tftp_response_boot_ini_hit():
    boot_ini = "[boot loader]\ntimeout=30\n[operating systems]\nmulti(0)disk(0)rdisk(0)partition(1)\n"
    result = p.detect_tftp_response(boot_ini, filename="/boot.ini")
    assert result is not None
    assert len(result) >= 2


def test_detect_tftp_response_miss():
    assert p.detect_tftp_response("200 OK\nContent-Type: text/html\n", filename="/etc/passwd") is None


def test_detect_service_recognises_tftp_passwd():
    passwd = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin\n"
    result = p.detect_service(passwd)
    assert result is not None
    svc, matched = result
    assert svc == "tftp-unix-passwd"
    assert len(matched) >= 2


# --------------------------------------------------------------------------- #
# tftp:// recon end-to-end (Tier-2 loopback)
# --------------------------------------------------------------------------- #

_PASSWD_BODY = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/bin/sh\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin\n"
)


def test_tftp_recon_detects_passwd(httpserver):
    def handler(request):
        injected = request.args.get("url", "")
        if injected.startswith("tftp://") and "etc/passwd" in injected:
            return WZResponse(_PASSWD_BODY, content_type="text/plain")
        return WZResponse("")

    httpserver.expect_request("/fetch").respond_with_handler(handler)
    target = Target.from_url(httpserver.url_for("/fetch"), param="url")
    scope = Scope.from_entries(["127.0.0.1"])

    findings = asyncio.run(
        p.tftp_recon(target, scope, host="127.0.0.1", port=69, files=("/etc/passwd",))
    )
    assert findings, "no tftp finding produced"
    f = findings[0]
    assert f.variant == "tftp:/etc/passwd"
    assert f.cwe_id == 918
    assert f.severity == "high"
    assert "tftp://127.0.0.1:69/etc/passwd" in f.evidence["injected_payload"]
    assert f.evidence["filename"] == "/etc/passwd"
    # R5: secret bytes (passwords) never stored in evidence
    assert "x:0:0" not in f.evidence.get("banner_signature", "")


def test_tftp_recon_no_hit(httpserver):
    httpserver.expect_request("/fetch").respond_with_data("404 not found")
    target = Target.from_url(httpserver.url_for("/fetch"), param="url")
    scope = Scope.from_entries(["127.0.0.1"])

    findings = asyncio.run(
        p.tftp_recon(target, scope, host="127.0.0.1", files=("/etc/passwd",))
    )
    assert findings == []
