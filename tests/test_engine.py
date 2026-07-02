"""Engine tests: request-file parsing, injection, and the end-to-end scan.

* Tier-0: :func:`wraith.engine.parse_http_request` (SSRFmap-style raw request)
  and :class:`~wraith.engine.Target` injection (marker + named query param).
* Tier-2: a real loopback "vulnerable app" (pytest-httpserver) whose handler
  performs the server-side fetch, driving both confirmation channels end to end:
  a cloud-metadata **response-signature** hit (critical AWS finding) and an
  **OOB callback** confirming blind SSRF.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import httpx
import pytest
from scan_primitives import Scope
from werkzeug.wrappers import Response as WZResponse

from wraith.engine import Target, parse_http_request, run_scan
from wraith.oob import LocalCollaborator

_FIXTURES = Path(__file__).parent / "fixtures" / "metadata"
_AWS_CREDS = (_FIXTURES / "aws_iam_credentials.json").read_text()


@pytest.fixture(scope="session")
def httpserver_listen_address():
    return ("127.0.0.1", 0)


@pytest.fixture
def local_collab():
    collab = LocalCollaborator(domain="oob.local")
    try:
        yield collab
    finally:
        collab.close()


# --------------------------------------------------------------------------- #
# Tier-0: request-file parsing (SSRFmap parity, criteria #1)
# --------------------------------------------------------------------------- #

def test_parse_http_request_get():
    raw = "GET /proxy?url=FUZZ HTTP/1.1\r\nHost: app.example.com\r\nUser-Agent: x\r\n\r\n"
    method, url, headers, body = parse_http_request(raw)
    assert method == "GET"
    assert url == "http://app.example.com/proxy?url=FUZZ"
    assert headers["Host"] == "app.example.com"
    assert headers["User-Agent"] == "x"
    assert body is None


def test_parse_http_request_post_with_body_and_https():
    raw = (
        "POST /webhook HTTP/1.1\n"
        "Host: api.example.com:443\n"
        "Content-Type: application/json\n"
        "\n"
        '{"url":"FUZZ"}'
    )
    method, url, headers, body = parse_http_request(raw)
    assert method == "POST"
    assert url == "https://api.example.com:443/webhook"  # :443 -> https
    assert body == '{"url":"FUZZ"}'


def test_parse_http_request_absolute_target():
    raw = "GET http://app.example.com/x?u=FUZZ HTTP/1.1\nHost: ignored\n\n"
    _, url, _, _ = parse_http_request(raw)
    assert url == "http://app.example.com/x?u=FUZZ"


def test_target_from_request_file(tmp_path):
    p = tmp_path / "req.txt"
    p.write_text("GET /p?url=FUZZ HTTP/1.1\nHost: app.example.com\n\n")
    target = Target.from_request_file(str(p), marker="FUZZ")
    assert target.injection.vector() == "marker:FUZZ"
    method, url, headers, body = target.build_request("http://169.254.169.254/")
    assert url == "http://app.example.com/p?url=http://169.254.169.254/"


# --------------------------------------------------------------------------- #
# Tier-0: injection (marker everywhere, named query param)
# --------------------------------------------------------------------------- #

def test_marker_injection_replaces_everywhere():
    target = Target.from_url(
        "http://app/x?u=FUZZ",
        marker="FUZZ",
        headers={"X-Real-IP": "FUZZ"},
        body="target=FUZZ",
    )
    method, url, headers, body = target.build_request("PAYLOAD")
    assert url == "http://app/x?u=PAYLOAD"
    assert headers["X-Real-IP"] == "PAYLOAD"
    assert body == "target=PAYLOAD"


def test_query_param_injection_sets_named_param():
    target = Target.from_url("http://app/proxy?url=orig&keep=1", param="url")
    assert target.injection.vector() == "query:url"
    _, url, _, _ = target.build_request("http://169.254.169.254/")
    # The named param is replaced; other params are preserved.
    assert "keep=1" in url
    assert "url=http%3A%2F%2F169.254.169.254%2F" in url
    assert "url=orig" not in url


# --------------------------------------------------------------------------- #
# Tier-2: end-to-end scan against a loopback "vulnerable app"
# --------------------------------------------------------------------------- #

def test_scan_detects_aws_metadata_via_response_signature(httpserver):
    """The app fetches the injected URL; when it reaches AWS IMDS it echoes creds."""

    def handler(request):
        injected = request.args.get("url", "")
        # A real SSRF-vulnerable app would fetch `injected` server-side; here we
        # emulate the metadata response when the payload targets AWS IMDS.
        if "169.254.169.254" in injected:
            return WZResponse(_AWS_CREDS, content_type="application/json")
        return WZResponse("nothing interesting")

    httpserver.expect_request("/proxy").respond_with_handler(handler)
    target = Target.from_url(httpserver.url_for("/proxy"), param="url")
    scope = Scope.from_entries(["127.0.0.1"])

    findings = asyncio.run(
        run_scan(target, scope, cloud_metadata=True, concurrency=8)
    )

    aws = [f for f in findings if f.evidence.get("provider") == "aws"]
    assert aws, f"no AWS finding; got {[f.title for f in findings]}"
    f = aws[0]
    assert f.severity == "critical"
    assert f.cwe_id == 918
    assert f.vector == "query:url"
    # R5: the secret bytes never enter the finding.
    assert "wJalr" not in str(f.to_dict())


def test_scan_confirms_blind_ssrf_via_oob(local_collab, httpserver):
    """No response signature -- the app makes an out-of-band callback that confirms."""

    def handler(request):
        injected = request.args.get("url", "")
        m = re.search(r"wr[0-9a-f]{12}", injected)
        if m:
            # Emulate the server-side SSRF fetch reaching the OOB collaborator.
            try:
                httpx.get(local_collab.http_url_for(m.group(0)), timeout=2)
            except Exception:
                pass
        return WZResponse("ok")  # nothing leaked in-band -> blind

    httpserver.expect_request("/fetch").respond_with_handler(handler)
    target = Target.from_url(httpserver.url_for("/fetch"), param="url")
    scope = Scope.from_entries(["127.0.0.1"])

    findings = asyncio.run(
        run_scan(target, scope, collaborator=local_collab, oob_timeout=3.0, concurrency=6)
    )

    confirmed = [f for f in findings if f.is_confirmed()]
    assert confirmed, "no OOB-confirmed finding produced"
    f = confirmed[0]
    assert f.cwe_id == 918
    assert f.oob_proof.startswith("http:")
    assert "blind SSRF" in f.title


def test_scan_no_findings_when_app_is_not_vulnerable(httpserver):
    httpserver.expect_request("/safe").respond_with_data("no ssrf here")
    target = Target.from_url(httpserver.url_for("/safe"), param="url")
    scope = Scope.from_entries(["127.0.0.1"])
    findings = asyncio.run(run_scan(target, scope, cloud_metadata=True, concurrency=8))
    assert findings == []
