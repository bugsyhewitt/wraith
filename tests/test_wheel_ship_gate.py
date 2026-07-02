"""v0.1 release ship-gate: build the wheel, install into a fresh venv, prove it works.

Skippable via `pytest -m "not ship_gate"`. Runs in the full v0.1 suite.

Mirrors ferryman's ship-gate, then adds the v0.1 detection gate: the installed
`wraith` CLI must produce a real Finding against a loopback fixture.

[Worker decision: the fresh-venv install resolves wraith's runtime deps from the
LOCAL sibling clones (`../h1-reporter`, `../scan-primitives`) plus PyPI, then
installs the wheel `--no-deps`. This is deterministic in the necromancer
clones-side-by-side layout and pins the REAL local `scan_primitives.ScanClient`
(rather than whatever a remote git ref happens to hold). If the siblings are not
present the test falls back to the declared git deps (`pip install <wheel>`),
which needs network + reachable remotes -- hence the gate is opt-in.]
"""

from __future__ import annotations

import json
import subprocess
import sys
import venv
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

_AWS_CREDS = (
    '{"Code":"Success","Type":"AWS-HMAC","AccessKeyId":"ASIAEXAMPLEDONOTUSE",'
    '"SecretAccessKey":"wJalrEXAMPLEKEYDONOTUSE","Token":"tok",'
    '"Expiration":"2026-07-02T06:00:00Z"}'
)


def _run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


@pytest.mark.ship_gate
def test_wheel_builds_cleanly(tmp_path):
    """`python -m build --wheel --sdist` produces both artifacts with no error."""
    out = tmp_path / "build-out"
    _run(
        [sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(out)],
        cwd=REPO_ROOT,
    )
    wheels = list(out.glob("wraith-0.1.0-*.whl"))
    sdists = list(out.glob("wraith-0.1.0.tar.gz"))
    assert wheels, f"wheel not built; got: {list(out.iterdir())}"
    assert sdists, f"sdist not built; got: {list(out.iterdir())}"
    test_wheel_builds_cleanly._wheel = wheels[0]


@pytest.mark.ship_gate
def test_wheel_installs_into_fresh_venv(tmp_path):
    """`pip install <wheel>` into a brand-new venv resolves the entry-point."""
    wheel = getattr(test_wheel_builds_cleanly, "_wheel", None)
    if wheel is None:
        pytest.skip("preceding build test did not produce a wheel")

    venv_dir = tmp_path / "fresh-venv"
    venv.create(venv_dir, with_pip=True, clear=True)
    pip = venv_dir / "bin" / "pip"

    siblings = [REPO_ROOT.parent / "h1-reporter", REPO_ROOT.parent / "scan-primitives"]
    if all(s.exists() for s in siblings):
        # Deterministic: real local siblings + the remaining runtime deps, then
        # the wheel with --no-deps.
        _run(
            [str(pip), "install", "--quiet", str(siblings[0]), str(siblings[1]),
             "httpx", "dnslib", "cryptography"]
        )
        _run([str(pip), "install", "--quiet", "--no-deps", str(wheel)])
    else:  # fall back to the declared git deps (needs network + reachable remotes)
        _run([str(pip), "install", "--quiet", str(wheel)])

    cli = venv_dir / "bin" / "wraith"
    version_out = _run([str(cli), "--version"]).stdout.strip()
    assert version_out == "wraith 0.1.0", f"unexpected --version output: {version_out!r}"

    test_wheel_installs_into_fresh_venv._venv_dir = venv_dir


@pytest.mark.ship_gate
def test_wheel_version_importable_in_fresh_venv(tmp_path):
    """`import wraith; wraith.__version__` == '0.1.0' inside the fresh venv."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding install test did not build a venv")

    py = venv_dir / "bin" / "python"
    _run([str(py), "-c", "import wraith; assert wraith.__version__ == '0.1.0'"])


@pytest.mark.ship_gate
def test_installed_wheel_public_api(tmp_path):
    """The installed wheel exposes the full public API surface."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding install test did not build a venv")

    py = venv_dir / "bin" / "python"
    check_script = (
        "import wraith, wraith.cli, wraith.findings, wraith.sarif, "
        "wraith.reporting, wraith.client, wraith.mutators, wraith.metadata, "
        "wraith.oob, wraith.engine, wraith.protocols, wraith.mcp; "
        "from wraith.findings import Finding, SEVERITIES, CONFIDENCES; "
        "from wraith.sarif import to_sarif; "
        "from wraith.reporting import to_h1md; "
        "from wraith.client import ScanClient, Response, get_client; "
        "from wraith.engine import Target, run_scan; "
        "from wraith.oob import LocalCollaborator, InteractshClient"
    )
    _run([str(py), "-c", check_script])


class _MetadataMock(BaseHTTPRequestHandler):
    """Loopback app that emulates an SSRF-vulnerable proxy: it 'fetches' the
    injected ``url`` and echoes AWS IMDS credentials when it targets 169.254.169.254."""

    def do_GET(self):  # noqa: N802
        injected = parse_qs(urlsplit(self.path).query).get("url", [""])[0]
        if "169.254.169.254" in injected:
            body = _AWS_CREDS.encode()
        else:
            body = b"nothing interesting"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        return


@pytest.mark.ship_gate
def test_installed_wheel_detects_ssrf_fixture(tmp_path):
    """The installed `wraith scan` produces a CONFIRMED-schema finding vs a fixture.

    Points the installed CLI at a loopback mock that echoes AWS IMDS credentials
    when the SSRF payload targets 169.254.169.254, and asserts a critical,
    CWE-918 AWS metadata finding is emitted as JSON. This is the acceptance gate
    that was a `pytest.skip` in the scaffolding pass.
    """
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding install test did not build a venv")

    server = ThreadingHTTPServer(("127.0.0.1", 0), _MetadataMock)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        scope = tmp_path / "scope.txt"
        scope.write_text("127.0.0.1\n")
        cli = venv_dir / "bin" / "wraith"
        url = f"http://127.0.0.1:{port}/proxy?url=FUZZ"
        out = _run(
            [
                str(cli), "scan", "-u", url, "--marker", "FUZZ",
                "--cloud-metadata", "--scope-file", str(scope), "--format", "json",
            ]
        ).stdout
    finally:
        server.shutdown()
        server.server_close()

    findings = json.loads(out)
    assert findings, f"installed CLI produced no findings; output: {out!r}"
    aws = [f for f in findings if f.get("evidence", {}).get("provider") == "aws"]
    assert aws, f"no AWS metadata finding; got: {findings}"
    assert aws[0]["cwe_id"] == 918
    assert aws[0]["severity"] == "critical"
    assert aws[0]["tool"] == "wraith"
    # R5: the secret bytes never made it into the emitted finding.
    assert "wJalrEXAMPLE" not in out
