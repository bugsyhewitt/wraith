"""v0.1 release ship-gate: build the wheel, install into a fresh venv, prove it works.

Skippable via `pytest -m "not ship_gate"`. Runs in the full v0.1 suite.

Mirrors ferryman's ship-gate. The install step resolves the declared runtime
deps (httpx, h1-reporter). h1-reporter is a git dependency; if the git remote is
unreachable in a given environment this test will fail at the install step --
that is expected and is why the gate is opt-in (the fast unit tier at
`pytest -m "not ship_gate"` needs no network).
"""

from __future__ import annotations

import subprocess
import sys
import venv
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


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

    # Install wheel; pip resolves all declared runtime deps (httpx, h1-reporter).
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
        "wraith.reporting, wraith.client; "
        "from wraith.findings import Finding, SEVERITIES, CONFIDENCES; "
        "from wraith.sarif import to_sarif; "
        "from wraith.reporting import to_h1md; "
        "from wraith.client import ScanClient, Response, get_client"
    )
    _run([str(py), "-c", check_script])


@pytest.mark.ship_gate
def test_installed_wheel_detects_ssrf_fixture(tmp_path):
    """TODO(v0.1): the installed CLI produces a finding against a mock target.

    Deferred to the v0.1 detection build. Once the SSRF mutator engine, the
    cloud-metadata probes, and the OOB confirmation engine exist
    (V0.1-CRITERIA.md #2-#4), this step will point the installed `wraith scan`
    at a hermetic loopback fixture (pytest-httpserver + the in-process dnslib OOB
    listener) and assert a CONFIRMED finding is emitted with cwe_id 918. No
    detection is built in this scaffolding pass, so there is nothing to run yet.
    """
    pytest.skip("detection engine not built this pass -- see V0.1-CRITERIA.md #2-#4")
