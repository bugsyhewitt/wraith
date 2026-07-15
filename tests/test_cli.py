"""CLI tests: argument surface, the offline gopher generator, and a live scan.

Exercises the wired handlers (criteria #1-#6 via the CLI): the dry-run gopher
generator (pure/offline), scope fail-closed enforcement, and a real
``wraith scan`` against a loopback mock producing an AWS metadata finding in
each output format.
"""

from __future__ import annotations

import json

import pytest
from werkzeug.wrappers import Response as WZResponse

from wraith.cli import build_parser, main

_AWS_CREDS = (
    '{"Code":"Success","AccessKeyId":"ASIAEXAMPLE",'
    '"SecretAccessKey":"wJalrEXAMPLE","Token":"tok","Expiration":"2026-07-02T06:00:00Z"}'
)


@pytest.fixture(scope="session")
def httpserver_listen_address():
    return ("127.0.0.1", 0)


# --------------------------------------------------------------------------- #
# Parser + offline handlers
# --------------------------------------------------------------------------- #

def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == "wraith 0.9.0"


def test_no_subcommand_returns_2(capsys):
    assert main([]) == 2


def test_gopher_redis_dry_run(capsys):
    rc = main(["gopher", "--protocol", "redis", "--command", "INFO"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "DRY-RUN" in out
    assert "gopher://127.0.0.1:6379/_" in out
    assert "%0d%0a" in out  # correct CRLF encoding


def test_gopher_fastcgi_double_encode(capsys):
    rc = main(["gopher", "--protocol", "fastcgi", "--double-encode", "--port", "9000"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "gopher://127.0.0.1:9000/_" in out
    assert "%25" in out  # double-encoded


def test_scan_requires_scope_file(capsys):
    rc = main(["scan", "-u", "http://127.0.0.1/proxy?url=FUZZ"])
    assert rc == 2
    assert "scope-file is required" in capsys.readouterr().err


def test_scan_rejects_empty_scope(tmp_path, capsys):
    scope = tmp_path / "scope.txt"
    scope.write_text("# only comments, no entries\n")
    rc = main(["scan", "-u", "http://127.0.0.1/proxy?url=FUZZ", "--scope-file", str(scope)])
    assert rc == 2
    assert "fail-closed" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# Live scan against a loopback mock (all output formats)
# --------------------------------------------------------------------------- #

@pytest.fixture
def aws_mock(httpserver):
    def handler(request):
        injected = request.args.get("url", "")
        if "169.254.169.254" in injected:
            return WZResponse(_AWS_CREDS, content_type="application/json")
        return WZResponse("ok")

    httpserver.expect_request("/proxy").respond_with_handler(handler)
    return httpserver


@pytest.fixture
def scope_file(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("127.0.0.1\n")
    return str(p)


def test_scan_json_output_has_finding(aws_mock, scope_file, capsys):
    url = aws_mock.url_for("/proxy") + "?url=FUZZ"
    rc = main(
        ["scan", "-u", url, "--marker", "FUZZ", "--cloud-metadata",
         "--scope-file", scope_file, "--format", "json"]
    )
    assert rc == 0
    findings = json.loads(capsys.readouterr().out)
    assert findings, "no findings emitted"
    aws = [f for f in findings if f["evidence"].get("provider") == "aws"]
    assert aws and aws[0]["cwe_id"] == 918 and aws[0]["severity"] == "critical"
    # R5: secret material is not serialised into the output.
    assert "wJalr" not in json.dumps(findings)


def test_scan_sarif_output(aws_mock, scope_file, capsys):
    url = aws_mock.url_for("/proxy") + "?url=FUZZ"
    rc = main(
        ["scan", "-u", url, "--cloud-metadata", "--scope-file", scope_file, "--format", "sarif"]
    )
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "wraith"
    assert doc["runs"][0]["results"], "no SARIF results"


def test_scan_text_output(aws_mock, scope_file, capsys):
    url = aws_mock.url_for("/proxy") + "?url=FUZZ"
    rc = main(
        ["scan", "-u", url, "--cloud-metadata", "--scope-file", scope_file, "--format", "text"]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "CRITICAL" in out and "AWS" in out


# --------------------------------------------------------------------------- #
# --target-file: multi-target batch scan (v0.9)
# --------------------------------------------------------------------------- #

def test_target_file_basic_scan(aws_mock, scope_file, tmp_path, capsys):
    """--target-file with a single URL produces the same findings as -u."""
    url = aws_mock.url_for("/proxy") + "?url=FUZZ"
    tf = tmp_path / "targets.txt"
    tf.write_text(f"# comment\n{url}\n\n")  # comment + URL + blank line

    rc = main(
        [
            "scan",
            "--target-file", str(tf),
            "--cloud-metadata",
            "--scope-file", scope_file,
            "--format", "json",
        ]
    )
    assert rc == 0
    findings = json.loads(capsys.readouterr().out)
    assert findings, "no findings from --target-file single-URL scan"
    aws = [f for f in findings if f["evidence"].get("provider") == "aws"]
    assert aws and aws[0]["severity"] == "critical"


def test_target_file_multi_url_deduplicates(aws_mock, scope_file, tmp_path, capsys):
    """Two identical URLs in --target-file yield deduplicated findings."""
    url = aws_mock.url_for("/proxy") + "?url=FUZZ"
    tf = tmp_path / "targets.txt"
    tf.write_text(f"{url}\n{url}\n")

    rc = main(
        [
            "scan",
            "--target-file", str(tf),
            "--cloud-metadata",
            "--scope-file", scope_file,
            "--format", "json",
        ]
    )
    assert rc == 0
    findings = json.loads(capsys.readouterr().out)
    ids = [f["id"] for f in findings]
    assert len(ids) == len(set(ids)), "duplicate finding IDs emitted for identical targets"


def test_target_file_skips_comments_and_blanks(tmp_path):
    """_read_target_file strips comment lines and blank lines."""
    from wraith.cli import _read_target_file

    tf = tmp_path / "targets.txt"
    tf.write_text(
        "# first comment\n"
        "\n"
        "http://a.example.com/FUZZ\n"
        "   # indented comment\n"
        "\n"
        "http://b.example.com/FUZZ\n"
    )
    urls = _read_target_file(str(tf))
    assert urls == ["http://a.example.com/FUZZ", "http://b.example.com/FUZZ"]


def test_target_file_empty_raises_systemexit(tmp_path, capsys):
    """--target-file with only comments exits 2 with a clear error."""
    from wraith.cli import _read_target_file

    tf = tmp_path / "empty.txt"
    tf.write_text("# no targets here\n\n")
    with pytest.raises(SystemExit) as exc:
        _read_target_file(str(tf))
    assert exc.value.code == 2
    assert "no target URLs" in capsys.readouterr().err


def test_target_file_missing_file_raises_systemexit(tmp_path, capsys):
    """--target-file pointing at a nonexistent file exits 2."""
    from wraith.cli import _read_target_file

    with pytest.raises(SystemExit) as exc:
        _read_target_file(str(tmp_path / "does_not_exist.txt"))
    assert exc.value.code == 2
    assert "cannot open" in capsys.readouterr().err


def test_target_file_and_request_file_are_mutually_exclusive(tmp_path, capsys):
    """Combining --target-file and -r is a usage error (exit 2)."""
    tf = tmp_path / "targets.txt"
    tf.write_text("http://127.0.0.1/FUZZ\n")
    rf = tmp_path / "req.txt"
    rf.write_text("GET / HTTP/1.1\nHost: 127.0.0.1\n\n")
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.1\n")

    rc = main(
        [
            "scan",
            "--target-file", str(tf),
            "-r", str(rf),
            "--scope-file", str(scope),
        ]
    )
    assert rc == 2
    assert "mutually exclusive" in capsys.readouterr().err


def test_scan_no_input_returns_2(tmp_path, capsys):
    """scan with no -u, -r, or --target-file exits 2 with a helpful message."""
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.1\n")
    rc = main(["scan", "--scope-file", str(scope)])
    assert rc == 2
    assert "required" in capsys.readouterr().err
