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

This is the SCAFFOLDING pass: the parser, flags, help text, and --version are
wired and tested, but every subcommand handler raises NotImplementedError -- the
SSRF mutator engine, metadata probes, OOB engine, and protocol modules are the
v0.1 build, not this pass.]

Exit codes:
    0  a handler completed (no handler completes yet this pass)
    2  usage / argument error, or no subcommand given (argparse default)
"""

from __future__ import annotations

import argparse
from typing import Sequence

from wraith import __version__

# Every handler raises this until the v0.1 detection/confirmation engine is
# built. The message points back at the contract so the next Worker (and the
# reviewing Team Lead) land on the right section.
_NOT_BUILT = "v0.1 build -- see V0.1-CRITERIA.md"


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
            "findings. [scaffold: not yet implemented -- see V0.1-CRITERIA.md "
            "#2-#4, #6]"
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
        help="include the MCP / AI-infra SSRF detection catalog (criteria #6)",
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
    scan.set_defaults(handler=_cmd_scan)

    # -- dict: read-only recon -------------------------------------------------
    dict_cmd = sub.add_parser(
        "dict",
        help="dict:// read-only recon (port/banner, Redis INFO, Memcached stats)",
        description=(
            "Read-only dict:// recon through an SSRF primitive. Read-only by "
            "definition -- no state change. [scaffold: not yet implemented -- "
            "see V0.1-CRITERIA.md #5]"
        ),
    )
    dict_cmd.add_argument(
        "-u", "--target", required=True, metavar="URL", help="target URL to probe"
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
            "v0.2 behind --exploit. [scaffold: not yet implemented -- see "
            "V0.1-CRITERIA.md #5]"
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
    gopher.set_defaults(handler=_cmd_gopher)

    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    # criteria #1-#4, #6: mutator engine, metadata probes, OOB confirmation,
    # MCP catalog. Not built this pass.
    raise NotImplementedError(_NOT_BUILT)


def _cmd_dict(args: argparse.Namespace) -> int:
    # criteria #5: dict:// read-only recon. Not built this pass.
    raise NotImplementedError(_NOT_BUILT)


def _cmd_gopher(args: argparse.Namespace) -> int:
    # criteria #5: gopher:// payload generator (dry-run). Not built this pass.
    raise NotImplementedError(_NOT_BUILT)


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
