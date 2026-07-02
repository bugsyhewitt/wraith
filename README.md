# wraith

SSRF (Server-Side Request Forgery) detection and out-of-band confirmation for
the modern bug-bounty and penetration-testing surface.

wraith resurrects the dead-ancestor SSRF tooling
([SSRFmap](https://github.com/swisskyrepo/SSRFmap),
[Gopherus](https://github.com/tarunkant/Gopherus)) as a headless, CLI-first tool
that owns the 2025-2026 frontier: current cloud-metadata endpoints (AWS IMDSv2,
GCP, Azure, Alibaba, Oracle, DigitalOcean), modern filter bypasses (DNS
rebinding, open-redirect chaining, IPv6 and decimal/octal/hex IP encodings),
out-of-band callback confirmation (interactsh-compatible), `dict://` / `gopher://`
protocol tooling, and the emerging MCP / AI-infrastructure SSRF class.

wraith's defining line is **detect and CONFIRM, not weaponize**: it proves SSRF
(including blind SSRF, via an out-of-band canary) and emits suite-standard
findings. It does not execute code, change target state, use harvested
credentials, or open a reverse shell. Weaponization is a deferred, gated v0.2
concern (see [Roadmap](#roadmap)).

> **Status:** scaffolding pass. The package, finding model, output adapters
> (SARIF 2.1.0 + HackerOne markdown), and CLI surface are in place and tested.
> The SSRF detection/confirmation engine is the v0.1 build and is **not yet
> implemented** -- every scan/recon/generate subcommand currently exits with
> `NotImplementedError`. See [`V0.1-CRITERIA.md`](V0.1-CRITERIA.md) for the
> build contract and [`RESEARCH.md`](RESEARCH.md) for the niche brief.

## Ethical Use

You are responsible for ensuring you have authorization to test any target.
Only scan systems you own or have explicit written permission to test. SSRF
testing reaches internal and cloud-metadata surface by design; running it
against unauthorized targets may violate computer-fraud laws. The authors accept
no liability for misuse.

## Install

Requires Python 3.13+.

```bash
git clone https://github.com/bugsyhewitt/wraith
cd wraith
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

For the hermetic test stack (respx, pytest-httpserver, pytest-socket, dnslib):

```bash
pip install -e ".[dev]"
```

> **Note:** wraith depends on `h1-reporter` (a git dependency) and, once built,
> on the shared `scan-primitives` HTTP client. `scan-primitives` is spec-only at
> this pass and is therefore a commented `# TODO` in `pyproject.toml`, not yet a
> hard install requirement.

## Scope file format

Scope is safety-critical for offensive tooling: an out-of-scope request is
real-world harm. Every wraith request is checked against a scope allowlist
*before any socket is opened* (enforced by `scan-primitives` once wired).

A plain-text file, one entry per line:
- Hostnames: `api.example.com`
- IP addresses: `10.0.0.1`
- CIDR blocks: `192.168.1.0/24`

Lines starting with `#` are ignored. Example `scope.txt`:

```
# Production targets
api.example.com
10.20.30.0/24

# Staging
staging.example.com
```

Pass it with `--scope-file scope.txt`.

## Usage

wraith is organized into subcommands. **All subcommands are v0.1-pending in this
scaffolding pass** -- the parser, flags, and help are wired and tested, but the
handlers raise `NotImplementedError` until the detection engine lands.

```bash
wraith --version          # -> wraith 0.1.0   (works now)
wraith --help             # subcommand overview (works now)
```

### `wraith scan` -- detect + confirm SSRF  *(v0.1-pending)*

The core engine: run the filter-bypass mutator catalog against a marked
injection point and confirm hits out-of-band.

```bash
# Target URL with an explicit injection marker
wraith scan -u "https://app.example.com/proxy?url=FUZZ" --marker FUZZ \
    --scope-file scope.txt --cloud-metadata --oob https://oob.example.net

# Raw HTTP request file (SSRFmap parity), injection point named by param
wraith scan -r request.txt --param url --oob https://oob.example.net --mcp
```

- `-u/--target URL` &mdash; target URL to test.
- `-r/--request-file FILE` &mdash; raw HTTP request to replay (SSRFmap parity).
- `--marker STR` &mdash; token in the URL/request that wraith replaces with each
  payload variant (default `FUZZ`).
- `--param NAME` &mdash; explicitly mark the injection point (query param,
  header, body field, or path segment).
- `--cloud-metadata` &mdash; run the cloud-metadata detection probes.
- `--oob COLLAB_URL` &mdash; interactsh-compatible OOB collaborator for
  blind-SSRF confirmation (a DNS-only callback still counts as CONFIRMED).
- `--mcp` &mdash; include the MCP / AI-infra SSRF detection catalog.
- `--format {json,text,h1md,sarif}` &mdash; finding output format.

### `wraith dict` -- dict:// read-only recon  *(v0.1-pending)*

Read-only `dict://` recon through an SSRF primitive: port/banner grab, Redis
`INFO`, Memcached `stats`. Read-only by definition; no target state change.

```bash
wraith dict -u "https://app.example.com/fetch?url=FUZZ" --scope-file scope.txt
```

### `wraith gopher` -- gopher:// payload generator  *(v0.1-pending)*

Generate a `gopher://` payload (RESP / FastCGI byte encoding, correct `%0d%0a`,
single/double URL-encode toggle) and print it for the operator. **Dry-run only**
in v0.1 -- it emits a payload, it never fires a weaponized sequence.

```bash
wraith gopher --protocol redis           # emit a Redis RESP gopher payload
wraith gopher --protocol fastcgi --double-encode
```

## Modules

| Module | Role | Status |
|---|---|---|
| `wraith.findings` | The pinned suite `Finding` dataclass (lowercase severity, confidence, `cwe_id=918`, OOB proof). | implemented |
| `wraith.sarif` | `to_sarif(findings) -> dict` &mdash; SARIF 2.1.0 export. | implemented |
| `wraith.reporting` | `to_h1md(findings) -> str` &mdash; HackerOne markdown via `h1-reporter`. | implemented |
| `wraith.client` | Scope-enforced HTTP boundary (backed by `scan-primitives`). | **stub** |
| `wraith.cli` | argparse CLI: `scan` / `dict` / `gopher`. | surface only |
| mutator engine, metadata probes, OOB engine, protocol modules, MCP catalog | The v0.1 detection/confirmation build. | **not built** |

## Example output

Once detection is built, a confirmed cloud-metadata SSRF renders to HackerOne
markdown (`--format h1md`) roughly as:

```markdown
# wraith SSRF findings

**Total findings:** 1

## Finding 1: SSRF to AWS IMDS via url query parameter

**Severity:** HIGH

### Description

SSRF reached `https://app.example.com/proxy?url=http://169.254.169.254/latest/meta-data/`
via the `query:url` injection point. Filter-bypass variant: `dword-decimal:2852039166`.
Confirmed out-of-band -- the server initiated a callback to the wraith canary.
...
```

The same finding exports to SARIF 2.1.0 via `--format sarif` for GitHub Code
Scanning / IDE ingestion. The `Finding` -> SARIF and `Finding` -> h1md adapters
are implemented and unit-tested now (`tests/test_findings.py`); only the code
that *produces* findings from a live scan is pending.

## Development

```bash
pip install -e ".[dev]"

# Fast unit tier (no network, no build) -- the finding/SARIF/h1md tests:
pytest -m "not ship_gate"

# Full suite incl. the wheel ship-gate (builds + installs into a fresh venv):
pytest
```

The unit tier runs with sockets disabled (via `pytest-socket`, when installed)
so any accidental real egress fails loudly -- the enforcement baseline for the
hermetic test tiers described in `V0.1-CRITERIA.md`.

## Roadmap

The v0.1 build implements the detection/confirmation engine per
[`V0.1-CRITERIA.md`](V0.1-CRITERIA.md). The following are **explicitly NOT in
v0.1** (deferred):

- **Weaponized `gopher://` exploitation** (Redis cron/SSH/`MODULE LOAD`,
  FastCGI php-fpm RCE) &mdash; v0.2, behind a sandboxed `--exploit`/`--dangerous`
  gate.
- **Using harvested cloud credentials** (SDK calls to enumerate/exfil)
  &mdash; detection emits the finding; credential use is a separate dangerous
  pivot.
- **Reverse-shell / connect-back listener** &mdash; weaponization.
- **Request-smuggling desync** to reach enforced IMDSv2 &mdash; that is
  `doppelganger`'s surface.
- **Self-hosted DNS-rebinding orchestration** &mdash; v0.1 may *emit* rebind
  hostnames pointing at public rebind services; hosting the flip is deferred.
- **Full CVE template library** &mdash; seed a handful, defer the catalog.
- Extended protocol weaponization (MySQL/Postgres/Zabbix/Memcached), advanced
  WAF-evasion beyond the core mutators, and GUI/proxy integration.

## License

MIT &mdash; see [LICENSE](LICENSE).

## Attribution

wraith stands on the shoulders of prior SSRF work:

- **[SSRFmap](https://github.com/swisskyrepo/SSRFmap)** by Swissky &mdash; the
  dead-ancestor SSRF scanner; the source of the raw-request + injection-marker
  workflow and the bypass-pattern catalog wraith modernizes.
- **[Gopherus](https://github.com/tarunkant/Gopherus)** by Tarun Kant Gupta
  &mdash; the reference for `gopher://` RESP / FastCGI payload structure.
- **[interactsh](https://github.com/projectdiscovery/interactsh)** by
  ProjectDiscovery &mdash; the out-of-band interaction protocol wraith's OOB
  confirmation engine speaks.
- Cloud-metadata and MCP SSRF technique authors cited inline in
  [`RESEARCH.md`](RESEARCH.md) and against the specific CVEs in
  [`V0.1-CRITERIA.md`](V0.1-CRITERIA.md) (e.g. Typebot IMDSv2 header-injection
  CVE-2025-64709; Fetch MCP CVE-2025-65513; MCP-Atlassian CVE-2026-27826;
  LangChain `RecursiveUrlLoader` CVE-2026-26019 / -27795).

See NOTICE for details where applicable.
