# Changelog

All notable changes to wraith are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Added
- GitHub Actions CI workflow (`pytest` on push/PR) (#13)
- Comic card image in README header

---

## [1.0.0] — 2026-08-xx

### Changed
- Quality sweep: dedup, dead-code removal, efficiency pass (#12)

### Added
- v1.0.0 release marker (#11)

---

## [0.9.2]

### Added
- Azure managed-identity credential endpoint in IMDS probe catalog and via-SSRF
  injection list (`169.254.169.254/metadata/identity/oauth2/token`) (#10)
- Critical-severity finding for harvested OAuth2 `access_token`
- `azure-managed-identity` classifier checked before `gcp` to prevent token
  response misclassification (Azure MI returns the disambiguating `resource`
  field; GCP does not)

---

## [0.9.1]

### Added
- `--timeout` flag for `wraith scan`: expose per-request timeout (previously
  hardcoded at 10 s) so operators can tune it for slow internal targets or fast
  infrastructure (#9)

---

## [0.9]

### Added
- `--target-file` multi-target batch scanning: pass a newline-delimited file of
  target URLs; wraith runs the full scan engine against each in sequence,
  accumulating and deduplicating findings before emitting the combined result.
  Blank lines and `#` comments are ignored. Cannot be combined with
  `-r/--request-file` (#8)

---

## [0.8]

### Added
- Open-redirect chaining (`--redirect-url`): when a known open-redirect on a
  trusted domain is available, wraith generates three bypass variants (raw,
  URL-encoded, double-encoded) for each internal SSRF target and places them at
  the head of the mutator ordering. Bypasses domain-allowlist filters that only
  check the outer URL's hostname (#7)

---

## [0.7]

### Added
- `file://` SSRF detection (`wraith probe --scheme file`): inject `file:///path`
  at the SSRF injection point and classify echoed responses for local-file-content
  signatures (`/etc/passwd`, `/etc/hosts`, `/proc/version`,
  `/proc/self/environ`, and Windows equivalents). Critical-severity finding when
  confirmed; read-only by nature (#6)

---

## [0.6]

### Added
- SSRF-based internal port scanner (`wraith portscan`): fire
  `http://<host>:<port>/` at the marked SSRF injection point for each target port
  and classify results as OPEN / FILTERED / CLOSED using response-time and
  service-banner differentials. 25 default ports; accepts `--ports 80,443,6379`
  or `--ports 8000-8100`. Emits medium (banner-confirmed) or info (anomalous
  timing) findings (#5)

---

## [0.5]

### Added
- Hetzner cloud-metadata provider in the IMDS probe catalog; catalog now covers
  7 providers (AWS IMDSv1/v2, GCP, Azure, Alibaba, Oracle, DigitalOcean,
  Hetzner) (#4)

---

## [0.4]

### Added
- `ldap://` scheme probe (`wraith probe --scheme ldap`): inject non-HTTP LDAP
  scheme URLs at the marked SSRF injection point and classify LDAP Root DSE
  (LDIF signatures) in the echoed response. Works through curl-backed SSRF
  sinks (#3)
- `tftp://` scheme probe (`wraith probe --scheme tftp`): classify TFTP
  file-content (`/etc/passwd`, `/boot.ini`) in echoed responses (#3)

---

## [0.3]

### Added
- MCP internal-SSRF discovery (`--mcp`): probes the injection point for internal
  MCP servers at well-known paths (Fetch MCP CVE-2025-65513, Microsoft MarkItDown
  MCP, MCP-Atlassian CVE-2026-27826, LiteLLM `/v1/rag/ingest`, LangChain
  `RecursiveUrlLoader` CVE-2026-26019/-27795). Version-gated signatures reuse the
  injection + OOB + finding-schema machinery (#2)

---

## [0.2]

### Added
- Weaponized `gopher://` exploit gate behind `--exploit` + interactive
  confirmation prompt: Redis cron-job RCE payload (`redis_cron_payload`), Redis
  authorized-keys SSH payload (`redis_ssh_payload`), and PHP-FPM FastCGI RCE
  payload (`fastcgi_rce_payload`). Destructive sequences are sandboxed and
  require explicit double-opt-in (#1)

---

## [0.1]

### Added
- Filter-bypass mutator engine: IP encodings (dword-decimal, hex dotted +
  dotless, octal dotted + dotless, shorthand `127.1`/`0`, IPv4-mapped IPv6
  `[::ffff:…]`, IPv6 loopback/link-local/ULA), userinfo `@` (incl. multi-`@`),
  fragment `#`, backslash `\`, whitespace/tab, CRLF, malformed/long scheme
- Cloud-metadata IMDS probes: AWS IMDSv1 GET and IMDSv2 PUT-token→GET handshake
  (incl. header-injection variant for Typebot CVE-2025-64709), GCP, Azure,
  Alibaba, Oracle, DigitalOcean
- OOB confirmation engine: interactsh-compatible client, unique token per probe,
  DNS and HTTP capture, polling with late-hit window. DNS-only callback counts as
  CONFIRMED
- `dict://` read-only recon (port/banner, Redis `INFO`, Memcached `stats`)
- `gopher://` payload generator (RESP + FastCGI byte encoders) — dry-run by
  default, emits payload for operator; does not fire weaponized sequences
- Input flexibility: raw HTTP request file (SSRFmap parity) and CLI flags;
  injection point explicitly markable (query param / header / body field / path
  segment)
- Async/concurrent execution via `httpx` + `asyncio`
- Suite-standard findings (target, injection vector, payload variant, response
  signature, OOB proof, severity, timestamps) + SARIF 2.1.0 export +
  HackerOne markdown via `h1-reporter`
- Hermetic test suite (Tier 0 unit, Tier 1 mocked HTTP with `respx`, Tier 2
  local fixture servers with `pytest-httpserver` and `dnslib`) + `ship_gate`
  wheel test
- Scope enforcement via `scan-primitives` shared library (scope-file, rate
  limiting, proxy awareness)

---

[Unreleased]: https://github.com/bugsyhewitt/wraith/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/bugsyhewitt/wraith/compare/v0.9.2...v1.0.0
[0.9.2]: https://github.com/bugsyhewitt/wraith/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/bugsyhewitt/wraith/compare/v0.9...v0.9.1
[0.9]: https://github.com/bugsyhewitt/wraith/compare/v0.8...v0.9
[0.8]: https://github.com/bugsyhewitt/wraith/compare/v0.7...v0.8
[0.7]: https://github.com/bugsyhewitt/wraith/compare/v0.6...v0.7
[0.6]: https://github.com/bugsyhewitt/wraith/compare/v0.5...v0.6
[0.5]: https://github.com/bugsyhewitt/wraith/compare/v0.4...v0.5
[0.4]: https://github.com/bugsyhewitt/wraith/compare/v0.3...v0.4
[0.3]: https://github.com/bugsyhewitt/wraith/compare/v0.2...v0.3
[0.2]: https://github.com/bugsyhewitt/wraith/compare/v0.1...v0.2
[0.1]: https://github.com/bugsyhewitt/wraith/releases/tag/v0.1
