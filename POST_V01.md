# wraith — Post-v1.0 Roadmap

**IMPORTANT — what is already live:** The v0.2 weaponized `gopher://` exploit
gate (`--exploit`) shipped in PR #1 and is fully live. `exploit.py` contains
`redis_cron_payload`, `redis_ssh_payload`, and `fastcgi_rce_payload` behind an
`--exploit` flag + interactive confirmation in `cli.py`. This is **not** a
roadmap item. Do not re-plan or re-implement it.

---

## Still-deferred items

The items below were explicitly listed as NOT in v0.1 (see
[`V0.1-CRITERIA.md`](V0.1-CRITERIA.md)) and have not shipped through v1.0.0.
Each item records what it is, why it is gated or deferred, and what must be
true before it can land.

---

### 1. Redis `MODULE LOAD` RCE

**What it is.** The v0.2 `--exploit` gate ships Redis cron-job, SSH
authorized-keys, and PHP-FPM FastCGI payloads via `gopher://`. `MODULE LOAD`
is a further Redis exploitation path: if the operator can stage a compiled
Redis module (`.so`) at a reachable URL, `MODULE LOAD <url>` loads it into the
running Redis process and executes arbitrary code with Redis's OS privileges —
a significantly more capable post-exploitation primitive than cron or SSH key
writes.

**Safety rationale.** `MODULE LOAD` requires a pre-staged malicious `.so`
binary and a Redis instance that has not set `enable-debug-command no`. The
blast radius is immediate arbitrary code execution with no additional steps.
Shipping this without a carefully scoped opt-in (separate from `--exploit`)
would make wraith trivially weaponizable against unintended targets if a scope
file is misconfigured. It is also narrower than cron/SSH in landing conditions.

**Prerequisites.** A module-staging helper or documentation for the operator to
stage the `.so`; a separate `--module-load` gate distinct from `--exploit`; a
test against a Redis mock that simulates the `MODULE LOAD` response.

---

### 2. Harvested cloud-credential SDK use (enumerate and exfil)

**What it is.** wraith's IMDS probes emit findings when they recover cloud
credentials (AWS `access_key_id`/`secret_access_key`/`session_token`, GCP OAuth
token, Azure managed-identity token). This deferred item is the next step: use
the harvested credential with the cloud provider's SDK (boto3, google-cloud,
azure-identity) to enumerate accessible resources — S3 buckets, IAM roles, VM
instances, secrets — and optionally exfiltrate selected data.

**Safety rationale.** Credential use is a privilege escalation step beyond
detection. An SSRF that only reads the IMDS metadata page is a critical finding
on its own; using the credential actively expands the attack surface against the
target's cloud environment in ways that may be out-of-scope for the engagement
or may trigger cloud-provider alerting. This step requires explicit, verified
operator authorization beyond what the scan scope file provides.

**Prerequisites.** An `--use-creds` gate with a mandatory confirmation step;
optional output to a structured credential dump file; SDK dependency
declarations kept optional (extras-require); a sandboxed test against a
localstack or azure-emulator fixture.

---

### 3. Reverse-shell / connect-back listener

**What it is.** SSRFmap (the ancestor) included the ability to chain an SSRF
into a reverse-shell payload and set up a listener for the connect-back.
wraith explicitly deferred this to keep v0.1 detect-and-confirm-only.

**Safety rationale.** A reverse shell gives the operator (or anyone who can
supply a scope file) interactive OS access on the target. This is weaponization
at the highest severity — equivalent to a Metasploit `shell` module. It must
be behind the most conservative opt-in gate in wraith, with scope validation
that confirms the operator's authorization includes post-exploitation, and
preferably a separate sub-command to make it impossible to trigger
accidentally.

**Prerequisites.** A post-exploitation subcommand (e.g. `wraith shell`) fully
separate from `wraith scan`; a mandatory out-of-band authorization token
(separate from the scope file); a loopback-only CI test fixture. This item
should not land until wraith has a mature audit-log feature so operator actions
are recorded.

---

### 4. Request-smuggling desync to reach enforced IMDSv2

**What it is.** AWS IMDSv2 requires a `PUT /latest/api/token` hop-limited
request before metadata reads. Enforced IMDSv2 rejects `GET` requests without
a token. Request-smuggling desync techniques can bypass the IMDSv2 hop-limit
enforcement by treating the HTTP/1.1 desync as a SSRF primitive that smuggles
the PUT inside what the front-end sees as a single GET.

**Safety rationale.** This is a complex attack chain that overlaps substantially
with HTTP request smuggling as a standalone technique. The primary maintainer of
this surface in the necromancer suite is **doppelganger** (which owns
request-smuggling desync as its core niche). Landing this in wraith risks
duplicating doppelganger logic and creating two half-implemented versions of the
same technique.

**Recommendation.** See doppelganger for the canonical smuggling engine. If
doppelganger exposes a library interface, wraith can call it rather than
reimplementing. This item should not land until doppelganger's smuggling
primitives are stable.

---

### 5. Self-hosted DNS-rebinding orchestration

**What it is.** wraith's v0.1 mutator engine emits rebind hostnames that point
at public DNS-rebinding services (rbndr.us, 1u.ms). Those services flip the DNS
response between an allowed external IP and the internal SSRF target, bypassing
same-origin and SSRF filters that check the initial resolution but not
subsequent ones. Hosting the DNS flip locally (running a wraith-controlled
authoritative nameserver) eliminates dependency on third-party services and
allows wraith to control the rebind timing precisely.

**Safety rationale.** A self-hosted rebinding server requires outbound DNS
authority, which has infrastructure and abuse-surface implications. The operator
must own or control the domain used for rebinding. Public services (rbndr.us)
handle these prerequisites externally; bringing the server in-process extends
wraith's infrastructure footprint.

**Prerequisites.** Integration with `dnslib` (already used in the test suite) to
run a controlled authoritative resolver; a domain registration workflow or
documentation; rate-limiting and access controls on the rebind listener to
prevent it from being used as an open resolver; a scope-file check that the
rebind domain is operator-controlled.

---

### 6. Full CVE template library

**What it is.** wraith v0.1 seeds a handful of curated, version-gated SSRF CVE
detection signatures (Typebot, Fetch MCP, MCP-Atlassian, LiteLLM, LangChain).
The deferred item is a maintained catalog covering high-value SSRF CVEs across
major frameworks and products: Ivanti Connect Secure, GitLab Runner, Spring
Boot Actuator, Next.js middleware, Grafana image renderer, and others.

**Safety rationale.** A CVE template library is lower risk than weaponization
items — templates detect, they do not exploit. The primary concern is false
positives from poorly version-gated signatures and the maintenance burden of
keeping versions accurate as products patch. Each template must carry a
version-gate and a CVE citation. Unmaintained templates that fire against patched
targets waste operator time and credibility.

**Prerequisites.** A template schema (YAML or TOML) for the detection signature,
version gate, CVE ID, and severity; a `wraith update-templates` subcommand or
mechanism to pull updates without a full release; a CI integration test that
confirms each template fires against a mock fixture at the target version and
does not fire against a mock at the patched version.

---

### 7. Extended protocol weaponization

**What it is.** The v0.2 `--exploit` gate covers Redis (cron, SSH, MODULE LOAD)
and PHP-FPM FastCGI. This item extends `gopher://`-based weaponization to
additional protocols: MySQL (authentication bypass via pre-auth RCE for older
versions), PostgreSQL (COPY TO/FROM for file read/write), Zabbix agent
(command execution via `system.run`), and Memcached (cache poisoning or slot
dump).

**Safety rationale.** Each additional protocol extends the destructive surface.
MySQL and PostgreSQL payloads can read and write arbitrary files on the database
host. Memcached cache poisoning affects application state for all users of the
target service. These must be behind protocol-specific opt-in flags (e.g.
`--exploit-mysql`, `--exploit-postgres`) in addition to the existing `--exploit`
gate, and must include a confirmation step that names the specific action and
its side effects.

**Prerequisites.** Verified gopher payload encodings for each protocol (reference
Gopherus for MySQL/Postgres byte structure); hermetic test fixtures (a local
MySQL and Postgres container in the Tier 3 docker test suite); explicit scope
documentation that the target service is in-scope for destructive testing.

---

### 8. Advanced WAF-evasion techniques

**What it is.** wraith's v0.1 mutator engine covers the standard bypass catalog
(IP encodings, userinfo, fragment, backslash, whitespace, CRLF, malformed
scheme). Advanced WAF evasion adds: Unicode normalization tricks, IDN homograph
attacks (e.g. `аpple.com` with Cyrillic `а`), HTTP parameter pollution, chunked
transfer encoding bypass, and WAF fingerprinting to select the most effective
bypass variant per WAF vendor.

**Safety rationale.** These techniques are bypass-only — they do not introduce
new exploit primitives. The risk is primarily false-positive noise if WAF
fingerprinting misidentifies the vendor and applies the wrong bypass catalog.
WAF fingerprinting also involves active probing of the WAF's error responses,
which may be out-of-scope.

**Prerequisites.** A WAF fingerprinting module that infers vendor from HTTP
response headers and error page signatures; an extended mutator catalog with
per-WAF applicability metadata; Unicode normalization tests against a
Tier 0 hermetic test suite (no network required).

---

### 9. GUI / proxy integration

**What it is.** Integration with Burp Suite (as a Burp extension via the
Montoya API) or OWASP ZAP (via the ZAP API) so operators can run wraith's
mutator and OOB confirmation engine directly from a proxy intercept session
without exporting raw request files. Also includes a minimal web UI for
scan configuration and finding review.

**Safety rationale.** GUI/proxy integration is primarily an ergonomics feature.
The main risk is scope creep: proxy integration requires maintaining a parallel
code path that is exercised differently from the CLI and may diverge from
wraith's scope enforcement.

**Prerequisites.** Stable CLI API (wraith is at v1.0.0 — prerequisites met);
Burp/ZAP extension packaging (Jython for ZAP, Java for Montoya — both require a
build path separate from the Python packaging); a design decision on whether the
GUI is a separate package or bundled.
