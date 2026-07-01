# wraith — Research Brief

**Tool:** wraith  
**Class:** SSRF (Server-Side Request Forgery) — fuzz, exploit, pivot  
**Status:** registered, not yet built  
**[CHECK: confirm codename before first build]**

---

## Dead Ancestor

**SSRFmap** (`github.com/swisskyrepo/SSRFmap`) — Python 3.4-era SSRF scanner. Last substantive merge years ago. No modern cloud-metadata endpoint coverage (AWS IMDSv2, GCP IMDS, Azure IMDS, Alibaba). No MCP-server SSRF support. DNS-rebinding and redirect-based filter bypasses are absent or minimal. Gopherus (`github.com/tarunkant/Gopherus`) — companion gopher-payload generator, also stale.

**Confirmation of "dead":** check last commit date, open issue age, and lack of IMDSv2 / `X-aws-ec2-metadata-token` support before first build to confirm the ancestor remains abandoned.

---

## Why the Niche Is Open

SSRF as a class is surging:
- Cloud-metadata SSRF is now a critical-severity finding on all major platforms (HackerOne, Bugcrowd, Intigriti)
- MCP-server SSRF CVEs emerged in early 2026 as AI-adjacent attack surface
- Modern filter bypasses (DNS rebinding, open redirects, IPv6, decimal/octal IP encoding) are poorly covered by existing headless tools
- No maintained, headless, CLI-first SSRF tool owns the 2025-2026 frontier
- Caido and Burp extensions cover it interactively but not headlessly

---

## Niche to Stake

### Core capability (inform v0.1 criteria)

1. **Metadata endpoint catalog** — curated, versioned catalog of cloud-provider SSRF targets:
   - AWS IMDSv1 (`169.254.169.254`) and IMDSv2 (token-based, TTL-1 hop-limit)
   - GCP IMDS (`metadata.google.internal`, `Metadata-Flavor: Google` header)
   - Azure IMDS (`169.254.169.254/metadata/instance`, `Metadata: true` header)
   - Alibaba Cloud IMDS
   - DigitalOcean, Oracle Cloud, Linode variants
   - Common internal service targets (Kubernetes API, etcd, Consul, Vault)

2. **Filter bypass techniques** — modular, pluggable bypass strategies:
   - DNS rebinding (external domain → 169.254.x.x on second resolution)
   - Open-redirect chaining (302/307 redirect at attacker-controlled host)
   - IP encoding variants (decimal, octal, hex, dotless, IPv6-mapped IPv4)
   - URL parsing quirks (@ in hostname, bracket notation, scheme injection)
   - Redirect-follow depth control

3. **OOB callback confirmation** — out-of-band interaction proof:
   - DNS callback (interactsh-compatible)
   - HTTP callback to attacker-controlled server
   - Blind vs. confirmed SSRF classification in output

4. **Protocol smuggling** — gopher:// and dict:// payload generation for:
   - HTTP request injection via gopher (Redis, Memcached, FastCGI)
   - SMTP / FTP enumeration via gopher
   - dict:// for banner grabbing

5. **Internal port scan via SSRF** — timing-based open/closed discrimination using response time differentials

6. **MCP-server SSRF** — scan for SSRF in MCP-compatible endpoints (early 2026 attack class)

### Suite integration (non-negotiable)
- Use the suite's shared `scan-primitives` HTTP client (scope-aware, rate-limited, proxy/Caido-aware). No bespoke HTTP plumbing.
- Emit findings in the canonical SARIF-compatible finding schema with HackerOne adapter. No bespoke output format.

---

## Prior Art to Study Before Building

| Tool | State | Notes |
|------|-------|-------|
| SSRFmap | Dead ancestor | Base for bypass patterns, do NOT copy Python 3.4-era approach |
| Gopherus | Dead ancestor | Gopher payload structure reference |
| interactsh | Active (projectdiscovery) | OOB callback — use as external dependency or protocol-compatible endpoint, not to build your own |
| httpx (projectdiscovery) | Active | Scope-aware HTTP — likely already in scan-primitives |
| Caido | Active (commercial) | Scope/proxy model to follow |

---

## Not in Scope (do not build, even if useful)

- Generic web scanner (that's ossuary's job)
- Full SSRF-to-RCE chain execution (out of scope for any tool in this suite)
- Cloud credential exfiltration automation beyond capturing the IMDS response
- Custom DNS server (use interactsh-compatible external)

---

## Open Questions for Overmind (resolve before v0.1 criteria)

1. Should wraith include the MCP-server SSRF class in v0.1, or is that a post-v0.1 direction?
2. Should OOB callback require interactsh or support a generic webhook URL?
3. Is gopher/dict protocol smuggling in v0.1 or post-v0.1 (it's niche but differentiating)?
4. Wave 1 budget (250K) — is that sufficient for the full metadata catalog + bypass engine, or should v0.1 scope to 2-3 bypass techniques and expand post-v0.1?
