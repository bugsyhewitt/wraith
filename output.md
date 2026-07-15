# wraith v1.0.0 — Worker Output

## Release shipped

**v1.0.0 — stable release cut**

### What

Bumped wraith from v0.9.2 to v1.0.0 — the first stable release of the SSRF
detection and out-of-band confirmation engine. The v0.1 criteria are fully met
and every feature through v0.9.2 is present and tested.

No new features were added; this is a clean version-bump release to mark the
engine as stable.

### Summary of the engine at v1.0.0

- Filter-bypass mutator catalog (IP encodings, `@`/`#`/`\`, CRLF, scheme, rebind, open-redirect chaining)
- Cloud-metadata probes: AWS IMDSv1/IMDSv2 (including header-injection variant), GCP, Azure instance + managed-identity (critical severity), Alibaba, Oracle, DigitalOcean, Hetzner
- OOB confirmation: interactsh-compatible client + local dnslib DNS/HTTP collaborator
- `dict://` read-only recon; `gopher://` payload generator (RESP + FastCGI)
- Weaponized `gopher://` exploit sequences behind `--exploit` gate (v0.2): redis-cron, redis-ssh, fastcgi-rce
- MCP / AI-infra detection catalog (5 CVE signatures) + internal MCP server discovery via SSRF
- `ldap://` and `tftp://` non-HTTP scheme probes (v0.4)
- `file://` local file read via SSRF — critical severity (v0.7)
- SSRF-based internal port scanner (`wraith portscan`, v0.6)
- Open-redirect chaining (`--redirect-url`, v0.8)
- `--target-file` multi-target batch scanning (v0.9)
- `--timeout` per-request tuning (v0.9.1)
- Azure managed-identity credential endpoint (v0.9.2)
- SARIF 2.1.0 export (`--format sarif`)
- HackerOne markdown output (`--format h1md`) via `h1-reporter`
- Hermetic test suite: 267 tests, 0 failures

### Files changed

| File | Change |
|---|---|
| `pyproject.toml` | `version` bumped `0.9.2` → `1.0.0` |
| `src/wraith/__init__.py` | `__version__` bumped `0.9.2` → `1.0.0` |
| `tests/test_cli.py` | `test_version` assertion updated to `"wraith 1.0.0"` |
| `tests/test_wheel_ship_gate.py` | All version strings updated to `1.0.0` (were stale at `0.6.0`/`0.1.0`) |
| `README.md` | Status line rewritten to reflect v1.0.0 stable; `--version` example updated |
| `output.md` | This file |
| `test-output.txt` | Updated test run output |

### Test results

```
267 passed, 5 deselected in 14.08s
```

All 267 non-ship-gate tests pass. No regressions.

### PR

v1.0.0 release — see PR opened against main.
