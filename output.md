# wraith v0.8.0 — Worker Output

## Improvement shipped

**Open-redirect chaining variants in the filter-bypass mutator catalog**

### What

Added `redirect_chain_variants()` to `wraith/mutators.py` and wired it into `build_variants()`, the scan engine, and the CLI.

When a known open-redirect endpoint exists on a trusted domain, wraith now generates **three redirect-chain bypass variants** per internal SSRF target:

| Variant name | Technique | Bypass target |
|---|---|---|
| `redirect-chain-raw` | Internal URL embedded verbatim | Redirectors that pass destination unchanged |
| `redirect-chain-enc` | Internal URL percent-encoded once | Redirectors that call `unquote()` once before following |
| `redirect-chain-double-enc` | Internal URL double-encoded | WAFs that only inspect outer encoding; redirectors that decode twice |

All three variants are in the new `"redirect-chain"` family and appear **first** in the mutator ordering — the highest-priority bypass class (per V0.1-CRITERIA.md #2: "redirect-chain + @ → DNS-rebind → parser-differential → encoding → scheme").

### Why this was chosen

The README and V0.1-CRITERIA.md #2 both explicitly list "open-redirect chaining" as a feature of the filter-bypass mutator catalog. The criteria even specify "redirect-chain" as the first family in the default ordering. It was listed but not implemented — a documented gap in a core module.

Real-world impact: domain-allowlist SSRF filters are common in modern apps. A filter that checks `url.startswith("https://trusted.com/")` is bypassed by `https://trusted.com/redir?next=http://169.254.169.254/latest/meta-data/`. The three encoding variants additionally bypass WAF layers that inspect the outer URL before the redirect handler decodes it.

### Files changed

| File | Change |
|---|---|
| `src/wraith/mutators.py` | Added `redirect_chain_variants()`, updated `build_variants()` to accept `redirect_url`/`redirect_marker` params, updated `__all__` and module docstring |
| `src/wraith/engine.py` | Added `redirect_url`/`redirect_marker` params to `run_scan()`, passes them through to `build_variants()` |
| `src/wraith/cli.py` | Added `--redirect-url REDIR_URL` argument to `wraith scan`, wires it into `run_scan()` |
| `src/wraith/__init__.py` | Version bumped: `0.7.0` → `0.8.0` |
| `pyproject.toml` | Version bumped: `0.7.0` → `0.8.0` |
| `README.md` | Updated status, documented `--redirect-url`, updated modules table and roadmap |
| `tests/test_mutators.py` | Added 14 new Tier-0 tests covering: exact-byte assertions on all 3 variants, custom marker, ordering, integration with `build_variants`, backward compatibility |
| `tests/test_cli.py` | Updated `test_version` to expect `wraith 0.8.0` |

### Test results

```
249 passed, 5 deselected in ~13s
```

14 new tests added (235 → 249). All pass. See `test-output.txt` for full output.

### CLI example

```bash
# Chain through an open redirect on a trusted domain
wraith scan \
  -u "https://app.example.com/fetch?url=FUZZ" \
  --scope-file scope.txt \
  --redirect-url "https://trusted.example.com/redir?next=FUZZ" \
  --cloud-metadata \
  --format json
```

Emits redirect-chain variants like:
```
https://trusted.example.com/redir?next=http://169.254.169.254/latest/meta-data/
https://trusted.example.com/redir?next=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F
https://trusted.example.com/redir?next=http%253A%252F%252F169.254.169.254%252Flatest%252Fmeta-data%252F
```

The outer URLs pass a `trusted.example.com` allowlist check; the sink follows to 169.254.169.254.
