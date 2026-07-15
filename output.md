# wraith v0.9.1 — Worker Output

## Improvement shipped

**`--timeout` flag for `wraith scan`**

### What

Added `--timeout SECS` to `wraith scan`. The engine (`wraith.engine.run_scan`)
has always accepted a `timeout` parameter (default 10.0 s), but the CLI never
exposed it — it was silently hardcoded. This meant operators scanning slow
internal targets (e.g. an application that asynchronously fetches internal
URLs before returning a response) could not extend the timeout, and operators
on fast infrastructure could not tighten it to accelerate scans.

`portscan` already had `--timeout`. This closes the parity gap.

Key behaviors:

- Default: `10.0` seconds (unchanged from the prior hardcoded value; no
  regression for existing users).
- Accepts any positive float: `--timeout 0.5` (aggressive), `--timeout 60.0`
  (very slow targets).
- Threaded through to `run_scan(timeout=...)` via `_run_single_scan()`, which
  means it applies to every SSRF probe request fired by the scan engine.
- Works with all input modes: `-u URL`, `-r FILE`, `--target-file FILE`.

### Files changed

| File | Change |
|---|---|
| `src/wraith/cli.py` | Added `--timeout FLOAT` arg to `scan` subparser; passed `timeout=getattr(args, "timeout", 10.0)` to `run_scan()` in `_run_single_scan()` |
| `src/wraith/__init__.py` | Version bumped: `0.9.0` → `0.9.1` |
| `pyproject.toml` | Version bumped: `0.9.0` → `0.9.1` |
| `README.md` | Updated status line and `--version` example; added `--timeout` to the `wraith scan` parameter list; updated Roadmap |
| `tests/test_cli.py` | Updated `test_version` to expect `wraith 0.9.1`; added 4 new tests |

### Test results

```
260 passed, 5 deselected in ~14s
```

4 new tests added (256 → 260). All pass. See `test-output.txt` for full output.

### New tests

| Test | Coverage |
|---|---|
| `test_scan_default_timeout_is_ten_seconds` | Parser default is 10.0 s (no regression) |
| `test_scan_custom_timeout_accepted` | `--timeout 30.0` is stored on the namespace |
| `test_scan_timeout_passed_to_run_scan` | `run_scan` receives `timeout=42.5` when `--timeout 42.5` is passed |
| `test_scan_default_timeout_reaches_run_scan` | `run_scan` receives `timeout=10.0` when `--timeout` is omitted |

### CLI example

```bash
# Scan a slow target: extend to 30 s so the application has time to
# fetch the internal URL and return a response.
wraith scan \
  -u "https://api.example.com/proxy?url=FUZZ" \
  --scope-file scope.txt \
  --cloud-metadata \
  --timeout 30.0 \
  --format json

# Scan fast infrastructure: tighten to 2 s to accelerate batch runs.
wraith scan \
  --target-file targets.txt \
  --scope-file scope.txt \
  --timeout 2.0 \
  --format sarif > findings.sarif
```
