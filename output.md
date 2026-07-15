# wraith v0.9.0 — Worker Output

## Improvement shipped

**`--target-file` multi-target batch scanning**

### What

Added `--target-file FILE` to `wraith scan`. When provided, wraith reads a
newline-delimited list of target URLs from the file (one per line, `#` comments
and blank lines ignored), runs the full scan engine against each URL in
sequence, deduplicates findings by ID across all targets, and emits a single
combined findings list.

This enables batch scanning of multiple injection endpoints in a single
invocation — the common case during a pentest where the target application has
several URL parameters that accept URLs (a webhook, a proxy, a fetcher, etc.).

Key behaviors:
- Blank lines and lines starting with `#` are silently skipped.
- Fails cleanly (exit 2) if the file cannot be opened or contains no valid URLs.
- Cannot be combined with `-r/--request-file` (mutually exclusive).
- Deduplication is by finding `id` — two identical targets that return the same
  finding only emit it once in the output.
- Works with all output formats: `json`, `text`, `h1md`, `sarif`.

### Files changed

| File | Change |
|---|---|
| `src/wraith/cli.py` | Added `--target-file` arg to `_add_target_group()`; added `_read_target_file()` helper; factored `_run_single_scan()` out of `_cmd_scan`; updated `_cmd_scan` to handle multi-target loop with deduplication |
| `src/wraith/__init__.py` | Version bumped: `0.8.0` → `0.9.0` |
| `pyproject.toml` | Version bumped: `0.8.0` → `0.9.0` |
| `README.md` | Updated status line, version in `--version` example, documented `--target-file` in the `wraith scan` section (usage example + parameter description + file format block), updated roadmap |
| `tests/test_cli.py` | Updated `test_version` to expect `wraith 0.9.0`; added 7 new tests |

### Test results

```
256 passed, 5 deselected in ~14s
```

7 new tests added (249 → 256). All pass. See `test-output.txt` for full output.

### New tests

| Test | Coverage |
|---|---|
| `test_target_file_basic_scan` | Single URL in `--target-file` produces same findings as `-u` (live mock) |
| `test_target_file_multi_url_deduplicates` | Identical URL listed twice yields no duplicate finding IDs |
| `test_target_file_skips_comments_and_blanks` | `_read_target_file` unit: only non-comment, non-blank lines returned |
| `test_target_file_empty_raises_systemexit` | All-comment file exits 2 with "no target URLs" message |
| `test_target_file_missing_file_raises_systemexit` | Nonexistent file exits 2 with "cannot open" message |
| `test_target_file_and_request_file_are_mutually_exclusive` | `--target-file` + `-r` → exit 2 "mutually exclusive" |
| `test_scan_no_input_returns_2` | scan with no `-u`, `-r`, `--target-file` → exit 2 |

### CLI example

```bash
# Create a target file
cat > targets.txt <<'EOF'
# Production endpoints
https://api.example.com/proxy?url=FUZZ
https://api.example.com/fetch?src=FUZZ

# Staging
https://staging.example.com/webhook?callback=FUZZ
EOF

# Scan all three endpoints, emit combined findings as SARIF
wraith scan \
  --target-file targets.txt \
  --scope-file scope.txt \
  --cloud-metadata \
  --format sarif > findings.sarif
```
