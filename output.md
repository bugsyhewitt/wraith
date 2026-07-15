# wraith v0.9.2 — Worker Output

## Improvement shipped

**Azure managed-identity credential endpoint coverage**

### What

Added `169.254.169.254/metadata/identity/oauth2/token` (the Azure IMDS managed-identity
OAuth2 token endpoint) as a **critical-severity** probe, complementing the existing Azure
instance-metadata probe (`/metadata/instance`, high severity).

The existing Azure probe returns instance identity data (vmId, subscriptionId, etc.).
The managed-identity endpoint returns an OAuth2 `access_token` for the VM's assigned
managed identity — an actual harvested credential usable against Azure management APIs.
This is a critical finding and warrants a separate probe.

Key behaviors:

- New `MetadataProbe` for `azure-managed-identity` added to `wraith.metadata.CATALOG`.
  Sends `Metadata: true` header; omits `X-Forwarded-For` (Azure IMDS rejects it).
- Via-SSRF URL `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` added to `engine.METADATA_SSRF_URLS`, so `--cloud-metadata` injects it through the target's SSRF sink.
- `detect_from_response` (the via-SSRF response classifier) now checks `azure-managed-identity` **before** `gcp`. Both token types carry `access_token`/`token_type`/`expires_in`; only Azure MI responses include the disambiguating `resource` field.
- `_TITLE_LABELS` dict added to `_make_finding` so the finding title reads
  `"SSRF to Azure managed-identity credential endpoint"` instead of the raw
  uppercased provider key `"AZURE-MANAGED-IDENTITY instance-metadata endpoint"`.
- Constants `AZURE_MI_PATH` and `AZURE_MI_QUERY` exported from `wraith.metadata`
  for use in tests and future probes.

### Files changed

| File | Change |
|---|---|
| `src/wraith/metadata.py` | `AZURE_MI_PATH`/`AZURE_MI_QUERY` constants; `_TITLE_LABELS` dict; `_make_finding` uses label lookup; new `azure-managed-identity` `MetadataProbe` in `CATALOG`; `azure-managed-identity` entry added to `_RESPONSE_SIGNATURES` before `gcp` |
| `src/wraith/engine.py` | `azure-managed-identity` URL added to `METADATA_SSRF_URLS` |
| `tests/fixtures/metadata/azure_managed_identity.json` | New fixture: representative Azure managed-identity token response |
| `tests/test_metadata.py` | `azure_managed_identity.json` added to `test_detect_from_response_classifies_fixtures` parametrize; 6 new standalone tests |
| `tests/test_cli.py` | Version assertion updated to `0.9.2` |
| `src/wraith/__init__.py` | Version bumped `0.9.1` → `0.9.2` |
| `pyproject.toml` | Version bumped `0.9.1` → `0.9.2` |
| `README.md` | Status line, `--version` example, Modules table, Roadmap updated |

### Test results

```
267 passed, 5 deselected in 13.57s
```

7 new tests (260 → 267). All pass. See `test-output.txt` for full output.

### New tests

| Test | Coverage |
|---|---|
| `test_detect_from_response_classifies_fixtures[azure_managed_identity.json-azure-managed-identity-critical]` | Via-SSRF classifier returns `azure-managed-identity` + `critical` for the fixture |
| `test_azure_managed_identity_probe_sends_metadata_header_and_omits_xff` | Direct probe sends `Metadata:true`, omits `X-Forwarded-For`, includes `api-version=` |
| `test_azure_managed_identity_probe_is_critical_severity` | Direct probe returns critical finding, CWE-918, correct provider label |
| `test_azure_managed_identity_finding_title_is_human_readable` | Title contains "managed-identity" (not raw uppercased key) |
| `test_azure_managed_identity_classifier_not_confused_with_gcp` | GCP fixture → `gcp`; Azure MI fixture → `azure-managed-identity` (ordering proof) |
| `test_azure_managed_identity_probe_no_finding_on_miss` | 400/non-credential response produces no finding |
| `test_azure_managed_identity_in_metadata_ssrf_urls` | URL present in `METADATA_SSRF_URLS` with `identity/oauth2/token` path |

### PR

https://github.com/bugsyhewitt/wraith/pull/10
