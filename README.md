# wraith

**Status:** registered — awaiting v0.1 criteria from Overmind  
**Slot:** 8 (wave 1, 250K budget)  
**Language:** Python  
**Niche:** SSRF fuzz → exploit → pivot

Resurrects the dead-ancestor SSRF tooling (SSRFmap, Gopherus) with modern cloud-metadata coverage, DNS-rebinding bypasses, OOB confirmation, and gopher/dict protocol smuggling. Integrates with the suite's shared scan-primitives HTTP client (scope-aware, rate-limited, proxy/Caido-aware) and emits findings in the canonical SARIF-compatible schema.

See `RESEARCH.md` for the niche brief and prior-art analysis.

> **Do not build until the Overmind defines v0.1 criteria.**
