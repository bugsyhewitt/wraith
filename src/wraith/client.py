"""wraith HTTP client boundary.

Backed by the ``scan-primitives`` shared lib once built (scope-enforced,
rate-limited httpx wrapper). STUB for scaffolding -- no network this pass.
R5: fetched content is untrusted data, never eval'd.

-------------------------------------------------------------------------------

Every outbound request wraith makes MUST route through this boundary so that a
single audited implementation enforces scope, rate limits, and proxy routing
(V0.1-CRITERIA.md #8 "Output" + "Safety"). wraith deliberately owns **no** HTTP
plumbing of its own: the concrete client is ``scan_primitives.ScanClient`` (an
async ``httpx`` wrapper) once that library ships. Until then this module only
declares the *shape* wraith depends on -- the :class:`ScanClient` /
:class:`Response` protocols -- and a placeholder that refuses to run.

Wiring status (this pass):
    * scan-primitives is spec-only (see projects/scan-primitives/SPEC.md); it is
      NOT yet an install dependency (see the ``# TODO`` line in pyproject.toml).
    * :class:`StubScanClient` raises :class:`NotImplementedError` on construction
      so no code path can accidentally open a socket before scope enforcement
      exists. The real client lands with V0.1-CRITERIA.md #8.

Safety rails encoded in the protocol below:
    * **Scope first.** The real client raises before opening a socket if the
      target is out of scope (the cardinal-sin guard for authorized testing).
    * **R5 -- untrusted response bytes.** :attr:`Response.content` /
      :attr:`Response.text` are *data*. wraith never passes them to ``eval``,
      ``exec``, a shell, or an LLM call with elevated permissions. They are
      pattern-matched for response signatures and captured into a
      :class:`wraith.findings.Finding` evidence dict -- nothing more.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol, runtime_checkable

# Raised by every not-yet-built code path; cites the contract so the reviewer
# and any future Worker land on the exact criteria section.
_NOT_BUILT = "v0.1 build -- scan-primitives integration; see V0.1-CRITERIA.md #8 'Output'"


@runtime_checkable
class Response(Protocol):
    """The minimal response shape wraith reads from the shared client.

    R5: ``content`` / ``text`` are untrusted response bytes. Treat them as data
    only -- signature-match and capture-as-evidence, never evaluate.
    """

    status_code: int
    headers: Mapping[str, str]

    @property
    def content(self) -> bytes: ...

    @property
    def text(self) -> str: ...


@runtime_checkable
class ScanClient(Protocol):
    """The scope-enforced async HTTP boundary wraith targets.

    Implemented by ``scan_primitives.ScanClient`` once that lib is built. The
    contract: every call asserts the target is in scope **before** any socket is
    opened, applies the shared token-bucket rate limit, honours the configured
    proxy, and records the request for finding evidence.
    """

    async def request(
        self, method: str, url: str, **kwargs: Any
    ) -> Response: ...

    async def get(self, url: str, **kwargs: Any) -> Response: ...

    async def aclose(self) -> None: ...


class StubScanClient:
    """Placeholder client for the scaffolding pass -- refuses to run.

    Instantiating (or calling) this raises :class:`NotImplementedError`. It
    exists so the client boundary is importable and type-checkable now, while
    guaranteeing no request is emitted before ``scan-primitives`` provides real,
    scope-enforced networking.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError(_NOT_BUILT)


def get_client(*args: Any, **kwargs: Any) -> ScanClient:
    """Return the shared scan client. STUB -- raises until scan-primitives lands.

    The real factory will construct a ``scan_primitives.ScanClient`` from a parsed
    scope, an optional rate limit, and an optional proxy (V0.1-CRITERIA.md #8).
    """
    raise NotImplementedError(_NOT_BUILT)
