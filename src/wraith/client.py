"""wraith HTTP client boundary -- wired to the ``scan-primitives`` shared lib.

Every outbound request wraith makes routes through
:class:`scan_primitives.ScanClient`, which enforces the engagement **scope
before any socket is opened** (the cardinal guard for authorized testing),
applies a shared token-bucket rate limit, and can route through a proxy
(Caido/Burp). wraith owns **no** HTTP plumbing of its own -- this module is the
thin factory + typing boundary over the shared client.

Wiring status: scan-primitives is now a real, installed dependency (see
``pyproject.toml``). :func:`get_client` constructs a live
:class:`scan_primitives.ScanClient`; :func:`build_scope` parses a scope file
and/or explicit entries into a :class:`scan_primitives.Scope`.

Safety rails inherited from the shared client:

* **Scope first.** ``scope.assert_in_scope(url)`` runs before the socket opens;
  an out-of-scope target raises :class:`OutOfScopeError` and NO traffic leaves.
* **R5 -- untrusted response bytes.** :attr:`Response.content` / ``.text`` are
  *data*. wraith signature-matches them and captures them as
  :class:`wraith.findings.Finding` evidence -- never ``eval`` / ``exec``, never a
  shell, never an LLM tool call.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol, runtime_checkable

import httpx
from scan_primitives import OutOfScopeError, Scope, ScanClient, load_scope

__all__ = [
    "OutOfScopeError",
    "Response",
    "Scope",
    "ScanClient",
    "build_scope",
    "get_client",
    "load_scope",
]


@runtime_checkable
class Response(Protocol):
    """The minimal response shape wraith reads from the shared client.

    Structurally satisfied by :class:`httpx.Response` (what
    ``scan_primitives.ScanClient`` returns). Kept as a Protocol so tests can pass
    lightweight fakes and so wraith never depends on more of httpx than it reads.

    R5: ``content`` / ``text`` are untrusted response bytes -- signature-match
    and capture-as-evidence only, never evaluate.
    """

    status_code: int
    headers: Mapping[str, str]

    @property
    def content(self) -> bytes: ...

    @property
    def text(self) -> str: ...


def build_scope(
    scope_file: str | Path | None = None,
    entries: Iterable[str] | None = None,
) -> Scope:
    """Build a :class:`Scope` from a scope file and/or explicit entries.

    * ``scope_file`` only -> :func:`scan_primitives.load_scope`.
    * ``entries`` (with or without a file) -> merged and parsed via
      :meth:`Scope.from_entries` (``#`` comments and blanks are ignored there).

    A scope with no valid entries is fail-closed: it denies every target. wraith
    therefore refuses to scan without at least one authorized entry (the CLI
    enforces this and surfaces a clear error rather than silently doing nothing).
    """
    if scope_file is not None and not entries:
        return load_scope(scope_file)

    lines: list[str] = []
    if scope_file is not None:
        lines.extend(Path(scope_file).read_text(encoding="utf-8").splitlines())
    if entries:
        lines.extend(str(e) for e in entries)
    return Scope.from_entries(lines)


def get_client(
    scope: Scope,
    *,
    rate_limit: float | None = None,
    proxy: str | None = None,
    timeout: float = 10.0,
    transport: httpx.AsyncBaseTransport | None = None,
    **client_kwargs: Any,
) -> ScanClient:
    """Construct the shared scope-enforced async client for wraith.

    Thin wrapper over :class:`scan_primitives.ScanClient` so wraith has a single
    construction site (and a single place to pin suite-wide client defaults).
    ``transport`` lets tests inject an ``httpx.MockTransport`` / respx router.
    """
    return ScanClient(
        scope,
        rate_limit=rate_limit,
        proxy=proxy,
        timeout=timeout,
        transport=transport,
        **client_kwargs,
    )
