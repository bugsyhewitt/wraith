"""Filter-bypass mutator tests: variant counts, Variant dataclass, IPv6 constants,
is_ipv4_literal, to_shorthand for additional IPs, loopback IPv6 count, scheme
case algorithm, and URL-structure semantics for each bypass family.

Covers gaps in test_mutators.py:
- ipv4_encodings count: 8 variants for a non-loopback target, 9 for loopback.
- Variant is a frozen dataclass (setting an attribute raises AttributeError).
- is_ipv4_literal with hostnames, bare IPv4, and IPv6 literals.
- to_shorthand for a third IP not covered by the existing tests (10.0.0.1).
- IPV6_LINK_LOCAL and IPV6_ULA constants are bracket-formatted IPv6 addresses.
- Scheme case alternation for 'https'.
- CRLF injection variant injects the Wraith-Canary header token.
- build_variants includes IPv6 loopback in the full catalog for a loopback target.
- Variant family and name attributes are non-empty strings.

All tests are pure-function / zero-I/O (Tier-0).
"""

from __future__ import annotations

import pytest

from wraith import mutators as m
from wraith.mutators import (
    IPV6_LINK_LOCAL,
    IPV6_LOOPBACK,
    IPV6_ULA,
    Variant,
    build_variants,
    ipv4_encodings,
    is_ipv4_literal,
    to_shorthand,
)

_SEED_LINK_LOCAL = "http://169.254.169.254/latest/meta-data/"
_SEED_LOOPBACK = "http://127.0.0.1/admin"
_DECOY = "trusted.example"


# --------------------------------------------------------------------------- #
# Variant dataclass
# --------------------------------------------------------------------------- #

def test_variant_is_frozen():
    """Variant must be a frozen dataclass — setting any field raises AttributeError."""
    v = Variant("test-name", "encoding", "http://example.com/", "note")
    with pytest.raises((AttributeError, TypeError)):
        v.name = "other"  # type: ignore[misc]


def test_variant_attributes_are_non_empty():
    """Variant name, family, and value must all be non-empty strings."""
    v = Variant("my-bypass", "userinfo", "http://trusted@internal/", "")
    assert v.name and isinstance(v.name, str)
    assert v.family and isinstance(v.family, str)
    assert v.value and isinstance(v.value, str)


def test_variant_note_defaults_to_empty_string():
    """Variant.note has a default value of '' when not supplied."""
    v = Variant("bypass", "encoding", "http://2130706433/")
    assert v.note == ""


# --------------------------------------------------------------------------- #
# IPv6 module constants
# --------------------------------------------------------------------------- #

def test_ipv6_loopback_constant_is_bracketed():
    """IPV6_LOOPBACK must be bracket-formatted for URL embedding."""
    assert IPV6_LOOPBACK.startswith("[")
    assert IPV6_LOOPBACK.endswith("]")
    assert "::1" in IPV6_LOOPBACK


def test_ipv6_link_local_constant_is_bracketed():
    """IPV6_LINK_LOCAL must be bracket-formatted for URL embedding."""
    assert IPV6_LINK_LOCAL.startswith("[")
    assert IPV6_LINK_LOCAL.endswith("]")
    assert "fe80" in IPV6_LINK_LOCAL.lower()


def test_ipv6_ula_constant_is_bracketed():
    """IPV6_ULA must be bracket-formatted for URL embedding."""
    assert IPV6_ULA.startswith("[")
    assert IPV6_ULA.endswith("]")
    assert "fd00" in IPV6_ULA.lower()


# --------------------------------------------------------------------------- #
# is_ipv4_literal
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "host,expected",
    [
        ("127.0.0.1", True),
        ("169.254.169.254", True),
        ("10.0.0.1", True),
        ("0.0.0.0", True),
        ("255.255.255.255", True),
        ("metadata.google.internal", False),
        ("localhost", False),
        ("example.com", False),
        ("[::1]", False),
        ("::1", False),
        ("", False),
    ],
)
def test_is_ipv4_literal(host: str, expected: bool):
    assert is_ipv4_literal(host) is expected


# --------------------------------------------------------------------------- #
# ipv4_encodings: variant counts
# --------------------------------------------------------------------------- #

def test_ipv4_encodings_count_for_non_loopback():
    """Non-loopback IPv4 must produce exactly 8 encoding variants (no IPv6 loopback)."""
    variants = ipv4_encodings("169.254.169.254")
    assert len(variants) == 8
    names = {v.name for v in variants}
    assert "ipv6-loopback" not in names


def test_ipv4_encodings_count_for_loopback():
    """Loopback IPv4 must produce 9 encoding variants (8 + IPv6 loopback)."""
    variants = ipv4_encodings("127.0.0.1")
    assert len(variants) == 9
    names = {v.name for v in variants}
    assert "ipv6-loopback" in names


def test_build_variants_count_loopback_exceeds_non_loopback():
    """build_variants for a loopback target has more variants than a non-loopback one."""
    loopback_count = len(build_variants(_SEED_LOOPBACK, decoy=_DECOY))
    link_local_count = len(build_variants(_SEED_LINK_LOCAL, decoy=_DECOY))
    # Loopback adds the IPv6 loopback encoding variant.
    assert loopback_count > link_local_count


def test_build_variants_loopback_includes_ipv6_loopback_variant():
    """build_variants for a loopback target must include the ipv6-loopback variant."""
    variants = build_variants(_SEED_LOOPBACK, decoy=_DECOY)
    names = {v.name for v in variants}
    assert "ipv6-loopback" in names
    # Verify the value is the [::1] form embedded in a URL.
    ipv6_v = next(v for v in variants if v.name == "ipv6-loopback")
    assert "[::1]" in ipv6_v.value


# --------------------------------------------------------------------------- #
# to_shorthand for additional IPs
# --------------------------------------------------------------------------- #

def test_to_shorthand_10_0_0_1():
    """10.0.0.1 shorthand: A=10, B = (0<<16)|(0<<8)|1 = 1 → '10.1'."""
    assert to_shorthand("10.0.0.1") == "10.1"


def test_to_shorthand_192_168_1_1():
    """192.168.1.1 shorthand: A=192, B=(168<<16)|(1<<8)|1."""
    # B = 168*65536 + 1*256 + 1 = 11010048 + 256 + 1 = 11010305
    assert to_shorthand("192.168.1.1") == "192.11010305"


def test_to_shorthand_10_20_30_40():
    """10.20.30.40 shorthand: A=10, B=(20<<16)|(30<<8)|40 = 1319976 → '10.1319976'."""
    # B = 20*65536 + 30*256 + 40 = 1310720 + 7680 + 40 = 1318440
    # Actually: 20*65536 = 1310720, 30*256 = 7680, 40 = 40 → sum = 1318440
    result = to_shorthand("10.20.30.40")
    assert result.startswith("10.")
    b_part = int(result.split(".")[1])
    assert b_part == (20 << 16) | (30 << 8) | 40


# --------------------------------------------------------------------------- #
# Scheme case alternation
# --------------------------------------------------------------------------- #

def test_scheme_case_for_http_seed():
    """The scheme-case variant for 'http' must be 'HtTp'."""
    variants = {v.name: v for v in build_variants(_SEED_LINK_LOCAL, decoy=_DECOY)}
    assert variants["scheme-case"].value.startswith("HtTp://")


def test_scheme_case_for_https():
    """The scheme-case variant for 'https' must follow the alternating-case pattern."""
    variants = {v.name: v for v in build_variants("https://127.0.0.1/", decoy=_DECOY)}
    scheme_part = variants["scheme-case"].value.split("://")[0]
    # Alternating case: H=upper, t=lower, T=upper, p=lower, S=upper → "HtTpS"
    assert scheme_part == "HtTpS"


# --------------------------------------------------------------------------- #
# URL-structure bypass semantics
# --------------------------------------------------------------------------- #

def test_crlf_injection_contains_canary_header_name():
    """The CRLF injection variant must inject a 'Wraith-Canary' header token."""
    variants = {v.name: v for v in build_variants(_SEED_LINK_LOCAL, decoy=_DECOY)}
    crlf_value = variants["crlf-header-injection"].value
    assert "%0d%0a" in crlf_value.lower()
    assert "wraith-canary" in crlf_value.lower()


def test_crlf_injection_family():
    """The CRLF injection variant is in the 'parser-differential' family."""
    variants = {v.name: v for v in build_variants(_SEED_LINK_LOCAL, decoy=_DECOY)}
    assert variants["crlf-header-injection"].family == "parser-differential"


def test_fragment_hash_places_decoy_after_hash():
    """Fragment-hash variant must place the decoy after the '#@' token."""
    variants = {v.name: v for v in build_variants(_SEED_LINK_LOCAL, decoy=_DECOY)}
    frag_value = variants["fragment-hash"].value
    assert "#@" in frag_value
    assert frag_value.endswith(f"#@{_DECOY}")


def test_backslash_bypass_places_decoy_before_backslash():
    """Backslash variant: decoy appears before the backslash, internal host after '@'."""
    variants = {v.name: v for v in build_variants(_SEED_LINK_LOCAL, decoy=_DECOY)}
    bs_value = variants["backslash"].value
    assert _DECOY in bs_value
    assert "\\" in bs_value or "%5c" in bs_value.lower()


def test_whitespace_tab_bypass_encodes_tab_in_userinfo():
    """Whitespace-tab variant must include %09 (URL-encoded tab) between decoy and @."""
    variants = {v.name: v for v in build_variants(_SEED_LINK_LOCAL, decoy=_DECOY)}
    ws_value = variants["whitespace-tab"].value
    assert "%09" in ws_value


def test_scheme_backslash_uses_malformed_separator():
    """Scheme-backslash variant must use '/\\/' (backslash in scheme separator)."""
    variants = {v.name: v for v in build_variants(_SEED_LINK_LOCAL, decoy=_DECOY)}
    sb_value = variants["scheme-backslash"].value
    # The malformed separator is ":/\/" — backslash between the two forward slashes.
    assert ":/\\/" in sb_value


def test_userinfo_at_places_decoy_in_userinfo():
    """Userinfo-at variant must have scheme://decoy@internal_host/path structure."""
    variants = {v.name: v for v in build_variants(_SEED_LINK_LOCAL, decoy=_DECOY)}
    ui_value = variants["userinfo-at"].value
    assert f"{_DECOY}@" in ui_value
    assert "169.254.169.254" in ui_value


def test_userinfo_at_multi_has_two_at_signs():
    """Userinfo-at-multi variant must contain at least two '@' characters."""
    variants = {v.name: v for v in build_variants(_SEED_LINK_LOCAL, decoy=_DECOY)}
    multi_value = variants["userinfo-at-multi"].value
    assert multi_value.count("@") >= 2


def test_dns_rebind_family_is_dns_rebind():
    """DNS-rebind variant must be in the 'dns-rebind' family."""
    variants = {v.name: v for v in build_variants(_SEED_LINK_LOCAL, decoy=_DECOY)}
    assert variants["dns-rebind-rbndr"].family == "dns-rebind"


def test_dns_rebind_value_contains_rbndr_us():
    """DNS-rebind variant value must reference rbndr.us."""
    variants = {v.name: v for v in build_variants(_SEED_LINK_LOCAL, decoy=_DECOY)}
    assert "rbndr.us" in variants["dns-rebind-rbndr"].value


def test_all_encoding_variants_are_in_encoding_family():
    """All IP-encoding variants must be in the 'encoding' family."""
    encoding_names = {
        "dword-decimal", "hex-dotless", "hex-dotted", "octal-dotted",
        "octal-dotless", "shorthand", "ipv4-mapped-ipv6", "ipv4-mapped-ipv6-hex",
    }
    variants = {v.name: v for v in build_variants(_SEED_LINK_LOCAL, decoy=_DECOY)}
    for name in encoding_names:
        assert variants[name].family == "encoding", (
            f"variant {name!r} must be in family 'encoding', got {variants[name].family!r}"
        )


def test_hostname_target_has_no_dns_rebind_or_encoding_variants():
    """A hostname internal target must have no dns-rebind or IP encoding variants."""
    variants = {v.name: v for v in
                build_variants("http://metadata.google.internal/computeMetadata/v1/")}
    for name in ("dns-rebind-rbndr", "dword-decimal", "hex-dotless"):
        assert name not in variants
    # But URL-structure tricks must still be present.
    assert "userinfo-at" in variants
    assert "crlf-header-injection" in variants
    assert "scheme-case" in variants
