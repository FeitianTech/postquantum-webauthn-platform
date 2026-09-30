"""``webauthn.attestation.certificate_summary``: the OpenSSL-style text summary of a certificate.

``certificates.serialize_attestation_certificate`` builds each section from what it
read; these give the builders that data directly.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from server.app.webauthn.attestation import certificate_summary


def test_a_public_key_section_skips_empty_values_and_indents_lists():
    lines = certificate_summary._public_key_section(
        [("Type", "Unknown"), ("Nothing", None), ("No lines", []), ("Public Key (hex)", ["00:01", "02:03"])]
    )

    assert lines == ["Subject Public Key Info:", "    Type: Unknown", "    Public Key (hex):", "        00:01", "        02:03"]


def test_a_key_with_nothing_to_say_has_no_section():
    assert certificate_summary._public_key_section([]) == []


def test_an_unknown_key_type_is_named_by_its_class():
    class SomeFutureKey:
        pass

    assert certificate_summary._public_key_entries(SomeFutureKey(), []) == [("Type", "SomeFutureKey")]


def test_an_extension_value_is_lines_of_its_fields_items_and_nested_values():
    value = {"skip": "", "none": None, "name": "value", "nested": [None, {"k": "v"}, "text"], "strings": ["a", "", "b"]}

    assert certificate_summary._structured_lines(value, 1) == [
        "    name: value",
        "    nested:",
        "        k: v",
        "        text",
        "    strings:",
        "        a",
        "        b",
    ]
    assert certificate_summary._structured_lines(None, 1) == []


@pytest.mark.parametrize(
    ("extension", "header"),
    [
        ({"oid": "1.2.3", "name": "1.2.3", "friendlyName": "Friendly"}, "1.2.3 (Friendly)"),
        ({"oid": "1.2.3", "name": "Named", "includeOidInHeader": False}, "Named"),
        ({"oid": "9.9.9", "name": "9.9.9", "includeOidInHeader": False}, "9.9.9"),
        ({"includeOidInHeader": False}, "Extension"),
        ({"oid": "1.2.3", "displayHeader": "  Shown As  ", "critical": True}, "Shown As [critical]"),
    ],
)
def test_an_extension_header_names_the_oid_and_the_friendliest_name_it_has(extension, header):
    assert certificate_summary._extension_header(extension) == header


def test_sections_with_nothing_to_show_are_left_out():
    assert certificate_summary._signature_section("ed25519", []) == []
    assert certificate_summary._fingerprint_section({"md5": "", "sha1": None}) == []


def test_a_missing_fingerprint_is_skipped_and_the_others_shown_in_order():
    assert certificate_summary._fingerprint_section({"sha256": "0a0b", "md5": "0c"}) == [
        "Fingerprint:",
        "    MD5:",
        "        0c",
        "    SHA256:",
        "        0a:0b",
    ]


def test_an_empty_subject_key_identifier_has_no_section():
    certificate = SimpleNamespace(
        extensions=SimpleNamespace(get_extension_for_oid=lambda _oid: SimpleNamespace(value=SimpleNamespace(digest=b"")))
    )

    assert certificate_summary._subject_key_identifier_section(certificate) == []
