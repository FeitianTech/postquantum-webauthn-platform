"""``webauthn.attestation.formatting``: bytes as colon-separated hex lines, and DER OCTET STRING content."""
from __future__ import annotations

import pytest

from server.app.webauthn.attestation import formatting as attestation_formatting


def test_bytes_are_colon_separated_hex_a_line_at_a_time():
    assert attestation_formatting.format_hex_bytes_lines(bytes(range(5)), bytes_per_line=2) == ["00:01", "02:03", "04"]
    assert attestation_formatting.format_hex_bytes_lines(b"") == []


@pytest.mark.parametrize(
    ("text", "lines"),
    [
        ("0a:bc", ["0a:bc"]),
        # An odd number of digits is read with a leading zero.
        ("abc", ["0a:bc"]),
        # Text that is not hex is shown as it is.
        ("zz", ["zz"]),
    ],
)
def test_hex_text_is_reformatted_and_other_text_shown_as_it_is(text, lines):
    assert attestation_formatting.format_hex_string_lines(text, bytes_per_line=2) == lines


def test_an_octet_string_gives_its_content_and_anything_else_is_itself():
    assert attestation_formatting.der_octet_string_content(b"\x04\x02\xaa\xbb") == b"\xaa\xbb"
    assert attestation_formatting.der_octet_string_content(b"\xaa\xbb") == b"\xaa\xbb"
