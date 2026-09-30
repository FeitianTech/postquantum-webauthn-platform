from __future__ import annotations

from server.app.webauthn.attestation import formatting as attestation_formatting


def test_hex_format_helpers_cover_empty_odd_and_invalid_inputs(attestation_module):
    assert attestation_formatting.format_hex_bytes_lines(b"") == []
    assert attestation_formatting.format_hex_string_lines("abc", bytes_per_line=2) == ["0a:bc"]
    assert attestation_formatting.format_hex_string_lines("zz") == ["zz"]
