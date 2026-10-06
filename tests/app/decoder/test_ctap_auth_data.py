"""``decoder.decode.ctap_auth_data``: authenticator data inside a CTAP view, as far as its flags describe it.

What does not read -- a truncated credential, a COSE key or extensions that are not
well-formed CBOR -- is shown as it is, with where it stops, never dropped or completed.
"""

from __future__ import annotations

import cbor2
from fido2 import cbor
from fido2.cose import CoseKey
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

from server.app.decoder.decode import ctap_auth_data as decode_ctap_auth_data
from tests.app.decoder.ctap_auth_bytes import _auth_header

AT = bytes([AuthenticatorData.FLAG.AT])
ED = bytes([AuthenticatorData.FLAG.ED])


def _header(flags: bytes, counter: int = 1) -> bytes:
    return b"\x01" * 32 + flags + counter.to_bytes(4, "big")


def _read(data: bytes):
    return decode_ctap_auth_data._parse_authenticator_data_bytes(data)


def test_attested_credential_data_too_short_to_read_is_reported_not_dropped():
    truncated = _header(AT)
    mismatch = _header(AT) + b"\x02" * 16 + (4).to_bytes(2, "big") + b"AB"

    details, trimmed, trailing = _read(truncated)
    attested = _read(mismatch)[0]["attestedCredentialData"]

    assert details["attestedCredentialData"] == {
        "parseError": "Attested credential data truncated: it needs at least 18 bytes, 0 remain."
    }
    assert (trimmed, trailing) == (truncated, b"")
    assert attested["lengthMismatch"] is True
    assert attested["parseError"] == "The credential ID declares 4 bytes; 2 remain."
    assert "credentialPublicKey" not in attested


def test_a_cose_key_that_is_not_well_formed_is_shown_as_hex_with_where_it_breaks():
    data = _header(AT) + b"\x02" * 16 + (2).to_bytes(2, "big") + b"AB" + b"\xa1"

    details, trimmed, trailing = _read(data)

    assert details["attestedCredentialData"]["credentialPublicKey"] == "a1"
    assert details["attestedCredentialData"]["parseError"] == (
        "credentialPublicKey is not well-formed CBOR at authData offset 58: map declares 1 entry; the data ends after 0"
    )
    assert (trimmed, trailing) == (data, b"")


def test_a_cose_key_that_is_not_a_map_is_shown_as_the_value_it_is():
    details, _, _ = _read(_header(AT) + b"\x02" * 16 + (0).to_bytes(2, "big") + cbor.encode(5))

    assert details["attestedCredentialData"]["credentialPublicKey"] == 5


def test_extensions_are_read_and_the_bytes_after_them_reported():
    data = _header(ED, counter=3) + cbor.encode(7)

    details, trimmed, trailing = _read(data + b"\x99")

    assert details["extensions"] == 7
    assert (trimmed, trailing) == (data, b"\x99")


def test_extensions_that_are_not_well_formed_are_shown_as_hex_with_where_they_break():
    broken = cbor.encode({"ext": True})[:-1]

    details, _, trailing = _read(_header(ED) + broken)

    assert details["extensions"] == broken.hex()
    assert details["parseError"] == 'extensions is not well-formed CBOR at authData offset 38: map key "ext" has no value'
    assert trailing == b""


def test_the_expanded_json_shows_the_raw_authenticator_data_and_what_follows_it():
    cose_key = CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x03" * 32, -3: b"\x04" * 32})
    credential = AttestedCredentialData.create(bytes(16), b"credential", cose_key)
    auth_data = bytes(AuthenticatorData.create(b"\x11" * 32, AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT, 3, credential))

    formatted, trailing = decode_ctap_auth_data._format_auth_data_for_expanded_json(auth_data + b"\x99")

    assert formatted["signCount"] == 3
    assert formatted["raw"] == auth_data.hex()
    assert (formatted["trailingBytesHex"], trailing) == ("99", b"\x99")


def test_parse_authenticator_data_bytes_returns_parse_error_for_short_payload():
    details, trimmed, trailing = decode_ctap_auth_data._parse_authenticator_data_bytes(b"\x00" * 10)

    assert details["parseError"].startswith("Authenticator data shorter")
    assert trimmed == b"\x00" * 10
    assert trailing == b""


def test_parse_authenticator_data_bytes_parses_attested_and_extension_sections_with_trailing():
    aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")
    credential_id = b"\xAA\xBB"
    public_key = cbor2.dumps({1: 2, 3: -7})
    extensions = cbor2.dumps({"credProtect": 1})
    trailer = b"\x00\xFF"

    payload = (
        _auth_header(flags=0xC1, sign_count=9)  # UP + AT + ED
        + aaguid
        + len(credential_id).to_bytes(2, "big")
        + credential_id
        + public_key
        + extensions
        + trailer
    )

    details, trimmed, trailing = decode_ctap_auth_data._parse_authenticator_data_bytes(payload)

    assert details["rpIdHash"] == bytes(range(32)).hex()
    assert details["flags"]["AT"] is True
    assert details["flags"]["ED"] is True
    assert details["attestedCredentialData"]["credentialId"] == "aabb"
    assert details["extensions"]["credProtect"] == 1
    # Only the bytes after the extensions trail; the extensions were read.
    assert trailing == trailer
    assert trimmed == payload[: len(payload) - len(trailer)]
