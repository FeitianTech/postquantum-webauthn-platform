"""``decoder.decode.authenticator_data``: authenticator data as the decoder describes it."""
from __future__ import annotations

import hashlib

from fido2.webauthn import AuthenticatorData

from server.app.decoder import values as decoder_values
from server.app.decoder.decode import authenticator_data as decode_authenticator_data


def test_extension_outputs_are_shown_with_what_they_name():
    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.ED,
        5,
        b"",
        {"credProtect": 2},
    )

    extensions = decode_authenticator_data._describe_authenticator_data_bytes(bytes(auth_data))["extensions"]

    assert extensions["raw"] == {"credProtect": 2}
    assert extensions["summary"]["credProtectLabel"] == "userVerificationOptionalWithCredentialIDList"


def _with_extensions(extensions_hex: str) -> bytes:
    # The UP and ED flags, a counter of 5, then the extensions.
    return hashlib.sha256(b"example.com").digest() + bytes([0x81]) + (5).to_bytes(4, "big") + bytes.fromhex(extensions_hex)


def test_extensions_that_are_a_tag_are_not_summarised_as_a_map():
    # 8(simple(1)) reads as the mapping {"tag": 8, "value": simple(1)}, but no map was sent.
    extensions = decode_authenticator_data._describe_authenticator_data_bytes(_with_extensions("c8e1"))["extensions"]

    assert extensions["raw"] == {"tag": 8, "value": decoder_values.CborDiagnostic("simple(1)")}
    assert "summary" not in extensions


def test_extensions_that_are_a_map_of_tag_and_value_are_summarised_as_a_map():
    # {"tag": 8, "value": 1}
    extensions = decode_authenticator_data._describe_authenticator_data_bytes(
        _with_extensions("a263746167086576616c756501")
    )["extensions"]

    assert extensions["summary"] == {"tag": 8, "value": 1}
