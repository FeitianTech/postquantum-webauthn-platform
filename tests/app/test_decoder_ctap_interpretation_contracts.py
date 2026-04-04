import base64

import cbor2
import pytest

from tests.fido2.test_attestation import _GSR2_DER


def _auth_header(flags: int = 0x01, sign_count: int = 1) -> bytes:
    return bytes(range(32)) + bytes([flags]) + sign_count.to_bytes(4, "big")


def _auth_data_with_trailing_map(fields: dict) -> bytes:
    return _auth_header() + cbor2.dumps(fields)


def _auth_data_with_trailing_pairs(pairs: list[tuple[int, object]]) -> bytes:
    trailing = b"".join(cbor2.dumps(key) + cbor2.dumps(value) for key, value in pairs)
    return _auth_header() + trailing


def test_parse_authenticator_data_bytes_returns_parse_error_for_short_payload():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    details, trimmed, trailing = decode_module._parse_authenticator_data_bytes(b"\x00" * 10)

    assert details["parseError"].startswith("Authenticator data shorter")
    assert trimmed == b"\x00" * 10
    assert trailing == b""


def test_parse_authenticator_data_bytes_parses_attested_and_extension_sections_with_trailing():
    decode_module = pytest.importorskip("server.app.decoder.decode")

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

    details, trimmed, trailing = decode_module._parse_authenticator_data_bytes(payload)

    assert details["rpIdHash"] == bytes(range(32)).hex()
    assert details["flags"]["AT"] is True
    assert details["flags"]["ED"] is True
    assert details["attestedCredentialData"]["credentialId"] == "aabb"
    assert details["extensions"]["credProtect"] == 1
    assert trailing.startswith(extensions)
    assert trailing.endswith(trailer)
    assert trimmed == payload[: len(payload) - len(trailer)]


def test_build_get_assertion_expanded_json_recovers_signature_and_optional_trailing_fields():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_data = _auth_data_with_trailing_pairs(
        [
            (3, b"\xAA"),
            (4, {1: b"\x01", 2: "user@example.com", 3: "User"}),
            (5, 2),
            (6, True),
            (8, {"uvm": True}),
            (9, b"\xBB"),
        ]
    )

    result = decode_module._build_get_assertion_expanded_json({2: auth_data})

    assert result["3 (signature)"] == "aa"
    assert result["4 (user)"]["id"] == "01"
    assert result["5 (numberOfCredentials)"] == 2
    assert result["6 (userSelected)"] is True
    assert result["8 (extensions)"]["uvm"] is True
    assert result["trailingFields"]["9"] == "bb"


def test_interpret_get_assertion_map_uses_trailing_signature_when_primary_signature_missing():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_data = _auth_data_with_trailing_pairs(
        [
            (3, b"\x11\x22"),
            (4, {1: b"\x02", 2: b"alice", 3: b"Alice"}),
            (8, {"credBlob": b"\xFF"}),
            (10, b"\xCC"),
        ]
    )
    value = {
        1: {2: "public-key", 1: b"\x10"},
        2: auth_data,
        7: b"\x0A",
    }

    interpreted = decode_module._interpret_get_assertion_map(value)

    assert interpreted is not None
    assert interpreted["3 (signature)"] == "1122"
    assert interpreted["4 (user)"]["id"] == "02"
    assert interpreted["7 (largeBlobKey)"] == "0a"
    assert interpreted["8 (extensions)"]["credBlob"] == "ff"
    assert interpreted["trailingFields"]["10"] == "cc"


def test_interpret_make_credential_map_handles_attstmt_optional_fields_and_extras():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_data = _auth_data_with_trailing_pairs([(7, b"\x99")])
    value = {
        1: "packed",
        2: auth_data,
        3: {"alg": -7, "sig": b"\x01\x02", "x5c": [_GSR2_DER]},
        4: b"\x05",
        5: b"\x06",
        6: {"example": b"\x07"},
        99: b"\x08",
    }

    interpreted = decode_module._interpret_make_credential_map(value)

    assert interpreted is not None
    assert interpreted["1 (fmt)"] == "packed"
    assert interpreted["3 (attStmt)"]["sig"] == "0102"
    assert interpreted["4 (epAtt)"] == "05"
    assert interpreted["5 (largeBlobKey)"] == "06"
    assert interpreted["6 (extensions)"]["example"] == "07"
    assert interpreted["99"] == "08"
    assert interpreted["2 (authData trailing)"]["7"] == "99"


def test_interpret_ctap_cbor_value_prefers_make_credential_request_classification():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    value = {
        1: b"\x11" * 32,
        2: {"id": "example.com", "name": "Example"},
        3: {"id": b"\x01", "name": "user", "displayName": "User"},
        4: [{"type": "public-key", "alg": -7}],
    }

    interpreted = decode_module._interpret_ctap_cbor_value(value)

    assert interpreted is not None
    assert "makeCredentialRequest" in interpreted
    mapped = interpreted["makeCredentialRequest"]
    assert mapped["1 (clientDataHash)"] == (b"\x11" * 32).hex()
    assert mapped["2 (rp)"]["id"] == "example.com"


def test_convert_ctap_user_decodes_cbor_bytes_and_preserves_custom_fields():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    user_mapping = {
        1: b"\xAA\xBB",
        2: b"alice",
        3: "Alice",
        b"role": "admin",
    }
    encoded = cbor2.dumps(user_mapping)

    converted = decode_module._convert_ctap_user(encoded)

    assert converted["id"] == "aabb"
    assert converted["name"]["text"] == "alice"
    assert converted["displayName"] == "Alice"
    assert converted["role"] == "admin"

    encoded_text = base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")
    converted_from_text = decode_module._convert_ctap_user(encoded_text)
    assert converted_from_text["id"] == "aabb"


def test_convert_ctap_credential_descriptor_supports_bytes_mapping_and_extra_keys():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._convert_ctap_credential_descriptor(b"\xAB") == "ab"

    descriptor = decode_module._convert_ctap_credential_descriptor(
        {
            1: b"\x01\x02",
            2: "public-key",
            3: ["usb", "nfc"],
            9: b"\x03",
        }
    )

    assert descriptor["id"] == "0102"
    assert descriptor["type"] == "public-key"
    assert descriptor["transports"] == ["usb", "nfc"]
    assert descriptor["9"] == "03"


def test_attempt_decode_cbor_map_returns_none_for_non_map_payload():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._attempt_decode_cbor_map(cbor2.dumps([1, 2, 3])) is None
    assert decode_module._attempt_decode_cbor_map(cbor2.dumps({1: 2})) == {1: 2}


def test_try_decode_cbor_interprets_prefixed_get_assertion_request_payload():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    map_payload = cbor2.dumps({1: "example.com", 2: b"\x22" * 32})
    data = b"\x02" + map_payload

    result = decode_module._try_decode_cbor(data, "hex")

    assert result is not None
    assert result["format"] == "CBOR"
    decoded = result["decoded"]
    assert decoded["ctap"]["kind"] == "command"
    assert "ctapDecoded" in decoded
    ctap_decoded = decoded["ctapDecoded"]
    assert "getAssertionRequest" in ctap_decoded or "makeCredentialResponse" in ctap_decoded
    if "getAssertionRequest" in ctap_decoded:
        assert ctap_decoded["getAssertionRequest"]["1 (rpId)"] == "example.com"
    else:
        assert ctap_decoded["makeCredentialResponse"]["1 (fmt)"] == "example.com"
    assert decoded["expandedJson"]["2 (clientDataHash)"] == (b"\x22" * 32).hex()
