"""A binary field inside PublicKeyCredential JSON is checked like the same bytes alone.

The attestationObject, authenticatorData and clientDataJSON of a
PublicKeyCredential are base64url text holding bytes. Findings about those
bytes are surfaced with ``source`` naming the field, their offsets counted from
the field's decoded bytes. A field that does not decode is reported where it
stops (``parseError``), and the rest of the credential still decodes: one bad
field no longer turns the whole decode into a 422.
"""
from __future__ import annotations

import base64
import json

import cbor2
import pytest

from server.app.decoder import decode_payload_text
from tests.app.decoder.real_vectors import (
    WEBAUTHN_L3_PACKED_SELF_ATTESTATION_OBJECT,
    WEBAUTHN_L3_PACKED_SELF_CLIENT_DATA_JSON,
)

_ATTESTATION = WEBAUTHN_L3_PACKED_SELF_ATTESTATION_OBJECT
_CLIENT_DATA = WEBAUTHN_L3_PACKED_SELF_CLIENT_DATA_JSON
# {3: -7, 1: 2, ...}: kty (1) after alg (3) is out of CTAP2 order.
_UNSORTED_KEY = bytes.fromhex("a5" "0326" "0102" "2001" "215820") + bytes(32) + bytes.fromhex("225820") + bytes(32)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _credential(**response: bytes) -> dict:
    payload = {
        "id": "AQID",
        "rawId": "AQID",
        "type": "public-key",
        "response": {name: _b64url(value) for name, value in response.items()},
    }
    return decode_payload_text(json.dumps(payload))


def _auth_data_with_key(credential_key: bytes, tail: bytes = b"") -> bytes:
    attested = bytes(16) + (4).to_bytes(2, "big") + b"cred" + credential_key
    return bytes(32) + bytes([0x41]) + bytes(4) + attested + tail


def test_a_valid_credential_has_no_findings():
    result = _credential(attestationObject=_ATTESTATION, clientDataJSON=_CLIENT_DATA)

    assert result["type"] == "PublicKeyCredential"
    assert result["findings"] == []
    assert result["data"]["attestationObject"]["fmt"] == "packed"


def test_canonical_findings_inside_the_attestation_object_are_surfaced_with_their_source():
    auth_data = _auth_data_with_key(_UNSORTED_KEY)
    attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})

    result = _credential(attestationObject=attestation, clientDataJSON=_CLIENT_DATA)
    (finding,) = result["findings"]

    assert finding["source"] == "response.attestationObject"
    assert finding["code"] == "map-key-order"
    assert finding["path"] == '${"authData"}<credentialPublicKey>{1}'
    # Counted from the attestationObject's own bytes.
    assert finding["offset"] == attestation.index(_UNSORTED_KEY) + 3


def test_bytes_after_a_nested_attestation_object_are_a_finding_not_a_422():
    result = _credential(attestationObject=_ATTESTATION + b"\x00\x00", clientDataJSON=_CLIENT_DATA)
    (finding,) = result["findings"]

    assert finding["code"] == "trailing-bytes"
    assert finding["source"] == "response.attestationObject"
    assert finding["offset"] == len(_ATTESTATION)
    assert result["data"]["attestationObject"]["fmt"] == "packed"


def test_an_attestation_object_that_is_not_cbor_is_reported_where_it_stops():
    truncated = _ATTESTATION[:40]

    result = _credential(attestationObject=truncated, clientDataJSON=_CLIENT_DATA)

    assert result["success"] is True
    parse_error = result["data"]["attestationObject"]["parseError"]
    assert parse_error["reason"].startswith("byte string declares")
    (finding,) = result["findings"]
    assert finding["code"] == "parse-error"
    assert finding["source"] == "response.attestationObject"
    assert (finding["offset"], finding["path"]) == (parse_error["offset"], parse_error["path"])
    assert truncated[finding["offset"]] >> 5 == 2  # the byte string that runs out
    # The rest of the credential still decodes.
    assert result["data"]["clientDataJSON"]["type"] == "webauthn.create"


def test_malformed_cbor_inside_authdata_is_located_in_the_attestation_object():
    broken_key = bytes.fromhex("a5" "0102" "0326" "2001" "215820") + bytes(8)  # x declares 32 bytes
    auth_data = _auth_data_with_key(broken_key)
    attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})

    result = _credential(attestationObject=attestation, clientDataJSON=_CLIENT_DATA)
    parse_error = result["data"]["attestationObject"]["parseError"]

    assert parse_error["path"] == '${"authData"}<credentialPublicKey>{-2}'
    assert parse_error["offset"] == attestation.index(broken_key) + 8  # the head of -2's byte string
    assert parse_error["reason"] == "byte string declares 32 bytes; 8 remain"


def test_authenticator_data_that_does_not_decode_is_reported_where_it_stops():
    auth_data = bytes(32) + bytes([0x81]) + bytes(4) + bytes.fromhex("a1" "6b") + b"credProtect"

    result = _credential(authenticatorData=auth_data, clientDataJSON=_CLIENT_DATA, signature=b"\x30\x00")
    parse_error = result["data"]["authenticatorData"]["parseError"]
    (finding,) = result["findings"]

    assert result["type"] == "PublicKeyCredential"
    assert parse_error["path"] == '$<extensions>{"credProtect"}'
    assert parse_error["reason"] == 'map key "credProtect" has no value'
    assert parse_error["offset"] == 38  # the key, just past the extensions map's head at 37
    assert finding["source"] == "response.authenticatorData"


def test_bytes_after_authenticator_data_are_located():
    auth_data = bytes(32) + bytes([0x01]) + bytes(4) + b"\xab\xcd"

    result = _credential(authenticatorData=auth_data, clientDataJSON=_CLIENT_DATA, signature=b"\x30\x00")
    parse_error = result["data"]["authenticatorData"]["parseError"]

    assert parse_error["offset"] == 37
    assert "2 byte(s) after what the AT and ED flags account for" in parse_error["reason"]


def test_client_data_that_is_not_json_is_reported_where_it_stops():
    result = _credential(attestationObject=_ATTESTATION, clientDataJSON=b'{"type": "webauthn.create",')
    parse_error = result["data"]["clientDataJSON"]["parseError"]

    assert parse_error["offset"] == 27
    assert result["findings"][0]["source"] == "response.clientDataJSON"
    assert result["data"]["attestationObject"]["fmt"] == "packed"


def test_client_data_that_is_not_utf8_is_reported_where_it_stops():
    result = _credential(clientDataJSON=b'{"type": "\xff"}', signature=b"\x30\x00")

    assert result["data"]["clientDataJSON"]["parseError"]["offset"] == 10
    assert result["data"]["clientDataJSON"]["parseError"]["reason"].startswith("not UTF-8")


@pytest.mark.parametrize("client_data", [b"[1]", b"null", b"1", b'"x"'])
def test_client_data_that_is_json_but_not_an_object_is_a_located_parse_error(client_data):
    # Before: AttributeError, and the endpoint answered 500.
    result = _credential(attestationObject=_ATTESTATION, clientDataJSON=client_data)

    parse_error = result["data"]["clientDataJSON"]["parseError"]
    assert (parse_error["offset"], parse_error["path"]) == (0, "$")
    assert parse_error["reason"].startswith("client data is JSON, but not an object")
    assert result["data"]["attestationObject"]["fmt"] == "packed"
