from __future__ import annotations

import hashlib

from server.app.decoder import decode as decode_module


def _build_attested_auth_data(sign_count: int = 1) -> bytes:
    from fido2.cose import CoseKey
    from fido2.webauthn import AttestedCredentialData, AuthenticatorData

    credential_id = b"batch-three-cred"
    cose_key = CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})
    credential_data = AttestedCredentialData.create(
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        credential_id,
        cose_key,
    )
    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        sign_count,
        credential_data,
    )
    return bytes(auth_data)


def test_try_decode_cbor_reports_bytes_after_a_make_credential_response_and_keeps_its_att_stmt():
    # Bytes after the response are reported. They are not a signature: the
    # attStmt is shown exactly as the authenticator sent it.
    from fido2 import cbor

    auth_data = _build_attested_auth_data(sign_count=2)
    response_map = {1: "packed", 2: auth_data, 3: {"alg": -7, "sig": b"\x01\x02"}}
    data = b"\x00" + cbor.encode(response_map) + b"\xaa\xbb\xcc\xdd"

    result = decode_module._try_decode_cbor(data, "hex")

    decoded = result["decoded"]
    assert decoded["ctap"]["kind"] == "status"
    assert "signatureLength" not in decoded["ctap"]
    att_stmt = decoded["ctapDecoded"]["makeCredentialResponse"]["3 (attStmt)"]
    assert att_stmt["alg"] == -7
    assert att_stmt["sig"] == "0102"
    assert result["malformed"]


def test_try_decode_cbor_does_not_call_a_status_prefixed_auth_data_map_a_get_assertion_response():
    # A status byte says "response", not which command it answers. A map with
    # only authData is neither response shape, so it is not labelled as one.
    from fido2 import cbor

    auth_data = _build_attested_auth_data(sign_count=3)
    data = b"\x00" + cbor.encode({"authData": auth_data}) + b"\x12\x34"

    result = decode_module._try_decode_cbor(data, "hex")

    decoded = result["decoded"]
    assert decoded["ctap"]["kind"] == "status"
    assert "expandedJson" not in decoded
    assert "ctapDecoded" not in decoded
    assert "decodedValue" in decoded
    assert result["malformed"]
