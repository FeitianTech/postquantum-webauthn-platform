import base64
import hashlib

import cbor2

from server.app.decoder.decode import binary as decode_binary
from server.app.decoder.decode import response as decode_response


def _build_authenticator_data_bytes() -> bytes:
    rp_id_hash = hashlib.sha256(b"example.com").digest()
    flags = bytes([0x45])  # UP + UV + AT
    sign_count = (7).to_bytes(4, "big")

    aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")
    credential_id = b"\x10\x20\x30\x40"
    credential_length = len(credential_id).to_bytes(2, "big")
    cose_key = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})

    return rp_id_hash + flags + sign_count + aaguid + credential_length + credential_id + cose_key


def _build_attestation_object_bytes() -> tuple[bytes, bytes]:
    from fido2.cose import CoseKey
    from fido2.webauthn import (
        AttestationObject,
        AttestedCredentialData,
        AuthenticatorData,
    )

    credential_id = b"decode-edge-cred"
    cose_key = CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x03" * 32, -3: b"\x04" * 32})
    credential_data = AttestedCredentialData.create(bytes(16), credential_id, cose_key)
    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        11,
        credential_data,
    )
    attestation = AttestationObject.create("none", auth_data, {})
    return bytes(attestation), bytes(auth_data)


def test_build_authenticator_data_payload_falls_back_to_raw_bytes_when_details_absent():
    auth_bytes = _build_authenticator_data_bytes()
    payload = decode_response._build_authenticator_data_payload(auth_bytes, None, fallback_alg=-7)

    assert payload["rpIdHash"] == hashlib.sha256(b"example.com").hexdigest()
    assert payload["flags"]["UP"] is True
    assert payload["flags"]["AT"] is True
    assert payload["counter"] == 7
    assert payload["credential"]["credentialIdLength"] == "0004"
    assert payload["credential"]["credentialId"] == "10203040"
    assert payload["credential"]["publicKey"]["alg"] == "ES256 (ECDSA)"


def test_extract_authenticator_bytes_from_attestation_parses_valid_object_and_handles_invalid():
    attestation_bytes, auth_data_bytes = _build_attestation_object_bytes()
    attestation_entry = {"raw": base64.b64encode(attestation_bytes).decode("ascii")}

    extracted = decode_binary._extract_authenticator_bytes_from_attestation(attestation_entry)
    assert extracted == auth_data_bytes

    assert decode_binary._extract_authenticator_bytes_from_attestation({"raw": "%%%%"}) is None
