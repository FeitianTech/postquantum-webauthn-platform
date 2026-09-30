from __future__ import annotations

import hashlib

from fido2.cose import CoseKey
from fido2.webauthn import AttestationObject, AttestedCredentialData, AuthenticatorData

from server.app.decoder.decode import ctap_classify as decode_ctap_classify


def _auth_data_bytes() -> bytes:
    credential_id = b"decoder-unreferenced"
    cose_key = CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})
    credential_data = AttestedCredentialData.create(bytes(16), credential_id, cose_key)
    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        4,
        credential_data,
    )
    return bytes(auth_data)


def _attestation_object_bytes() -> bytes:
    auth_data = AuthenticatorData(_auth_data_bytes())
    return bytes(AttestationObject.create("none", auth_data, {}))


def test_ctap_shape_detection_and_classification_helpers():
    client_data_hash = b"\x11" * 32
    auth_data = _auth_data_bytes()

    make_request = {1: client_data_hash, 2: {"id": "example.com"}, 3: {"id": b"u"}}
    get_request = {1: "example.com", 2: client_data_hash}
    make_output = {1: "packed", 2: auth_data, 3: {"alg": -7, "sig": b"\xaa"}}
    get_output = {1: {"id": b"id"}, 2: auth_data, 3: b"\xaa" * 32}

    assert decode_ctap_classify._looks_like_make_credential_request(make_request) is True
    assert decode_ctap_classify._looks_like_get_assertion_request(get_request) is True
    assert decode_ctap_classify._looks_like_make_credential_output(make_output) is True
    assert decode_ctap_classify._looks_like_get_assertion_output(get_output) is True

    assert decode_ctap_classify._classify_ctap_map(make_output) == "make_credential_output"
    assert decode_ctap_classify._classify_ctap_map(get_output) == "get_assertion_output"
    assert decode_ctap_classify._classify_ctap_map(make_request) == "make_credential_input"
    assert decode_ctap_classify._classify_ctap_map(get_request) == "get_assertion_input"
