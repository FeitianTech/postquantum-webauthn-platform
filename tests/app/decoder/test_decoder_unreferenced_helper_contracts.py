from __future__ import annotations

import hashlib

from fido2.cose import CoseKey
from fido2.webauthn import AttestationObject, AttestedCredentialData, AuthenticatorData

from server.app.decoder.decode import answer as decode_answer
from server.app.decoder.decode import certificates as decode_certificates
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


def test_result_conversion_helpers_for_all_base_payload_types(monkeypatch, binary):
    monkeypatch.setattr(decode_answer, "_build_credential_overview", lambda _d: {"id": "cred"})
    monkeypatch.setattr(decode_certificates, "convert_attestation_entry", lambda _e: {"fmt": "none"})
    monkeypatch.setattr(decode_answer, "_build_authenticator_section", lambda *_a, **_k: {"counter": 1})
    monkeypatch.setattr(decode_answer, "_convert_client_data_entry", lambda _e: {"type": "webauthn.create"})
    monkeypatch.setattr(decode_answer, "_collect_response_extras", lambda _e: {"signature": "aa"})

    pk_data = decode_answer._convert_public_key_credential_data(
        {"decoded": {"response": {}, "clientExtensionResults": {"credProps": {"rk": True}}}}
    )
    assert pk_data["credential"]["id"] == "cred"
    assert pk_data["attestationObject"]["fmt"] == "none"
    assert pk_data["authenticatorData"]["counter"] == 1
    assert pk_data["clientDataJSON"]["type"] == "webauthn.create"
    assert pk_data["responseDetails"]["signature"] == "aa"

    monkeypatch.setattr(decode_answer, "_extract_authenticator_bytes_from_attestation", lambda _e: b"\x00" * 37)
    monkeypatch.setattr(decode_answer, "_build_authenticator_data_payload", lambda *_a, **_k: {"flags": {"UP": True}})
    att_obj_data = decode_answer._convert_attestation_object_data(
        {"decoded": {"extensions": {"credProps": {"rk": True}}}, "binary": {"base64": "AQI="}}
    )
    assert att_obj_data["attestationObject"]["fmt"] == "none"
    assert att_obj_data["authenticatorData"]["flags"]["UP"] is True
    assert att_obj_data["extensions"]["credProps"]["rk"] is True

    auth_result = decode_answer._convert_authenticator_data_result(
        {"decoded": {}, "binary": {"hex": "00" * 37}}
    )
    assert auth_result["flags"]["UP"] is True

    client_result = decode_answer._convert_client_data_result({"decoded": {"type": "webauthn.get"}})
    assert client_result["type"] == "webauthn.create"

    cert_result = decode_answer._convert_certificate_result(
        {"decoded": {"certificates": [{"derBase64": "AQI=", "pem": "PEM"}]}}
    )
    assert cert_result["certificates"][0]["parsedX5c"]["derBase64"] == "AQI="
