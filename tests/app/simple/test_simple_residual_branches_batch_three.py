from __future__ import annotations

import base64
import time

import pytest
from fido2 import cbor

from server.app import visitor_session
from server.app.config import relying_party
from server.app.routes.simple import parsing as simple_parsing
from server.app.webauthn.attestation import aaguid as attestation_aaguid
from server.app.webauthn.attestation import certificates as attestation_certificates
from server.app.webauthn.attestation import checks as attestation_checks
from tests.app.entry_app import entry_app


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class _CredentialData:
    def __init__(self, alg: int):
        self.credential_id = b"residual-simple-credential"
        self.public_key = {
            1: 2,
            3: alg,
            -1: 1,
            -2: b"\x01" * 32,
            -3: b"\x02" * 32,
        }
        self.aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")


class _RegisterAuthData:
    class FLAG:
        UP = 0x01
        UV = 0x04
        BE = 0x08
        BS = 0x10
        AT = 0x40
        ED = 0x80

    def __init__(self, alg: int):
        self.credential_data = _CredentialData(alg)
        self.flags = self.FLAG.UP | self.FLAG.AT
        self.counter = 5
        self.rp_id_hash = object()  # Exercises non-bytes fallback path.

    def __bytes__(self):
        return b"\x01\x02\x03\x04"


class _RegisterServer:
    def __init__(self, auth_data):
        self._auth_data = auth_data

    def register_complete(self, *_args, **_kwargs):
        return self._auth_data


def test_parse_client_credentials_ignores_non_mapping_entries_and_keeps_valid_records():
    raw_credentials = [
        "not-a-mapping",
        {
            "aaguid": _b64url(bytes.fromhex("00112233445566778899aabbccddeeff")),
            "credentialId": _b64url(b"\x01\x02\x03"),
            "publicKey": _b64url(
                cbor.encode(
                    {
                        1: 2,
                        3: -7,
                        -1: 1,
                        -2: b"\x01" * 32,
                        -3: b"\x02" * 32,
                    }
                )
            ),
            "algorithm": -7,
        },
    ]

    credential_data_list, serialized = simple_parsing._parse_client_credentials(raw_credentials)

    assert len(credential_data_list) == 1
    assert len(serialized) == 1
    assert serialized[0]["algorithm"] == -7


def test_serialize_credential_for_session_accepts_hex_aaguid_alias():
    serialized = simple_parsing._serialize_credential_for_session(
        {
            "aaguidHex": "00112233445566778899aabbccddeeff",
            "credentialId": b"\x01\x02",
            "publicKey": memoryview(b"\x03\x04"),
            "algorithm": -7,
        }
    )

    # The serializer routes through generic binary decoding and preserves this
    # value as base64url-normalized text.
    assert serialized["aaguid"] == "00112233445566778899aabbccddeeff"
    assert serialized["credentialId"] == _b64url(b"\x01\x02")
    assert serialized["publicKey"] == _b64url(b"\x03\x04")


@pytest.mark.parametrize(
    ("algorithm", "expected_name"),
    [
        (-50, "ML-DSA-87 (PQC)"),
        (-49, "ML-DSA-65 (PQC)"),
        (-48, "ML-DSA-44 (PQC)"),
        (-8, "EdDSA"),
        (-123, "COSE alg -123"),
    ],
)
def test_register_complete_handles_algorithm_and_large_blob_residual_paths(monkeypatch, algorithm: int, expected_name: str, metadata_module, device_logs_module, attestation_module, storage_module, config_module):
    auth_data = _RegisterAuthData(algorithm)

    monkeypatch.setattr(relying_party, "determine_rp_id", lambda: "example.com")
    monkeypatch.setattr(
        relying_party,
        "create_fido_server",
        lambda **_kwargs: _RegisterServer(auth_data)
    )
    monkeypatch.setattr(
        attestation_certificates,
        "extract_attestation_details",
        lambda _response: (
            "none",
            {},
            None,
            None,
            {"largeBlob": {"blob": "present"}},
            None,
            [],
        )
    )
    monkeypatch.setattr(attestation_aaguid, "extract_min_pin_length", lambda _results: None)
    monkeypatch.setattr(
        attestation_checks,
        "perform_attestation_checks",
        lambda *_args, **_kwargs: {
            "signature_valid": True,
            "root_valid": True,
            "rp_id_hash_valid": None,
            "aaguid_match": None,
            "metadata": {"description": 123},
            "warnings": [],
        }
    )

    def _mutate_user_handle(credential_info, _public_key):
        credential_info["user_info"]["user_handle"] = "string-user-handle"

    monkeypatch.setattr(storage_module, "add_public_key_material", _mutate_user_handle)
    monkeypatch.setattr(visitor_session, "ensure_id", lambda: "meta-session")
    monkeypatch.setattr(storage_module, "read_for_update", lambda *_args, **_kwargs: ([], None))
    monkeypatch.setattr(storage_module, "save_if_unchanged", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(device_logs_module, "record_registration_event", lambda _event: None)

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["state"] = {"challenge": "register-state", "issued_at": time.time()}
            session_state["register_rp_id"] = "example.com"
            session_state["simple_register_public_key"] = {"challenge": "AQID"}

        response = client.post(
            "/api/register/complete?email=user@example.com",
            json={
                "response": {
                    "attestationObject": _b64url(b"attestation"),
                    "clientDataJSON": _b64url(b"client-data"),
                }
            },
        )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["algo"] == expected_name
    assert payload["relyingParty"]["largeBlob"] is True
    assert payload["storedCredential"]["userHandle"] == _b64url(b"string-user-handle")
