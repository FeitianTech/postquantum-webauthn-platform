from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest
from fido2 import cbor


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


class _BadCredentialId:
    def __bytes__(self):
        raise TypeError("credential id cannot be converted")


class _AuthenticationServer:
    def authenticate_complete(self, *_args, **_kwargs):
        return SimpleNamespace(credential_id=_BadCredentialId())


def test_parse_client_credentials_ignores_non_mapping_entries_and_keeps_valid_records():
    simple_module = pytest.importorskip("server.app.routes.simple")

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

    credential_data_list, serialized = simple_module._parse_client_credentials(raw_credentials)

    assert len(credential_data_list) == 1
    assert len(serialized) == 1
    assert serialized[0]["algorithm"] == -7


def test_serialize_credential_for_session_accepts_hex_aaguid_alias():
    simple_module = pytest.importorskip("server.app.routes.simple")

    serialized = simple_module._serialize_credential_for_session(
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
        (-123, "Other (Classical)"),
    ],
)
def test_register_complete_handles_algorithm_and_large_blob_residual_paths(
    monkeypatch, algorithm: int, expected_name: str
):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    auth_data = _RegisterAuthData(algorithm)

    monkeypatch.setattr(simple_module, "determine_rp_id", lambda: "example.com", raising=False)
    monkeypatch.setattr(
        simple_module,
        "create_fido_server",
        lambda **_kwargs: _RegisterServer(auth_data),
        raising=False,
    )
    monkeypatch.setattr(
        simple_module,
        "extract_attestation_details",
        lambda _response: (
            "none",
            {},
            None,
            None,
            {"largeBlob": {"blob": "present"}},
            None,
            [],
        ),
        raising=False,
    )
    monkeypatch.setattr(simple_module, "extract_min_pin_length", lambda _results: None, raising=False)
    monkeypatch.setattr(
        simple_module,
        "perform_attestation_checks",
        lambda *_args, **_kwargs: {
            "signature_valid": True,
            "root_valid": True,
            "rp_id_hash_valid": None,
            "aaguid_match": None,
            "metadata": {"description": 123},
            "warnings": [],
        },
        raising=False,
    )

    def _mutate_user_handle(credential_info, _public_key):
        credential_info["user_info"]["user_handle"] = "string-user-handle"

    monkeypatch.setattr(simple_module, "add_public_key_material", _mutate_user_handle, raising=False)
    monkeypatch.setattr(simple_module, "ensure_metadata_session_id", lambda: "meta-session", raising=False)
    monkeypatch.setattr(simple_module, "readkey", lambda *_args, **_kwargs: [], raising=False)
    monkeypatch.setattr(simple_module, "savekey", lambda *_args, **_kwargs: None, raising=False)
    monkeypatch.setattr(simple_module, "record_registration_event", lambda _event: None, raising=False)

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["state"] = {"challenge": "register-state"}
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


def test_authenticate_complete_uses_request_state_fallback_and_handles_bad_matched_credential_id(
    monkeypatch,
):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(
        simple_module,
        "_parse_client_credentials",
        lambda _raw: ([SimpleNamespace(credential_id=b"\x01")], [{"credentialId": "AQ"}]),
        raising=False,
    )
    monkeypatch.setattr(
        simple_module,
        "create_fido_server",
        lambda **_kwargs: _AuthenticationServer(),
        raising=False,
    )

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["simple_credentials"] = [{"credentialId": "AQ"}]
            session_state["authenticate_rp_id"] = "example.com"

        response = client.post(
            "/api/authenticate/complete?email=user@example.com",
            json={
                "__session_state": {"challenge": "from-request"},
                "response": {"authenticatorData": "@@@"},
            },
        )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "OK"
    assert "authenticatedCredentialId" not in payload
    assert "signCount" not in payload
