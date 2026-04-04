from __future__ import annotations

import hashlib
import types

import pytest


def _register_begin_payload() -> dict:
    return {
        "publicKey": {
            "rp": {"id": "example.com", "name": "Example"},
            "user": {
                "id": "01020304",
                "name": "user@example.com",
                "displayName": "User",
            },
            "challenge": "0a0b0c0d",
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        }
    }


def _install_register_begin_server(monkeypatch, advanced_module, captured: dict, *, include_extensions=False):
    class _FakeServer:
        def __init__(self):
            self.allowed_algorithms = []
            self.timeout = None
            self.attestation = None

        def register_begin(self, *args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            captured["attestation"] = self.attestation
            public_key = {"challenge": "AQID"}
            if include_extensions:
                public_key["extensions"] = {"largeBlob": {"support": "preferred"}}
            return {"publicKey": public_key}, {"challenge": "state-token"}

    monkeypatch.setattr(
        advanced_module,
        "create_fido_server",
        lambda **_kwargs: _FakeServer(),
        raising=False,
    )


def _install_register_complete_defaults(monkeypatch, advanced_module):
    monkeypatch.setattr(advanced_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(advanced_module, "readkey", lambda *_args, **_kwargs: [], raising=False)
    monkeypatch.setattr(advanced_module, "add_public_key_material", lambda *_args, **_kwargs: None, raising=False)
    monkeypatch.setattr(advanced_module, "augment_aaguid_fields", lambda *_args, **_kwargs: None, raising=False)
    monkeypatch.setattr(advanced_module, "record_registration_event", lambda _event: None, raising=False)
    monkeypatch.setattr(advanced_module, "store_credential_artifact", lambda *_args, **_kwargs: True, raising=False)
    monkeypatch.setattr(
        advanced_module,
        "_log_authenticator_attestation_response",
        lambda *_args, **_kwargs: None,
        raising=False,
    )
    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or "example.com", raising=False)


def test_helper_none_and_non_string_decode_paths():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    assert advanced_module._coerce_optional_bool(None) is None
    assert advanced_module._decode_base64url_bytes(object()) == b""


@pytest.mark.parametrize(
    "attestation_value,expected_value",
    [
        ("direct", "direct"),
        ("indirect", "indirect"),
        ("enterprise", "enterprise"),
    ],
)
def test_register_begin_maps_attestation_modes_and_exercises_pqc_warning_branch(
    monkeypatch,
    attestation_value,
    expected_value,
):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    captured = {}
    _install_register_begin_server(monkeypatch, advanced_module, captured, include_extensions=True)

    warning_messages = []
    monkeypatch.setattr(
        advanced_module,
        "detect_available_pqc_algorithms",
        lambda: (set(), None),
        raising=False,
    )
    monkeypatch.setattr(
        advanced_module.app.logger,
        "warning",
        lambda message, *args: warning_messages.append(message % args if args else message),
        raising=False,
    )

    payload = _register_begin_payload()
    payload["publicKey"].update(
        {
            "attestation": attestation_value,
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -50},
                [],
            ],
            "extensions": {
                "credProtect": ["unexpected-shape"],
                "prf": "raw-prf",
                "largeBlob": {"support": "required"},
            },
        }
    )

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/register/begin", json=payload)

    assert response.status_code == 200
    assert getattr(captured["attestation"], "value", captured["attestation"]) == expected_value
    assert captured["kwargs"]["extensions"]["credentialProtectionPolicy"] == ["unexpected-shape"]
    assert captured["kwargs"]["extensions"]["prf"] == "raw-prf"
    assert warning_messages


def test_register_complete_validates_required_payload_and_username_fields():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        missing_response = client.post(
            "/api/advanced/register/complete",
            json={"publicKey": {"user": {"name": "user@example.com"}}},
        )
        assert missing_response.status_code == 400
        assert missing_response.get_json() == {"error": "Credential response is required"}

        missing_public_key = client.post(
            "/api/advanced/register/complete",
            json={"__credential_response": {"response": {}}},
        )
        assert missing_public_key.status_code == 400
        assert "Missing publicKey" in missing_public_key.get_json()["error"]

        missing_username = client.post(
            "/api/advanced/register/complete",
            json={
                "publicKey": {
                    "challenge": "AQID",
                    "rp": {"id": "example.com", "name": "Example"},
                    "user": {"name": "", "displayName": "User"},
                },
                "__credential_response": {"response": {}},
            },
        )
        assert missing_username.status_code == 400
        assert missing_username.get_json() == {"error": "Username is required in user.name"}


def test_register_complete_hits_non_mapping_fallback_paths_and_keeps_response_contract(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    _install_register_complete_defaults(monkeypatch, advanced_module)

    class _BadBytes:
        def __bytes__(self):
            raise TypeError("boom")

    class _BadPublicKey:
        def __getitem__(self, _key):
            raise TypeError("not-indexable")

        def __iter__(self):
            raise TypeError("not-iterable")

    class _CredentialData:
        credential_id = b"cred-id"
        public_key = _BadPublicKey()
        aaguid = _BadBytes()

    class _Flag:
        UP = 0x01
        UV = 0x04
        BE = 0x08
        BS = 0x10
        AT = 0x40
        ED = 0x80

    class _AuthData:
        FLAG = _Flag
        credential_data = _CredentialData()
        rp_id_hash = _BadBytes()
        flags = _Flag.UP | _Flag.AT
        counter = 7
        extensions = {"credProtect": 2}

        def __bytes__(self):
            return b"auth-data"

    class _Server:
        def register_complete(self, _state, _response):
            return _AuthData()

    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _Server(), raising=False)
    monkeypatch.setattr(
        advanced_module,
        "extract_attestation_details",
        lambda _response: (
            "packed",
            {},
            "parsed-attestation-object",
            "parsed-client-data-json",
            {"credProps": True, "largeBlob": True},
            {"certificate": True},
            [{"chain": 1}],
        ),
        raising=False,
    )
    monkeypatch.setattr(advanced_module, "extract_min_pin_length", lambda _results: 6, raising=False)
    monkeypatch.setattr(
        advanced_module,
        "perform_attestation_checks",
        lambda *_args, **_kwargs: {
            "signature_valid": True,
            "root_valid": True,
            "rp_id_hash_valid": None,
            "aaguid_match": True,
            "metadata": {"description": 7},
            "warnings": [],
        },
        raising=False,
    )
    monkeypatch.setattr(
        advanced_module,
        "summarize_authenticator_extensions",
        lambda _extensions: {"ext": True},
        raising=False,
    )

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_state"] = {"challenge": "state-token"}
            session_state["advanced_rp"] = {"id": "example.com", "name": "Example"}
            session_state["advanced_original_request"] = {"publicKey": "stored-non-mapping"}

        response = client.post(
            "/api/advanced/register/complete",
            json={
                "publicKey": {
                    "challenge": "AQID",
                    "rp": {"name": "Example"},
                    "rpId": "fallback-rpid.example",
                    "extensions": {"credProtect": "custom-policy"},
                    "authenticatorSelection": "invalid-shape",
                    "user": {
                        "name": "user@example.com",
                        "displayName": "User",
                        "id": "not-hex",
                    },
                },
                "__credential_response": {
                    "authenticatorAttachment": "platform",
                    "transports": ["usb", 7],
                    "response": {
                        "attestationObject": "AQID",
                        "clientDataJSON": "AQID",
                    },
                },
                "__session_state": {"challenge": "fallback"},
            },
        )

    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "OK"
    assert body["relyingParty"]["largeBlob"] is True
    assert body["relyingParty"]["registrationData"]["authenticatorExtensions"] == {"ext": True}


def test_register_complete_returns_400_for_non_mapping_extensions_payload(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    _install_register_complete_defaults(monkeypatch, advanced_module)

    class _CredentialData:
        credential_id = b"cred-id"
        public_key = {"alg": -7}
        aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")

    class _Flag:
        UP = 0x01
        UV = 0x04
        BE = 0x08
        BS = 0x10
        AT = 0x40
        ED = 0x80

    class _AuthData:
        FLAG = _Flag
        credential_data = _CredentialData()
        rp_id_hash = hashlib.sha256(b"example.com").digest()
        flags = _Flag.UP | _Flag.AT
        counter = 1
        extensions = {}

        def __bytes__(self):
            return b"auth-data"

    class _Server:
        def register_complete(self, _state, _response):
            return _AuthData()

    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _Server(), raising=False)
    monkeypatch.setattr(
        advanced_module,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {}, None, []),
        raising=False,
    )
    monkeypatch.setattr(advanced_module, "extract_min_pin_length", lambda _results: None, raising=False)
    monkeypatch.setattr(
        advanced_module,
        "perform_attestation_checks",
        lambda *_args, **_kwargs: {
            "signature_valid": True,
            "root_valid": True,
            "rp_id_hash_valid": True,
            "aaguid_match": True,
            "metadata": {},
            "warnings": [],
        },
        raising=False,
    )

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_state"] = {"challenge": "state-token"}
            session_state["advanced_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/register/complete",
            json={
                "publicKey": {
                    "challenge": "AQID",
                    "rp": {"id": "example.com", "name": "Example"},
                    "extensions": "invalid-shape",
                    "user": {"name": "user@example.com", "displayName": "User"},
                },
                "__credential_response": {"response": {}},
            },
        )

    assert response.status_code == 400
    assert "has no attribute 'get'" in response.get_json()["error"]


@pytest.mark.parametrize(
    "cred_protect_value,expected_display",
    [
        (2, "userVerificationOptionalWithCredentialIDList"),
        ("custom-policy", "custom-policy"),
    ],
)
def test_register_complete_maps_cred_protect_display_and_handles_public_key_alg_fallbacks(
    monkeypatch,
    cred_protect_value,
    expected_display,
):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    _install_register_complete_defaults(monkeypatch, advanced_module)

    class _CredentialData:
        credential_id = b"cred-two"
        public_key = {"alg": -7, "bad": object()}
        aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")

    class _Flag:
        UP = 0x01
        UV = 0x04
        BE = 0x08
        BS = 0x10
        AT = 0x40
        ED = 0x80

    class _AuthData:
        FLAG = _Flag
        credential_data = _CredentialData()
        rp_id_hash = hashlib.sha256(b"example.com").digest()
        flags = _Flag.UP | _Flag.AT
        counter = 3
        extensions = {}

        def __bytes__(self):
            return b"auth-data-two"

    class _Server:
        def register_complete(self, _state, _response):
            return _AuthData()

    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _Server(), raising=False)
    monkeypatch.setattr(
        advanced_module,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {"largeBlob": {"supported": True}}, None, []),
        raising=False,
    )
    monkeypatch.setattr(advanced_module, "extract_min_pin_length", lambda _results: None, raising=False)
    monkeypatch.setattr(
        advanced_module,
        "perform_attestation_checks",
        lambda *_args, **_kwargs: {
            "signature_valid": True,
            "root_valid": True,
            "rp_id_hash_valid": None,
            "aaguid_match": True,
            "metadata": {},
            "warnings": [],
        },
        raising=False,
    )
    monkeypatch.setattr(advanced_module, "summarize_authenticator_extensions", lambda _ext: {}, raising=False)
    monkeypatch.setattr(advanced_module, "_generate_storage_id", lambda _source: "generated::storage::id", raising=False)
    monkeypatch.setattr(
        advanced_module.uuid,
        "UUID",
        lambda **_kwargs: (_ for _ in ()).throw(ValueError("invalid uuid")),
        raising=False,
    )

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_state"] = {"challenge": "state-token"}
            session_state["advanced_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/register/complete",
            json={
                "publicKey": {
                    "challenge": "AQID",
                    "rp": {"id": "example.com", "name": "Example"},
                    "user": {"name": "user@example.com", "displayName": "User"},
                    "extensions": {"credProtect": cred_protect_value},
                },
                "__credential_response": {
                    "response": {},
                },
            },
        )

    assert response.status_code == 200
    body = response.get_json()
    assert body["credProtectUsed"] == expected_display


def test_authenticate_begin_uses_stored_rp_required_uv_and_skips_invalid_allow_credentials(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    marker = object()
    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [
                {
                    "id": b"cred-id",
                    "data": marker,
                    "attachment": None,
                    "algorithm": -7,
                    "resident": True,
                }
            ],
            [{"credentialId": "cred", "publicKey": "pk", "resident": True}],
        ),
        raising=False,
    )

    captured = {}

    class _Server:
        def __init__(self):
            self.allowed_algorithms = []
            self.timeout = None

        def authenticate_begin(self, credentials, *, user_verification, challenge, extensions):
            captured["credentials"] = credentials
            captured["user_verification"] = user_verification
            captured["challenge"] = challenge
            captured["extensions"] = extensions
            return {
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": "placeholder"}],
                }
            }, {"challenge": "state-token"}

    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _Server(), raising=False)
    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or "example.com", raising=False)

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/authenticate/begin",
            json={
                "publicKey": {
                    "challenge": "0102",
                    "userVerification": "required",
                    "allowCredentials": [
                        {"type": "not-public-key", "id": "00"},
                        {"type": "public-key", "id": "zz"},
                        {"type": "public-key", "id": 7},
                        {"type": "public-key", "id": b"cred-id".hex()},
                    ],
                },
                "__storedCredentials": [{"record": 1}],
            },
        )

    assert response.status_code == 200
    assert captured["credentials"] == [marker]
    assert getattr(captured["user_verification"], "value", captured["user_verification"]) == "required"
