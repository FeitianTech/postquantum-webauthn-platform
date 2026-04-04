from __future__ import annotations

import binascii
import types

import pytest


def _base_register_begin_payload() -> dict:
    return {
        "publicKey": {
            "rp": {"id": "example.com", "name": "Example"},
            "user": {
                "name": "user@example.com",
                "displayName": "User",
            },
            "challenge": "0a0b0c0d",
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        }
    }


def _install_fake_register_server(monkeypatch, advanced_module, captured: dict):
    class _FakeServer:
        def __init__(self):
            self.allowed_algorithms = []
            self.timeout = None
            self.attestation = None

        def register_begin(self, *args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return {"publicKey": {"challenge": "AQID"}}, {"challenge": "state-token"}

    monkeypatch.setattr(
        advanced_module,
        "create_fido_server",
        lambda **_kwargs: _FakeServer(),
        raising=False,
    )


def test_summary_helpers_drop_non_mapping_inputs_and_nested_non_mapping_sections():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    assert advanced_module._summarize_properties("not-a-mapping") is None
    assert advanced_module._summarize_relying_party(["not-a-mapping"]) is None

    summary = advanced_module._summarize_stored_credential(
        {
            "credentialId": "cred",
            "registrationResponse": {"heavy": True},
            "properties": "invalid-shape",
            "relyingParty": ["invalid-shape"],
        },
        "storage-id",
    )

    assert "registrationResponse" not in summary
    assert "properties" not in summary
    assert "relyingParty" not in summary
    assert summary["storageId"] == "storage-id"
    assert summary["localStorageId"] == "storage-id"


def test_decode_client_binary_handles_recursive_wrappers_and_validation_failures(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    assert advanced_module._decode_client_binary({"hex": {"$hex": "6162"}}) == b"ab"
    assert advanced_module._decode_client_binary({"base64url": "YWI"}) == b"ab"
    assert advanced_module._decode_client_binary({"base64url": {"$hex": "6162"}}) == b"ab"
    assert advanced_module._decode_client_binary({"base64": {"$hex": "6162"}}) == b"ab"

    with pytest.raises(ValueError, match="empty binary value"):
        advanced_module._decode_client_binary({"base64url": "   "})

    monkeypatch.setattr(
        advanced_module.base64,
        "urlsafe_b64decode",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(binascii.Error("bad b64u")),
        raising=False,
    )
    with pytest.raises(ValueError, match="invalid binary value"):
        advanced_module._decode_client_binary({"base64url": "YWI"})

    monkeypatch.setattr(
        advanced_module.base64,
        "b64decode",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(binascii.Error("bad b64")),
        raising=False,
    )
    with pytest.raises(ValueError, match="invalid binary value"):
        advanced_module._decode_client_binary({"base64": "YWI="})


def test_algorithm_coercion_handles_blank_values_failed_numeric_extraction_and_pqc_allowlist(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    assert advanced_module._lookup_named_cose_algorithm("   ") is None
    assert advanced_module._coerce_cose_algorithm("   ") is None

    class _BadMatch:
        def group(self, _index=0):
            return "--"

    class _BadPattern:
        def finditer(self, _value):
            return [_BadMatch()]

    monkeypatch.setattr(
        advanced_module,
        "_COSE_ALGORITHM_NUMERIC_PATTERN",
        _BadPattern(),
        raising=False,
    )
    assert advanced_module._coerce_cose_algorithm("custom algorithm -- broken") is None

    monkeypatch.setattr(
        advanced_module,
        "PQC_ALGORITHM_ID_TO_NAME",
        {123456: "PQ-Example"},
        raising=False,
    )
    assert advanced_module._is_custom_cose_algorithm(123456) is False


def test_base64url_and_assertion_algorithm_helpers_degrade_gracefully_on_decode_errors(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    monkeypatch.setattr(
        advanced_module,
        "_decode_base64url",
        lambda _value: (_ for _ in ()).throw(ValueError("decode failure")),
        raising=False,
    )

    assert advanced_module._decode_base64url_bytes("broken") == b""
    assert advanced_module._extract_assertion_credential_id({"rawId": "broken"}) is None

    requested = advanced_module._extract_requested_assertion_algorithm(
        {
            "allowCredentials": [
                {"type": "public-key", "id": "broken", "alg": "-7"},
            ]
        },
        credential_id=b"target",
    )
    assert requested is None


def test_attestation_log_falls_back_to_plain_string_payload_when_json_encoding_fails(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    class _Flag:
        UP = 0x01
        UV = 0x04
        BE = 0x08
        BS = 0x10
        AT = 0x40
        ED = 0x80

    class _CredentialData:
        aaguid = b"\x00" * 16
        credential_id = b"credential-id"
        public_key = {"alg": "-257", -2: b"x" * 32, -3: b"y" * 32}

    class _AuthData:
        FLAG = _Flag
        rp_id_hash = b"\x11" * 32
        flags = _Flag.UP | _Flag.AT
        counter = 3
        credential_data = _CredentialData()
        extensions = {}

        def __bytes__(self):
            return b"\x00" * 37

    log_messages = []
    monkeypatch.setattr(
        advanced_module.app.logger,
        "info",
        lambda _template, payload: log_messages.append(payload),
        raising=False,
    )
    monkeypatch.setattr(
        advanced_module.json,
        "dumps",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(TypeError("serialization blocked")),
        raising=False,
    )

    advanced_module._log_authenticator_attestation_response(
        "packed",
        _AuthData(),
        {"alg": -257},
        "raw-attestation-object",
    )

    assert log_messages
    assert "credentialPublicKeyAlgorithm" in log_messages[0]
    assert "raw-attestation-object" in log_messages[0]


def test_register_begin_accepts_non_mapping_authenticator_selection_and_derives_cross_platform_from_hints(
    monkeypatch,
):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    captured = {}
    monkeypatch.setattr(
        advanced_module,
        "detect_available_pqc_algorithms",
        lambda: ({-50, -49, -48}, None),
        raising=False,
    )
    _install_fake_register_server(monkeypatch, advanced_module, captured)

    payload = _base_register_begin_payload()
    payload["publicKey"]["authenticatorSelection"] = "unexpected-shape"
    payload["publicKey"]["hints"] = ["security-key"]
    payload["publicKey"]["extensions"] = {
        "largeBlob": {"support": "preferred"},
    }

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/register/begin", json=payload)
        assert response.status_code == 200

        kwargs = captured["kwargs"]
        assert (
            getattr(kwargs["authenticator_attachment"], "value", kwargs["authenticator_attachment"])
            == "cross-platform"
        )

        user_entity = captured["args"][0]
        assert bytes(getattr(user_entity, "id")) == b"user@example.com"

        with client.session_transaction() as session_state:
            assert session_state["advanced_register_allowed_attachments"] == ["cross-platform"]


def test_register_begin_maps_discouraged_uv_require_resident_key_and_extension_aliases(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    captured = {}
    monkeypatch.setattr(
        advanced_module,
        "detect_available_pqc_algorithms",
        lambda: ({-50, -49, -48}, None),
        raising=False,
    )
    _install_fake_register_server(monkeypatch, advanced_module, captured)

    payload = _base_register_begin_payload()
    payload["publicKey"]["user"]["id"] = "01020304"
    payload["publicKey"]["authenticatorSelection"] = {
        "userVerification": "discouraged",
        "requireResidentKey": True,
    }
    payload["publicKey"]["extensions"] = {
        "credProtect": "userVerificationOptionalWithCredentialIdList",
        "prf": {"eval": "unexpected"},
        "customExtension": {"enabled": True},
    }

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/register/begin", json=payload)

    assert response.status_code == 200

    kwargs = captured["kwargs"]
    assert (
        getattr(kwargs["user_verification"], "value", kwargs["user_verification"])
        == "discouraged"
    )
    assert (
        getattr(kwargs["resident_key_requirement"], "value", kwargs["resident_key_requirement"])
        == "required"
    )
    assert kwargs["extensions"]["credentialProtectionPolicy"] == "userVerificationOptionalWithCredentialIDList"
    assert kwargs["extensions"]["prf"] == {"eval": "unexpected"}
    assert kwargs["extensions"]["customExtension"] == {"enabled": True}
