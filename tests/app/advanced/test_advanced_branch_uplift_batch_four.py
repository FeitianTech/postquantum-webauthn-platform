from __future__ import annotations

from server.app import config as config_module
from server.app.config import relying_party
from server.app.routes import advanced as advanced_module
from server.app.routes.advanced import algorithms as advanced_algorithms
from server.app.routes.advanced import summary as advanced_summary
from tests.app.entry_app import entry_app


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


def _install_fake_register_server(monkeypatch, advanced_module, captured: dict, config_module):
    class _FakeServer:
        def __init__(self):
            self.allowed_algorithms = []
            self.timeout = None
            self.attestation = None

        def register_begin(self, *args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return {"publicKey": {"challenge": "AQID"}}, {"challenge": "state-token"}

    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())


def test_summary_helpers_drop_non_mapping_inputs_and_nested_non_mapping_sections():
    assert advanced_summary._summarize_properties("not-a-mapping") is None
    assert advanced_summary._summarize_relying_party(["not-a-mapping"]) is None

    summary = advanced_summary._summarize_stored_credential(
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


def test_register_begin_accepts_non_mapping_authenticator_selection_and_derives_cross_platform_from_hints(monkeypatch, pqc_module):
    captured = {}
    monkeypatch.setattr(advanced_algorithms, "_verifiable_algorithms", lambda: {-50, -49, -48})
    _install_fake_register_server(monkeypatch, advanced_module, captured, config_module)

    payload = _base_register_begin_payload()
    payload["publicKey"]["authenticatorSelection"] = "unexpected-shape"
    payload["publicKey"]["hints"] = ["security-key"]
    payload["publicKey"]["extensions"] = {
        "largeBlob": {"support": "preferred"},
    }

    with entry_app().test_client() as client:
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


def test_register_begin_maps_discouraged_uv_require_resident_key_and_extension_aliases(monkeypatch, pqc_module):
    captured = {}
    monkeypatch.setattr(advanced_algorithms, "_verifiable_algorithms", lambda: {-50, -49, -48})
    _install_fake_register_server(monkeypatch, advanced_module, captured, config_module)

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

    with entry_app().test_client() as client:
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
