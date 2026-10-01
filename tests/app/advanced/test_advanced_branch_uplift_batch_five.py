from __future__ import annotations

from server.app import visitor_session
from server.app.config import relying_party
from server.app.routes.advanced import parsing as advanced_parsing
from server.app.webauthn.attestation import aaguid as attestation_aaguid
from tests.app.entry_app import entry_app


def _install_register_complete_defaults(monkeypatch, advanced_module, attestation_module, credential_artifacts_module, device_logs_module, metadata_module, storage_module, config_module):
    monkeypatch.setattr(visitor_session, "ensure_id", lambda: "session-id")
    monkeypatch.setattr(storage_module, "add_public_key_material", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(attestation_aaguid, "augment_aaguid_fields", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(device_logs_module, "record_registration_event", lambda _event: None)
    monkeypatch.setattr(credential_artifacts_module, "store_credential_artifact", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or "example.com")


def test_helper_none_and_non_string_decode_paths():
    assert advanced_parsing._coerce_optional_bool(None) is None


def test_authenticate_begin_uses_stored_rp_required_uv_and_skips_invalid_allow_credentials(monkeypatch, config_module, advanced_parsing):
    marker = object()
    monkeypatch.setattr(
        advanced_parsing,
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
        )
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

    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _Server())
    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or "example.com")

    with entry_app().test_client() as client:
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
