import base64
import hashlib

import pytest


def _minimal_register_complete_payload(*, include_public_key: bool = True):
    payload = {
        "__credential_response": {
            "response": {},
        },
    }
    if include_public_key:
        payload["publicKey"] = {
            "challenge": "AQID",
            "rp": {"id": "example.com", "name": "Example RP"},
            "user": {"name": "user@example.com", "displayName": "User"},
        }
    return payload


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class _FakeCredentialData:
    def __init__(self, credential_id: bytes, *, algorithm: int = -7):
        self.credential_id = credential_id
        self.public_key = {1: 2, 3: algorithm, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32}
        self.aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")


class _FakeAuthData:
    class FLAG:
        UP = 0x01
        UV = 0x04
        BE = 0x08
        BS = 0x10
        AT = 0x40
        ED = 0x80

    def __init__(self, *, credential_id: bytes, rp_id: str, counter: int = 9):
        self.credential_data = _FakeCredentialData(credential_id)
        self.rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        self.flags = self.FLAG.UP | self.FLAG.AT
        self.counter = counter
        self.extensions = {}

    def __bytes__(self):
        return self.rp_id_hash + bytes([self.flags]) + int(self.counter).to_bytes(4, "big")


def test_advanced_register_complete_prefers_session_state_over_request_state(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    captured = {}

    class _FailingServer:
        def register_complete(self, state, _response):
            captured["state"] = state
            raise ValueError("register failure")

    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FailingServer(), raising=False)
    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or "example.com", raising=False)

    session_state = {"challenge": "session-state"}
    request_state = {"challenge": "request-state"}

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_store:
            session_store["advanced_state"] = session_state
            session_store["advanced_rp"] = {"id": "example.com", "name": "Example RP"}

        payload = _minimal_register_complete_payload()
        payload["__session_state"] = request_state

        response = client.post("/api/advanced/register/complete", json=payload)

        assert response.status_code == 400
        assert response.get_json() == {"error": "register failure"}
        assert captured["state"] == session_state

        with client.session_transaction() as session_store:
            assert "advanced_state" not in session_store
            assert "advanced_rp" not in session_store


def test_advanced_register_complete_uses_request_state_fallback_when_session_missing(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    captured = {}

    class _FailingServer:
        def register_complete(self, state, _response):
            captured["state"] = state
            raise ValueError("register fallback failure")

    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FailingServer(), raising=False)
    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or "example.com", raising=False)

    fallback_state = {"challenge": "request-fallback-state"}

    with config_module.app.test_client() as client:
        payload = _minimal_register_complete_payload()
        payload["__session_state"] = fallback_state

        response = client.post("/api/advanced/register/complete", json=payload)

    assert response.status_code == 400
    assert response.get_json() == {"error": "register fallback failure"}
    assert captured["state"] == fallback_state


def test_advanced_register_complete_invalid_request_state_fallback_returns_400(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_store:
            session_store["advanced_rp"] = {"id": "example.com", "name": "Example RP"}

        payload = _minimal_register_complete_payload()
        payload["__session_state"] = "invalid"

        response = client.post("/api/advanced/register/complete", json=payload)

        assert response.status_code == 400
        assert "Registration state not found or has expired" in response.get_json()["error"]

        with client.session_transaction() as session_store:
            # advanced_rp remains untouched because state validation exits before RP resolution.
            assert session_store.get("advanced_rp") == {"id": "example.com", "name": "Example RP"}


def test_advanced_register_complete_requires_attachment_when_hints_resolve_to_attachment():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        payload = _minimal_register_complete_payload()
        payload["publicKey"]["hints"] = ["security-key"]

        response = client.post("/api/advanced/register/complete", json=payload)

    assert response.status_code == 400
    assert "Authenticator attachment could not be determined" in response.get_json()["error"]


def test_advanced_register_complete_prefers_session_attachment_scope_over_tampered_request_hints(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(advanced_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(advanced_module, "readkey", lambda *_args, **_kwargs: [], raising=False)
    monkeypatch.setattr(
        advanced_module,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {}, None, []),
        raising=False,
    )

    class _FailingServer:
        def register_complete(self, *_args, **_kwargs):
            raise ValueError("register reached")

    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FailingServer(), raising=False)
    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or "example.com", raising=False)

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_store:
            session_store["advanced_state"] = {"challenge": "session-state"}
            session_store["advanced_rp"] = {"id": "example.com", "name": "Example RP"}
            session_store["advanced_register_allowed_attachments"] = ["platform"]

        payload = _minimal_register_complete_payload()
        payload["publicKey"]["hints"] = ["security-key"]
        payload["__credential_response"]["authenticatorAttachment"] = "platform"

        response = client.post("/api/advanced/register/complete", json=payload)

        assert response.status_code == 400
        assert response.get_json() == {"error": "register reached"}

        with client.session_transaction() as session_store:
            assert "advanced_register_allowed_attachments" not in session_store


def test_advanced_register_complete_success_contract_propagates_warnings_and_records_artifact(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    credential_id = b"advanced-register-success"
    rp_id = "rp.example"

    captured = {}
    artifacts_written = []

    class _FakeServer:
        def register_complete(self, state, _response):
            captured["state"] = state
            return _FakeAuthData(credential_id=credential_id, rp_id=rp_id)

    def _perform_attestation_checks(
        response,
        state,
        public_key_options,
        auth_data,
        expected_origin,
        resolved_rp_id,
    ):
        captured["attestation_response"] = response
        captured["attestation_state"] = state
        captured["attestation_public_key"] = public_key_options
        captured["attestation_auth_data"] = auth_data
        captured["expected_origin"] = expected_origin
        captured["resolved_rp_id"] = resolved_rp_id
        return {
            "signature_valid": True,
            "root_valid": True,
            "rp_id_hash_valid": True,
            "aaguid_match": True,
            "metadata": {"description": "Demo authenticator"},
            "warnings": ["  retained warning  ", "", None, "second warning"],
        }

    def _store_credential_artifact(storage_id, payload, *, merge=False, session_id=None):
        artifacts_written.append(
            {
                "storage_id": storage_id,
                "payload": payload,
                "merge": merge,
                "session_id": session_id,
            }
        )

    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FakeServer(), raising=False)
    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or rp_id, raising=False)
    monkeypatch.setattr(advanced_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(advanced_module, "readkey", lambda *_args, **_kwargs: [], raising=False)
    monkeypatch.setattr(advanced_module, "perform_attestation_checks", _perform_attestation_checks, raising=False)
    monkeypatch.setattr(
        advanced_module,
        "extract_attestation_details",
        lambda _response: (
            "none",
            {},
            None,
            None,
            {"credProps": {"rk": True}},
            None,
            [],
        ),
        raising=False,
    )
    monkeypatch.setattr(advanced_module, "add_public_key_material", lambda *_args, **_kwargs: None, raising=False)
    monkeypatch.setattr(advanced_module, "augment_aaguid_fields", lambda *_args, **_kwargs: None, raising=False)
    monkeypatch.setattr(advanced_module, "store_credential_artifact", _store_credential_artifact, raising=False)
    monkeypatch.setattr(advanced_module, "record_registration_event", lambda _event: None, raising=False)

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_store:
            session_store["advanced_state"] = {"challenge": "session-state"}
            session_store["advanced_rp"] = {"id": rp_id, "name": "Example RP"}
            session_store["advanced_register_allowed_attachments"] = ["platform"]

        payload = _minimal_register_complete_payload()
        payload["publicKey"]["rp"] = {"id": rp_id, "name": "Example RP"}
        payload["__credential_response"] = {
            "rawId": _b64url(credential_id),
            "authenticatorAttachment": "platform",
            "response": {
                "attestationObject": _b64url(b"attestation"),
                "clientDataJSON": _b64url(b"client-data"),
            },
        }

        response = client.post(
            "/api/advanced/register/complete",
            json=payload,
            headers={"Origin": "https://origin.example"},
        )

        assert response.status_code == 200
        body = response.get_json()
        assert body["status"] == "OK"
        assert body["warnings"] == ["retained warning", "second warning"]

        stored_credential = body["storedCredential"]
        assert stored_credential["hasServerArtifact"] is True
        assert stored_credential["artifactVersion"] == 1
        assert stored_credential["storageId"] == stored_credential["localStorageId"]

        assert captured["expected_origin"] == "https://origin.example"
        assert captured["resolved_rp_id"] == rp_id
        assert isinstance(captured["attestation_public_key"], dict)

        assert len(artifacts_written) == 1
        assert artifacts_written[0]["session_id"] == "session-id"
        assert artifacts_written[0]["payload"]["schemaVersion"] == 1

        with client.session_transaction() as session_store:
            assert "advanced_state" not in session_store
            assert "advanced_rp" not in session_store
            assert "advanced_register_allowed_attachments" not in session_store
