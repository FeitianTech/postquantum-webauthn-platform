import base64
import hashlib

import pytest


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

    def __init__(self, *, credential_id: bytes, rp_id: str, counter: int = 7, algorithm: int = -7):
        self.credential_data = _FakeCredentialData(credential_id, algorithm=algorithm)
        self.rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        self.flags = self.FLAG.UP | self.FLAG.AT
        self.counter = counter
        self.extensions = {}

    def __bytes__(self):
        return self.rp_id_hash + bytes([self.flags]) + int(self.counter).to_bytes(4, "big")


class _SimpleFakeServer:
    def __init__(self, auth_data):
        self._auth_data = auth_data

    def register_complete(self, *_args, **_kwargs):
        return self._auth_data


def test_simple_register_complete_returns_500_when_savekey_fails(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    credential_id = b"simple-savekey-fail"
    rp_id = "example.com"

    auth_data = _FakeAuthData(credential_id=credential_id, rp_id=rp_id)

    monkeypatch.setattr(simple_module, "determine_rp_id", lambda: rp_id, raising=False)
    monkeypatch.setattr(
        simple_module,
        "create_fido_server",
        lambda **_kwargs: _SimpleFakeServer(auth_data),
        raising=False,
    )
    monkeypatch.setattr(
        simple_module,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {}, None, []),
        raising=False,
    )
    monkeypatch.setattr(
        simple_module,
        "perform_attestation_checks",
        lambda *_args, **_kwargs: {
            "signature_valid": True,
            "root_valid": True,
            "rp_id_hash_valid": True,
            "aaguid_match": True,
            "warnings": [],
        },
        raising=False,
    )
    monkeypatch.setattr(simple_module, "extract_min_pin_length", lambda _ext: None, raising=False)
    monkeypatch.setattr(simple_module, "add_public_key_material", lambda *_args, **_kwargs: None, raising=False)
    monkeypatch.setattr(simple_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(simple_module, "readkey", lambda *_args, **_kwargs: [], raising=False)
    monkeypatch.setattr(
        simple_module,
        "savekey",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("storage unavailable")),
        raising=False,
    )
    monkeypatch.setattr(simple_module, "record_registration_event", lambda *_args, **_kwargs: None, raising=False)

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["state"] = {"challenge": "state"}
            session_state["register_rp_id"] = rp_id
            session_state["simple_register_public_key"] = {"challenge": "AQID"}

        response = client.post(
            "/api/register/complete?email=user@example.com",
            json={
                "rawId": _b64url(credential_id),
                "response": {
                    "attestationObject": _b64url(b"attestation"),
                    "clientDataJSON": _b64url(b"client-data"),
                },
            },
        )

    assert response.status_code == 500
    assert response.get_json() == {"error": "Unable to persist registered credential."}


def _install_advanced_register_common_monkeypatches(monkeypatch, advanced_module, auth_data, rp_id):
    class _AdvancedFakeServer:
        def register_complete(self, *_args, **_kwargs):
            return auth_data

    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or rp_id, raising=False)
    monkeypatch.setattr(
        advanced_module,
        "create_fido_server",
        lambda **_kwargs: _AdvancedFakeServer(),
        raising=False,
    )
    monkeypatch.setattr(advanced_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(advanced_module, "readkey", lambda *_args, **_kwargs: [], raising=False)
    monkeypatch.setattr(
        advanced_module,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {}, None, []),
        raising=False,
    )
    monkeypatch.setattr(
        advanced_module,
        "perform_attestation_checks",
        lambda *_args, **_kwargs: {
            "signature_valid": True,
            "root_valid": True,
            "rp_id_hash_valid": True,
            "aaguid_match": True,
            "warnings": [],
        },
        raising=False,
    )
    monkeypatch.setattr(advanced_module, "extract_min_pin_length", lambda _ext: None, raising=False)
    monkeypatch.setattr(advanced_module, "add_public_key_material", lambda *_args, **_kwargs: None, raising=False)
    monkeypatch.setattr(advanced_module, "augment_aaguid_fields", lambda *_args, **_kwargs: None, raising=False)


def _advanced_register_payload(rp_id: str, credential_id: bytes):
    return {
        "publicKey": {
            "challenge": "AQID",
            "rp": {"id": rp_id, "name": "Example"},
            "user": {"name": "user@example.com", "displayName": "User"},
        },
        "__credential_response": {
            "rawId": _b64url(credential_id),
            "authenticatorAttachment": "platform",
            "response": {
                "attestationObject": _b64url(b"attestation"),
                "clientDataJSON": _b64url(b"client-data"),
            },
        },
    }


def test_advanced_register_complete_returns_500_when_artifact_store_returns_false(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    credential_id = b"advanced-store-false"
    rp_id = "example.com"
    auth_data = _FakeAuthData(credential_id=credential_id, rp_id=rp_id)
    registration_events = []

    _install_advanced_register_common_monkeypatches(monkeypatch, advanced_module, auth_data, rp_id)
    monkeypatch.setattr(advanced_module, "store_credential_artifact", lambda *_args, **_kwargs: False, raising=False)
    monkeypatch.setattr(
        advanced_module,
        "record_registration_event",
        lambda event: registration_events.append(event),
        raising=False,
    )

    payload = _advanced_register_payload(rp_id, credential_id)

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_state"] = {"challenge": "state"}
            session_state["advanced_rp"] = {"id": rp_id, "name": "Example"}
            session_state["advanced_register_allowed_attachments"] = ["platform"]

        response = client.post("/api/advanced/register/complete", json=payload)

        with client.session_transaction() as session_state:
            assert "advanced_state" not in session_state
            assert "advanced_rp" not in session_state
            assert "advanced_register_allowed_attachments" not in session_state

    assert response.status_code == 500
    assert response.get_json() == {"error": "Unable to persist credential artifact."}
    assert registration_events == []


def test_advanced_register_complete_returns_500_when_artifact_store_raises(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    credential_id = b"advanced-store-raises"
    rp_id = "example.com"
    auth_data = _FakeAuthData(credential_id=credential_id, rp_id=rp_id)
    registration_events = []

    _install_advanced_register_common_monkeypatches(monkeypatch, advanced_module, auth_data, rp_id)
    monkeypatch.setattr(
        advanced_module,
        "store_credential_artifact",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("artifact store down")),
        raising=False,
    )
    monkeypatch.setattr(
        advanced_module,
        "record_registration_event",
        lambda event: registration_events.append(event),
        raising=False,
    )

    payload = _advanced_register_payload(rp_id, credential_id)

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_state"] = {"challenge": "state"}
            session_state["advanced_rp"] = {"id": rp_id, "name": "Example"}
            session_state["advanced_register_allowed_attachments"] = ["platform"]

        response = client.post("/api/advanced/register/complete", json=payload)

        with client.session_transaction() as session_state:
            assert "advanced_state" not in session_state
            assert "advanced_rp" not in session_state
            assert "advanced_register_allowed_attachments" not in session_state

    assert response.status_code == 500
    assert response.get_json() == {"error": "Unable to persist credential artifact."}
    assert registration_events == []


def test_advanced_register_complete_returns_400_when_add_public_key_material_raises(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    credential_id = b"advanced-public-key-material-raises"
    rp_id = "example.com"
    auth_data = _FakeAuthData(credential_id=credential_id, rp_id=rp_id)
    registration_events = []
    artifact_store_calls = []

    _install_advanced_register_common_monkeypatches(monkeypatch, advanced_module, auth_data, rp_id)
    monkeypatch.setattr(
        advanced_module,
        "add_public_key_material",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("public key material unavailable")),
        raising=False,
    )
    monkeypatch.setattr(
        advanced_module,
        "store_credential_artifact",
        lambda *args, **kwargs: artifact_store_calls.append((args, kwargs)) or True,
        raising=False,
    )
    monkeypatch.setattr(
        advanced_module,
        "record_registration_event",
        lambda event: registration_events.append(event),
        raising=False,
    )

    payload = _advanced_register_payload(rp_id, credential_id)

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_state"] = {"challenge": "state"}
            session_state["advanced_rp"] = {"id": rp_id, "name": "Example"}
            session_state["advanced_register_allowed_attachments"] = ["platform"]

        response = client.post("/api/advanced/register/complete", json=payload)

        with client.session_transaction() as session_state:
            assert "advanced_state" not in session_state
            assert "advanced_rp" not in session_state
            assert "advanced_register_allowed_attachments" not in session_state

    assert response.status_code == 400
    assert response.get_json() == {"error": "public key material unavailable"}
    assert artifact_store_calls == []
    assert registration_events == []
