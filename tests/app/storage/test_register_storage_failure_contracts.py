import hashlib
import time

from server.app import visitor_session
from server.app.config import relying_party
from server.app.storage import credential_artifacts, github_mirror
from server.app.storage import credentials as storage_credentials
from server.app.webauthn.attestation import aaguid as attestation_aaguid
from server.app.webauthn.attestation import certificates as attestation_certificates
from server.app.webauthn.attestation import checks as attestation_checks
from tests.app.entry_app import entry_app
from tests.app.fido2_stand_ins import ES256_KEY, CredentialData
from tests.app.security.ceremony_helpers import b64u


class _FakeAuthData:
    class FLAG:
        UP = 0x01
        UV = 0x04
        BE = 0x08
        BS = 0x10
        AT = 0x40
        ED = 0x80

    def __init__(self, *, credential_id: bytes, rp_id: str, counter: int = 7, algorithm: int = -7):
        self.credential_data = CredentialData(credential_id=credential_id, public_key={**ES256_KEY, 3: algorithm})
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


def test_simple_register_complete_returns_500_when_saving_fails(monkeypatch):
    credential_id = b"simple-save-fail"
    rp_id = "example.com"

    auth_data = _FakeAuthData(credential_id=credential_id, rp_id=rp_id)

    monkeypatch.setattr(relying_party, "determine_rp_id", lambda: rp_id)
    monkeypatch.setattr(
        relying_party,
        "create_fido_server",
        lambda **_kwargs: _SimpleFakeServer(auth_data)
    )
    monkeypatch.setattr(
        attestation_certificates,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {}, None, [])
    )
    monkeypatch.setattr(
        attestation_checks,
        "perform_attestation_checks",
        lambda *_args, **_kwargs: {
            "signature_valid": True,
            "root_valid": True,
            "rp_id_hash_valid": True,
            "aaguid_match": True,
            "warnings": [],
        }
    )
    monkeypatch.setattr(attestation_aaguid, "extract_min_pin_length", lambda _ext: None)
    monkeypatch.setattr(storage_credentials, "add_public_key_material", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(visitor_session, "ensure_id", lambda: "session-id")
    monkeypatch.setattr(storage_credentials, "read_for_update", lambda *_args, **_kwargs: ([], None))
    monkeypatch.setattr(
        storage_credentials,
        "save_if_unchanged",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("storage unavailable"))
    )
    # Read again after the failed save, to tell a write that landed from one that did not.
    monkeypatch.setattr(storage_credentials, "readkey", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(github_mirror, "record_registration_event", lambda *_args, **_kwargs: None)

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["state"] = {"challenge": "state", "issued_at": time.time()}
            session_state["register_rp_id"] = rp_id
            session_state["simple_register_public_key"] = {"challenge": "AQID"}

        response = client.post(
            "/api/register/complete?email=user@example.com",
            json={
                "rawId": b64u(credential_id),
                "response": {
                    "attestationObject": b64u(b"attestation"),
                    "clientDataJSON": b64u(b"client-data"),
                },
            },
        )

    assert response.status_code == 500
    assert response.get_json() == {"error": "Unable to persist registered credential."}


def _install_advanced_register_common_monkeypatches(monkeypatch, auth_data, rp_id):
    class _AdvancedFakeServer:
        def register_complete(self, *_args, **_kwargs):
            return auth_data

    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or rp_id)
    monkeypatch.setattr(
        relying_party,
        "create_fido_server",
        lambda **_kwargs: _AdvancedFakeServer()
    )
    monkeypatch.setattr(visitor_session, "ensure_id", lambda: "session-id")
    monkeypatch.setattr(
        attestation_certificates,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {}, None, [])
    )
    monkeypatch.setattr(
        attestation_checks,
        "perform_attestation_checks",
        lambda *_args, **_kwargs: {
            "signature_valid": True,
            "root_valid": True,
            "rp_id_hash_valid": True,
            "aaguid_match": True,
            "warnings": [],
        }
    )
    monkeypatch.setattr(attestation_aaguid, "extract_min_pin_length", lambda _ext: None)
    monkeypatch.setattr(storage_credentials, "add_public_key_material", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(attestation_aaguid, "augment_aaguid_fields", lambda *_args, **_kwargs: None)


def _advanced_register_payload(rp_id: str, credential_id: bytes):
    return {
        "publicKey": {
            "challenge": "AQID",
            "rp": {"id": rp_id, "name": "Example"},
            "user": {"name": "user@example.com", "displayName": "User"},
        },
        "__credential_response": {
            "rawId": b64u(credential_id),
            "authenticatorAttachment": "platform",
            "response": {
                "attestationObject": b64u(b"attestation"),
                "clientDataJSON": b64u(b"client-data"),
            },
        },
    }


def test_advanced_register_complete_returns_500_when_artifact_store_returns_false(monkeypatch):
    credential_id = b"advanced-store-false"
    rp_id = "example.com"
    auth_data = _FakeAuthData(credential_id=credential_id, rp_id=rp_id)
    registration_events = []

    _install_advanced_register_common_monkeypatches(monkeypatch, auth_data, rp_id)
    monkeypatch.setattr(credential_artifacts, "store_credential_artifact", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(
        github_mirror,
        "record_registration_event",
        lambda event: registration_events.append(event)
    )

    payload = _advanced_register_payload(rp_id, credential_id)

    with entry_app().test_client() as client:
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
    assert response.get_json() == {
        "error": "Unable to persist credential artifact.",
        # A hand-made session state, never stamped by /begin.
        "challengeSource": "server-session",
        "challengeStatus": "expired",
    }
    assert registration_events == []


def test_advanced_register_complete_returns_500_when_artifact_store_raises(monkeypatch):
    credential_id = b"advanced-store-raises"
    rp_id = "example.com"
    auth_data = _FakeAuthData(credential_id=credential_id, rp_id=rp_id)
    registration_events = []

    _install_advanced_register_common_monkeypatches(monkeypatch, auth_data, rp_id)
    monkeypatch.setattr(
        credential_artifacts,
        "store_credential_artifact",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("artifact store down"))
    )
    monkeypatch.setattr(
        github_mirror,
        "record_registration_event",
        lambda event: registration_events.append(event)
    )

    payload = _advanced_register_payload(rp_id, credential_id)

    with entry_app().test_client() as client:
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
    assert response.get_json() == {
        "error": "Unable to persist credential artifact.",
        # A hand-made session state, never stamped by /begin.
        "challengeSource": "server-session",
        "challengeStatus": "expired",
    }
    assert registration_events == []


def test_advanced_register_complete_returns_400_when_add_public_key_material_raises(monkeypatch):
    credential_id = b"advanced-public-key-material-raises"
    rp_id = "example.com"
    auth_data = _FakeAuthData(credential_id=credential_id, rp_id=rp_id)
    registration_events = []
    artifact_store_calls = []

    _install_advanced_register_common_monkeypatches(monkeypatch, auth_data, rp_id)
    monkeypatch.setattr(
        storage_credentials,
        "add_public_key_material",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("public key material unavailable"))
    )
    monkeypatch.setattr(
        credential_artifacts,
        "store_credential_artifact",
        lambda *args, **kwargs: artifact_store_calls.append((args, kwargs)) or True
    )
    monkeypatch.setattr(
        github_mirror,
        "record_registration_event",
        lambda event: registration_events.append(event)
    )

    payload = _advanced_register_payload(rp_id, credential_id)

    with entry_app().test_client() as client:
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
    assert response.get_json() == {
        "error": "public key material unavailable",
        "challengeSource": "server-session",
        "challengeStatus": "expired",
    }
    assert artifact_store_calls == []
    assert registration_events == []
