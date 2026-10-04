import hashlib
from types import SimpleNamespace

from server.app import visitor_session
from server.app.config import relying_party
from server.app.routes.simple import parsing as simple_parsing
from server.app.storage import credentials as storage_credentials
from server.app.storage import github_mirror
from server.app.webauthn.attestation import aaguid as attestation_aaguid
from server.app.webauthn.attestation import certificates as attestation_certificates
from server.app.webauthn.attestation import checks as attestation_checks
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import (
    b64u,
    keep_simple_credentials,
    simple_complete_body,
)


class _FakeCredentialData:
    def __init__(self, credential_id: bytes, public_key: dict, aaguid: bytes):
        self.credential_id = credential_id
        self.public_key = public_key
        self.aaguid = aaguid


class _FakeAuthData:
    class FLAG:
        UP = 0x01
        UV = 0x04
        BE = 0x08
        BS = 0x10
        AT = 0x40
        ED = 0x80

    def __init__(self, credential_data: _FakeCredentialData, rp_id_hash: bytes, *, flags: int, counter: int):
        self.credential_data = credential_data
        self.rp_id_hash = rp_id_hash
        self.flags = flags
        self.counter = counter
        self.extensions = {}

    def __bytes__(self):
        return self.rp_id_hash + bytes([self.flags]) + int(self.counter).to_bytes(4, "big")


def test_simple_authenticate_begin_requires_valid_credentials(monkeypatch):
    monkeypatch.setattr(simple_parsing, "_parse_client_credentials", lambda _raw: ([], []))

    with entry_app().test_client() as client:
        response = client.post(
            "/api/authenticate/begin?email=user@example.com",
            json={"credentials": []},
        )

    assert response.status_code == 404


def test_simple_authenticate_complete_rejects_request_state_fallback(monkeypatch):
    """A client-supplied ``__session_state`` must never become the challenge."""

    credential_id = b"simple-auth-fallback"
    captured = {}

    class _FakeServer:
        def authenticate_complete(self, state, *_args, **_kwargs):
            captured["state"] = state
            return SimpleNamespace(credential_id=credential_id)

    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())
    monkeypatch.setattr(
        simple_parsing,
        "_parse_client_credentials",
        lambda _raw: ([object()], [{"credentialId": b64u(credential_id)}])
    )

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            keep_simple_credentials(session_state, [{"credentialId": b64u(credential_id)}])
            session_state["authenticate_rp_id"] = "example.com"
            # Deliberately no server-issued "state" in the session.

        response = client.post(
            "/api/authenticate/complete?email=user@example.com",
            json=simple_complete_body(
                {
                    "rawId": b64u(credential_id),
                    "response": {"authenticatorData": "AQID"},
                    "__session_state": {"challenge": "fallback-state"},
                },
                [{"credentialId": b64u(credential_id)}],
            ),
        )

        assert response.status_code == 400
        assert "state" in response.get_json()["error"].lower()
        # Verification must not even have been attempted.
        assert "state" not in captured


def test_simple_authenticate_complete_missing_state_returns_400(monkeypatch):
    monkeypatch.setattr(
        simple_parsing,
        "_parse_client_credentials",
        lambda _raw: ([object()], [{"credentialId": "cred-1"}])
    )

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            keep_simple_credentials(session_state, [{"credentialId": "cred-1"}])
            session_state["authenticate_rp_id"] = "example.com"
            session_state["simple_credentials_email"] = "user@example.com"

        response = client.post(
            "/api/authenticate/complete?email=user@example.com",
            json=simple_complete_body({"rawId": "cred-1", "response": {}}, [{"credentialId": "cred-1"}]),
        )

        assert response.status_code == 400
        assert "Authentication state not found or has expired" in response.get_json()["error"]

        with client.session_transaction() as session_state:
            assert "authenticate_rp_id" not in session_state
            assert session_state.get("simple_credentials_email") == "user@example.com"


def test_simple_register_complete_rejects_request_state_fallback(monkeypatch):
    """A cold /complete with a self-chosen challenge must be rejected."""

    rp_id = "example.com"
    credential_id = b"simple-register-cred"
    aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")
    rp_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()

    fake_credential_data = _FakeCredentialData(
        credential_id=credential_id,
        public_key={1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32},
        aaguid=aaguid,
    )
    fake_auth_data = _FakeAuthData(
        credential_data=fake_credential_data,
        rp_id_hash=rp_hash,
        flags=_FakeAuthData.FLAG.UP | _FakeAuthData.FLAG.AT,
        counter=11,
    )

    captured = {}
    saved = {}

    class _FakeServer:
        def register_complete(self, state, _response):
            captured["state"] = state
            return fake_auth_data

    monkeypatch.setattr(relying_party, "determine_rp_id", lambda: rp_id)
    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())
    monkeypatch.setattr(
        attestation_certificates,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {}, None, [])
    )
    monkeypatch.setattr(attestation_checks, "perform_attestation_checks", lambda *args, **kwargs: {
        "signature_valid": True,
        "root_valid": True,
        "rp_id_hash_valid": True,
        "aaguid_match": True,
        "warnings": [],
    })
    monkeypatch.setattr(attestation_aaguid, "extract_min_pin_length", lambda _ext: None)
    monkeypatch.setattr(storage_credentials, "add_public_key_material", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(visitor_session, "ensure_id", lambda: "session-id")
    monkeypatch.setattr(storage_credentials, "read_for_update", lambda *_args, **_kwargs: ([], None))

    def _fake_save_if_unchanged(email, credentials, version, *, session_id=None):
        saved["email"] = email
        saved["credentials"] = credentials
        saved["session_id"] = session_id
        return True

    monkeypatch.setattr(storage_credentials, "save_if_unchanged", _fake_save_if_unchanged)
    monkeypatch.setattr(github_mirror, "record_registration_event", lambda _event: None)

    request_state = {"challenge": "fallback-register-state"}

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["register_rp_id"] = rp_id
            session_state["simple_register_public_key"] = {"challenge": "ignored"}

        response = client.post(
            "/api/register/complete?email=user@example.com",
            json={
                "__session_state": request_state,
                "rawId": b64u(credential_id),
                "authenticatorAttachment": "cross-platform",
                "response": {
                    "attestationObject": b64u(b"attestation"),
                    "clientDataJSON": b64u(b"client-data"),
                },
            },
        )

        assert response.status_code == 400
        payload = response.get_json()
        assert payload.get("status") != "OK"
        assert "state" in payload["error"].lower()
        # Neither verification nor persistence may have happened.
        assert "state" not in captured
        assert saved == {}

        with client.session_transaction() as session_state:
            assert "state" not in session_state
