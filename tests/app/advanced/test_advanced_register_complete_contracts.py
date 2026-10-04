import hashlib

from server.app import visitor_session
from server.app.config import relying_party
from server.app.webauthn.attestation import certificates as attestation_certificates
from tests.app.entry_app import entry_app
from tests.app.fido2_stand_ins import CredentialData


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


class _FakeAuthData:
    class FLAG:
        UP = 0x01
        UV = 0x04
        BE = 0x08
        BS = 0x10
        AT = 0x40
        ED = 0x80

    def __init__(self, *, credential_id: bytes, rp_id: str, counter: int = 9):
        self.credential_data = CredentialData(credential_id=credential_id)
        self.rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        self.flags = self.FLAG.UP | self.FLAG.AT
        self.counter = counter
        self.extensions = {}

    def __bytes__(self):
        return self.rp_id_hash + bytes([self.flags]) + int(self.counter).to_bytes(4, "big")


def test_advanced_register_complete_reads_the_session_state_not_the_requests(monkeypatch):
    captured = {}

    class _FailingServer:
        def register_complete(self, state, _response):
            captured["state"] = state
            raise ValueError("register failure")

    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FailingServer())
    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or "example.com")

    session_state = {"challenge": "session-state"}

    with entry_app().test_client() as client:
        with client.session_transaction() as session_store:
            session_store["advanced_state"] = session_state
            session_store["advanced_rp"] = {"id": "example.com", "name": "Example RP"}

        payload = _minimal_register_complete_payload()
        payload["__session_state"] = {"challenge": "request-state"}

        response = client.post("/api/advanced/register/complete", json=payload)

        assert response.status_code == 400
        assert response.get_json() == {
            "error": "register failure",
            "challengeSource": "server-session",
            # This hand-made state was never stamped by /begin.
            "challengeStatus": "expired",
        }
        assert captured["state"] == session_state

        with client.session_transaction() as session_store:
            assert "advanced_state" not in session_store
            assert "advanced_rp" not in session_store


def test_advanced_register_complete_without_session_state_returns_400(monkeypatch):
    with entry_app().test_client() as client:
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
    with entry_app().test_client() as client:
        payload = _minimal_register_complete_payload()
        payload["publicKey"]["hints"] = ["security-key"]

        response = client.post("/api/advanced/register/complete", json=payload)

    assert response.status_code == 400
    assert "Authenticator attachment could not be determined" in response.get_json()["error"]


def test_advanced_register_complete_prefers_session_attachment_scope_over_tampered_request_hints(monkeypatch):
    monkeypatch.setattr(visitor_session, "ensure_id", lambda: "session-id")
    monkeypatch.setattr(
        attestation_certificates,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {}, None, [])
    )

    class _FailingServer:
        def register_complete(self, *_args, **_kwargs):
            raise ValueError("register reached")

    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FailingServer())
    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or "example.com")

    with entry_app().test_client() as client:
        with client.session_transaction() as session_store:
            session_store["advanced_state"] = {"challenge": "session-state"}
            session_store["advanced_rp"] = {"id": "example.com", "name": "Example RP"}
            session_store["advanced_register_allowed_attachments"] = ["platform"]

        payload = _minimal_register_complete_payload()
        payload["publicKey"]["hints"] = ["security-key"]
        payload["__credential_response"]["authenticatorAttachment"] = "platform"

        response = client.post("/api/advanced/register/complete", json=payload)

        assert response.status_code == 400
        assert response.get_json() == {
            "error": "register reached",
            "challengeSource": "server-session",
            "challengeStatus": "expired",
        }

        with client.session_transaction() as session_store:
            assert "advanced_register_allowed_attachments" not in session_store
