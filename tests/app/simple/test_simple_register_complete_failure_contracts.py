import time

from server.app.config import relying_party
from server.app.webauthn.attestation import certificates as attestation_certificates
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import b64u


def _register_complete_payload(*, state=None):
    payload = {
        "rawId": b64u(b"simple-register-failure"),
        "response": {
            "attestationObject": b64u(b"attestation"),
            "clientDataJSON": b64u(b"client-data"),
        },
    }
    if state is not None:
        payload["__session_state"] = state
    return payload


def test_simple_register_complete_returns_400_and_cleans_state_when_verification_fails(monkeypatch):
    class _FailingServer:
        def register_complete(self, *_args, **_kwargs):
            raise ValueError("register verification failed")

    monkeypatch.setattr(relying_party, "determine_rp_id", lambda: "example.com")
    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FailingServer())
    monkeypatch.setattr(
        attestation_certificates,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {}, None, [])
    )

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["state"] = {"challenge": "session-state", "issued_at": time.time()}
            session_state["register_rp_id"] = "example.com"
            session_state["simple_register_public_key"] = {"challenge": "saved"}

        response = client.post(
            "/api/register/complete?email=user@example.com",
            json=_register_complete_payload(),
        )

        assert response.status_code == 400
        assert response.get_json() == {"error": "register verification failed"}

        with client.session_transaction() as session_state:
            assert "state" not in session_state
            assert "register_rp_id" not in session_state
            assert "simple_register_public_key" not in session_state


def test_simple_register_complete_rejects_request_state_fallback_before_verification(monkeypatch):
    """The request-supplied state must be discarded before any verification."""

    captured = {}

    class _FailingServer:
        def register_complete(self, state, *_args, **_kwargs):
            captured["state"] = state
            raise ValueError("fallback verification failed")

    monkeypatch.setattr(relying_party, "determine_rp_id", lambda: "example.com")
    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FailingServer())
    monkeypatch.setattr(
        attestation_certificates,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {}, None, [])
    )

    fallback_state = {"challenge": "request-fallback-state"}

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["register_rp_id"] = "example.com"

        response = client.post(
            "/api/register/complete?email=user@example.com",
            json=_register_complete_payload(state=fallback_state),
        )

        assert response.status_code == 400
        # Rejected for a missing session state, NOT by the verifier: the
        # client-supplied challenge never reaches register_complete at all.
        assert "state" in response.get_json()["error"].lower()
        assert "state" not in captured

        with client.session_transaction() as session_state:
            assert "register_rp_id" not in session_state
