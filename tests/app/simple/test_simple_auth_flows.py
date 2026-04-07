import base64
import hashlib

import pytest


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


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


class _MatchedCredential:
    def __init__(self, credential_id: bytes):
        self.credential_id = credential_id


def test_simple_register_begin_persists_state_and_filters_algorithms(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    state = {"challenge": "register-state"}

    class _FakeServer:
        def register_begin(self, *_args, **_kwargs):
            return (
                {
                    "publicKey": {
                        "challenge": "challenge-1",
                        "pubKeyCredParams": [
                            {"type": "public-key", "alg": -257},
                            {"type": "public-key", "alg": -8},
                            {"type": "public-key", "alg": 12345},
                        ],
                    }
                },
                state,
            )

    monkeypatch.setattr(simple_module, "_SIMPLE_ALLOWED_ALGORITHMS", (-257, -7), raising=False)
    monkeypatch.setattr(simple_module, "determine_rp_id", lambda: "example.com", raising=False)
    monkeypatch.setattr(simple_module, "create_fido_server", lambda **_kwargs: _FakeServer(), raising=False)
    monkeypatch.setattr(
        simple_module,
        "_parse_client_credentials",
        lambda _raw: ([], [{"credentialId": "cred-1", "publicKey": "pk-1", "aaguid": "ag-1"}]),
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/register/begin?email=user@example.com",
            json={"credentials": [{"credentialId": "cred-1"}]},
        )

        assert response.status_code == 200
        payload = response.get_json()
        assert payload["publicKey"]["pubKeyCredParams"] == [
            {"type": "public-key", "alg": -257},
            {"type": "public-key", "alg": -7},
        ]
        assert payload["__session_state"] == state

        with client.session_transaction() as session_state:
            assert session_state["state"] == state
            assert session_state["register_rp_id"] == "example.com"
            assert session_state["simple_credentials"] == [
                {"credentialId": "cred-1", "publicKey": "pk-1", "aaguid": "ag-1"}
            ]
            assert "simple_register_public_key" in session_state


def test_simple_authenticate_begin_requires_valid_credentials(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(simple_module, "_parse_client_credentials", lambda _raw: ([], []), raising=False)

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/authenticate/begin?email=user@example.com",
            json={"credentials": []},
        )

    assert response.status_code == 404


def test_simple_authenticate_complete_success_returns_sign_count(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    credential_id = b"simple-auth-success"
    auth_data_bytes = b"\x00" * 32 + b"\x01" + (7).to_bytes(4, "big")
    auth_data_b64 = base64.b64encode(auth_data_bytes).decode("ascii").rstrip("=")

    class _FakeServer:
        def authenticate_complete(self, *_args, **_kwargs):
            return _MatchedCredential(credential_id)

    monkeypatch.setattr(simple_module, "create_fido_server", lambda **_kwargs: _FakeServer(), raising=False)
    monkeypatch.setattr(
        simple_module,
        "_parse_client_credentials",
        lambda _raw: ([object()], [{"credentialId": _b64url(credential_id)}]),
        raising=False,
    )

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["simple_credentials"] = [{"credentialId": _b64url(credential_id)}]
            session_state["state"] = {"challenge": "auth-state"}
            session_state["authenticate_rp_id"] = "example.com"
            session_state["simple_credentials_email"] = "user@example.com"

        response = client.post(
            "/api/authenticate/complete?email=user@example.com",
            json={
                "rawId": _b64url(credential_id),
                "response": {"authenticatorData": auth_data_b64},
            },
        )

        assert response.status_code == 200
        payload = response.get_json()
        assert payload == {
            "status": "OK",
            "hintsUsed": [],
            "authenticatedCredentialId": _b64url(credential_id),
            "signCount": 7,
        }

        with client.session_transaction() as session_state:
            assert "state" not in session_state
            assert "authenticate_rp_id" not in session_state
            assert "simple_credentials_email" not in session_state


def test_simple_authenticate_complete_uses_request_state_fallback(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    credential_id = b"simple-auth-fallback"
    captured = {}

    class _FakeServer:
        def authenticate_complete(self, state, *_args, **_kwargs):
            captured["state"] = state
            return _MatchedCredential(credential_id)

    monkeypatch.setattr(simple_module, "create_fido_server", lambda **_kwargs: _FakeServer(), raising=False)
    monkeypatch.setattr(
        simple_module,
        "_parse_client_credentials",
        lambda _raw: ([object()], [{"credentialId": _b64url(credential_id)}]),
        raising=False,
    )

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["simple_credentials"] = [{"credentialId": _b64url(credential_id)}]
            session_state["authenticate_rp_id"] = "example.com"

        response = client.post(
            "/api/authenticate/complete?email=user@example.com",
            json={
                "rawId": _b64url(credential_id),
                "response": {"authenticatorData": "AQID"},
                "__session_state": {"challenge": "fallback-state"},
            },
        )

        assert response.status_code == 200
        assert captured["state"] == {"challenge": "fallback-state"}


def test_simple_authenticate_complete_missing_state_returns_400(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(
        simple_module,
        "_parse_client_credentials",
        lambda _raw: ([object()], [{"credentialId": "cred-1"}]),
        raising=False,
    )

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["simple_credentials"] = [{"credentialId": "cred-1"}]
            session_state["authenticate_rp_id"] = "example.com"
            session_state["simple_credentials_email"] = "user@example.com"

        response = client.post(
            "/api/authenticate/complete?email=user@example.com",
            json={"rawId": "cred-1", "response": {}},
        )

        assert response.status_code == 400
        assert "Authentication state not found or has expired" in response.get_json()["error"]

        with client.session_transaction() as session_state:
            assert "authenticate_rp_id" not in session_state
            assert session_state.get("simple_credentials_email") == "user@example.com"


def test_simple_register_complete_accepts_request_state_fallback_and_persists(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

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

    monkeypatch.setattr(simple_module, "determine_rp_id", lambda: rp_id, raising=False)
    monkeypatch.setattr(simple_module, "create_fido_server", lambda **_kwargs: _FakeServer(), raising=False)
    monkeypatch.setattr(
        simple_module,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {}, None, []),
        raising=False,
    )
    monkeypatch.setattr(simple_module, "perform_attestation_checks", lambda *args, **kwargs: {
        "signature_valid": True,
        "root_valid": True,
        "rp_id_hash_valid": True,
        "aaguid_match": True,
        "warnings": [],
    }, raising=False)
    monkeypatch.setattr(simple_module, "extract_min_pin_length", lambda _ext: None, raising=False)
    monkeypatch.setattr(simple_module, "add_public_key_material", lambda *_args, **_kwargs: None, raising=False)
    monkeypatch.setattr(simple_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(simple_module, "readkey", lambda *_args, **_kwargs: [], raising=False)

    def _fake_savekey(email, credentials, *, session_id=None):
        saved["email"] = email
        saved["credentials"] = credentials
        saved["session_id"] = session_id

    monkeypatch.setattr(simple_module, "savekey", _fake_savekey, raising=False)
    monkeypatch.setattr(simple_module, "record_registration_event", lambda _event: None, raising=False)

    request_state = {"challenge": "fallback-register-state"}

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["register_rp_id"] = rp_id
            session_state["simple_register_public_key"] = {"challenge": "ignored"}

        response = client.post(
            "/api/register/complete?email=user@example.com",
            json={
                "__session_state": request_state,
                "rawId": _b64url(credential_id),
                "authenticatorAttachment": "cross-platform",
                "response": {
                    "attestationObject": _b64url(b"attestation"),
                    "clientDataJSON": _b64url(b"client-data"),
                },
            },
        )

        assert response.status_code == 200
        payload = response.get_json()
        assert payload["status"] == "OK"
        assert payload["storedCredential"]["credentialIdBase64Url"] == _b64url(credential_id)
        assert captured["state"] == request_state
        assert saved["email"] == "user@example.com"
        assert saved["session_id"] == "session-id"
        assert isinstance(saved["credentials"], list)
        assert len(saved["credentials"]) == 1

        with client.session_transaction() as session_state:
            assert "state" not in session_state
            assert "register_rp_id" not in session_state
