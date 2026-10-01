import base64
import hashlib

from server.app.config import relying_party
from server.app.webauthn.attestation import certificates as attestation_certificates
from tests.app.entry_app import entry_app


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class _BadBytes:
    def __bytes__(self):
        raise TypeError("not-bytes")


class _RegisterCredentialData:
    def __init__(self, credential_id: bytes):
        self.credential_id = credential_id
        self.public_key = {1: 2, 3: -257, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32}
        self.aaguid = _BadBytes()


class _RegisterAuthData:
    class FLAG:
        UP = 0x01
        UV = 0x04
        BE = 0x08
        BS = 0x10
        AT = 0x40
        ED = 0x80

    def __init__(self, credential_data: _RegisterCredentialData, rp_id: str):
        self.credential_data = credential_data
        self.rp_id_hash = bytearray(hashlib.sha256(rp_id.encode("utf-8")).digest())
        self.flags = self.FLAG.UP | self.FLAG.AT
        self.counter = 17

    def __bytes__(self):
        raise RuntimeError("auth-data-bytes-unavailable")


class _RegisterServer:
    def __init__(self, auth_data):
        self._auth_data = auth_data

    def register_complete(self, *_args, **_kwargs):
        return self._auth_data


class _AuthDataMapping(dict):
    def __bytes__(self):
        return b"\x01\x02\x03"


class _ObjectCredentialData:
    def __init__(self, credential_id: bytes):
        self.credential_id = credential_id
        self.public_key = {1: 2, 3: -8, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32}
        self.aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")


class _ObjectAuthData:
    class FLAG:
        UP = 0x01
        UV = 0x04
        BE = 0x08
        BS = 0x10
        AT = 0x40
        ED = 0x80

    def __init__(self, *, counter: int):
        self.flags = self.FLAG.UP | self.FLAG.AT
        self.counter = counter


def test_simple_register_begin_clears_cached_session_fields_when_client_credentials_are_empty(monkeypatch, config_module, simple_parsing):
    class _FakeServer:
        def register_begin(self, *_args, **_kwargs):
            return {"publicKey": "not-a-mapping"}, {"challenge": "simple-register-state"}

    monkeypatch.setattr(relying_party, "determine_rp_id", lambda: "example.com")
    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())
    monkeypatch.setattr(simple_parsing, "_parse_client_credentials", lambda _raw: ([], []))

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["simple_credentials"] = [{"credentialId": "stale"}]
            session_state["simple_register_public_key"] = {"challenge": "stale"}

        response = client.post(
            "/api/register/begin?email=user@example.com",
            json={"credentials": []},
        )

        assert response.status_code == 200
        # The ceremony state stays server-side and is never echoed back.
        assert "__session_state" not in response.get_json()

        with client.session_transaction() as session_state:
            assert session_state["state"]["challenge"] == "simple-register-state"
            assert isinstance(session_state["state"]["issued_at"], float)

        with client.session_transaction() as session_state:
            assert "simple_credentials" not in session_state
            assert "simple_register_public_key" not in session_state


def test_simple_register_complete_non_mapping_payload_returns_state_expired_error(monkeypatch, attestation_module):
    monkeypatch.setattr(
        attestation_certificates,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {}, None, [])
    )

    with entry_app().test_client() as client:
        response = client.post(
            "/api/register/complete?email=user@example.com",
            json=["not", "a", "mapping"],
        )

    assert response.status_code == 400
    assert "Registration state not found or has expired" in response.get_json()["error"]
