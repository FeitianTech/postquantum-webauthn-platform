import base64

import pytest


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _sample_public_key() -> dict:
    return {
        1: 2,
        3: -7,
        -1: 1,
        -2: b"\x01" * 32,
        -3: b"\x02" * 32,
    }


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

    def __init__(self, *, flags: int, counter: int, raw: bytes):
        self.flags = flags
        self.counter = counter
        self._raw = raw

    def __bytes__(self):
        return self._raw


def test_credentials_get_serializes_dict_backed_entries(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(simple_module, "ensure_metadata_session_id", lambda: "session-dict", raising=False)

    def _add_public_key_material(target, public_key):
        if isinstance(public_key, dict) and 3 in public_key:
            target.setdefault("publicKeyAlgorithm", public_key[3])

    def _augment_aaguid_fields(target):
        if target.get("aaguid"):
            target.setdefault("aaguidHex", target["aaguid"])
            target.setdefault("aaguidGuid", "00000000-0000-0000-0000-000000000000")

    monkeypatch.setattr(simple_module, "add_public_key_material", _add_public_key_material, raising=False)
    monkeypatch.setattr(simple_module, "augment_aaguid_fields", _augment_aaguid_fields, raising=False)

    dict_backed = {
        "credential_data": {
            "credential_id": b"cred-dict",
            "public_key": {3: -7},
            "aaguid": bytes.fromhex("00112233445566778899aabbccddeeff"),
        },
        "auth_data": {"counter": 9, "flags": {"be": True}},
        "user_info": {
            "name": "dict@example.com",
            "display_name": "Dict User",
            "user_handle": b"dict-user",
        },
        "registration_time": 1700000000.0,
        "client_extension_outputs": {"largeBlob": {"supported": True}},
        "attestation_format": "packed",
        "attestation_statement": {"sig": b"\x01"},
        "attestation_object": "raw-attestation-string",
        "attestation_object_decoded": {"fmt": "packed"},
        "attestation_certificate": {"subject": "CN=Device"},
        "attestation_certificates": [{"subject": "CN=Intermediate"}],
        "registration_response": {"id": "response-id"},
        "relying_party": {"id": "example.com", "registrationData": {"counter": 9}},
        "client_data_json": {"type": "webauthn.create"},
        "authenticator_data_raw": "raw-auth-data",
        "authenticator_data_hex": "aabbcc",
        "authenticator_attachment": "platform",
        "properties": {"label": "dict-backed"},
    }

    monkeypatch.setattr(
        simple_module,
        "iter_credentials",
        lambda session_id=None: iter([("dict@example.com", [dict_backed])]),
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.get("/api/credentials")

    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload) == 1

    entry = payload[0]
    assert entry["email"] == "dict@example.com"
    assert entry["userName"] == "dict@example.com"
    assert entry["displayName"] == "Dict User"
    assert entry["credentialId"] == base64.b64encode(b"cred-dict").decode("utf-8")
    assert entry["signCount"] == 9
    assert entry["algorithm"] == -7
    assert entry["publicKeyAlgorithm"] == -7
    assert entry["attestationObjectRaw"] == "raw-attestation-string"
    assert entry["attestationObjectDecoded"] == {"fmt": "packed"}
    assert entry["registrationResponse"] == {"id": "response-id"}
    assert entry["relyingParty"] == {"id": "example.com", "registrationData": {"counter": 9}}
    assert entry["clientDataJSON"] == {"type": "webauthn.create"}
    assert entry["authenticatorDataRaw"] == "raw-auth-data"
    assert entry["authenticatorDataHex"] == "aabbcc"
    assert entry["authenticatorAttachment"] == "platform"
    assert entry["residentKey"] is True
    assert entry["largeBlob"] is True
    assert entry["properties"]["authenticatorAttachment"] == "platform"


def test_credentials_get_serializes_object_backed_entries_and_derives_authenticator_data(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(simple_module, "ensure_metadata_session_id", lambda: "session-object", raising=False)

    def _add_public_key_material(target, public_key):
        if isinstance(public_key, dict) and 3 in public_key:
            target.setdefault("publicKeyAlgorithm", public_key[3])

    def _augment_aaguid_fields(target):
        if target.get("aaguid"):
            target.setdefault("aaguidHex", target["aaguid"])
            target.setdefault("aaguidGuid", "11111111-1111-1111-1111-111111111111")

    monkeypatch.setattr(simple_module, "add_public_key_material", _add_public_key_material, raising=False)
    monkeypatch.setattr(simple_module, "augment_aaguid_fields", _augment_aaguid_fields, raising=False)

    credential_data = _FakeCredentialData(
        credential_id=b"cred-object",
        public_key={1: 2, 3: -8, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32},
        aaguid=bytes.fromhex("00112233445566778899aabbccddeeff"),
    )
    auth_data = _FakeAuthData(
        flags=(
            _FakeAuthData.FLAG.UP
            | _FakeAuthData.FLAG.UV
            | _FakeAuthData.FLAG.AT
            | _FakeAuthData.FLAG.BE
        ),
        counter=12,
        raw=b"\x01\x02\x03\x04",
    )

    object_backed = {
        "credential_data": credential_data,
        "auth_data": auth_data,
        "user_info": {
            "name": "object@example.com",
            "display_name": "Object User",
            "user_handle": b"object-user",
        },
        "registration_time": 1700000001.0,
        "client_extension_outputs": {"credProps": {"rk": True}},
        "attestation_format": "none",
        "attestation_statement": {},
        "request_params": {"resident_key": "required"},
        "properties": {"label": "object-backed"},
    }

    monkeypatch.setattr(
        simple_module,
        "iter_credentials",
        lambda session_id=None: iter([("object@example.com", [object_backed])]),
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.get("/api/credentials")

    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload) == 1

    entry = payload[0]
    assert entry["email"] == "object@example.com"
    assert entry["credentialId"] == base64.b64encode(b"cred-object").decode("utf-8")
    assert entry["algorithm"] == -8
    assert entry["publicKeyAlgorithm"] == -8
    assert entry["signCount"] == 12
    assert entry["flags"]["up"] is True
    assert entry["flags"]["uv"] is True
    assert entry["flags"]["at"] is True
    assert entry["flags"]["be"] is True
    assert entry["residentKey"] is True
    assert "authenticatorDataRaw" not in entry
    assert "authenticatorDataHex" not in entry


def test_credentials_get_handles_bare_credential_objects_and_skips_malformed(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(simple_module, "ensure_metadata_session_id", lambda: "session-bare", raising=False)

    def _add_public_key_material(target, public_key):
        if isinstance(public_key, dict) and 3 in public_key:
            target.setdefault("publicKeyAlgorithm", public_key[3])

    def _augment_aaguid_fields(target):
        if target.get("aaguid"):
            target.setdefault("aaguidHex", target["aaguid"])

    monkeypatch.setattr(simple_module, "add_public_key_material", _add_public_key_material, raising=False)
    monkeypatch.setattr(simple_module, "augment_aaguid_fields", _augment_aaguid_fields, raising=False)

    class _BareCredential:
        def __init__(self):
            self.credential_id = b"bare-credential"
            self.public_key = _sample_public_key()
            self.aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")

    bare = _BareCredential()

    monkeypatch.setattr(
        simple_module,
        "iter_credentials",
        lambda session_id=None: iter([("bare@example.com", [object(), bare])]),
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.get("/api/credentials")

    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload) == 1

    entry = payload[0]
    assert entry["email"] == "bare@example.com"
    assert entry["credentialId"] == base64.b64encode(b"bare-credential").decode("utf-8")
    assert entry["type"] == "WebAuthn"
    assert entry["signCount"] == 0
    assert entry["algorithm"] == -7


def test_credentials_get_returns_empty_list_when_storage_iteration_fails(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(simple_module, "ensure_metadata_session_id", lambda: "session-fail", raising=False)

    def _raise_iter_failure(*_args, **_kwargs):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr(simple_module, "iter_credentials", _raise_iter_failure, raising=False)

    with config_module.app.test_client() as client:
        response = client.get("/api/credentials")

    assert response.status_code == 200
    assert response.get_json() == []


def test_credentials_delete_removes_all_usernames_and_reports_count(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(simple_module, "ensure_metadata_session_id", lambda: "session-delete", raising=False)
    monkeypatch.setattr(
        simple_module,
        "storage_list_credentials",
        lambda session_id=None: {"alice@example.com": [], "bob@example.com": []},
        raising=False,
    )

    observed = []

    def _delkey(username, *, session_id=None):
        observed.append((username, session_id))

    monkeypatch.setattr(simple_module, "delkey", _delkey, raising=False)

    with config_module.app.test_client() as client:
        response = client.delete("/api/credentials")

    assert response.status_code == 200
    assert response.get_json() == {"status": "OK", "removed": 2}
    assert observed == [
        ("alice@example.com", "session-delete"),
        ("bob@example.com", "session-delete"),
    ]


def test_credentials_delete_returns_zero_when_listing_credentials_raises(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(simple_module, "ensure_metadata_session_id", lambda: "session-delete-fail", raising=False)

    def _raise_list_failure(*_args, **_kwargs):
        raise RuntimeError("list failed")

    monkeypatch.setattr(simple_module, "storage_list_credentials", _raise_list_failure, raising=False)

    with config_module.app.test_client() as client:
        response = client.delete("/api/credentials")

    assert response.status_code == 200
    assert response.get_json() == {"status": "OK", "removed": 0}
