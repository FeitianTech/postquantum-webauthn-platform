import base64
import hashlib

import pytest


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


def test_simple_validation_helpers_cover_decode_and_assertion_id_fallbacks():
    simple_module = pytest.importorskip("server.app.routes.simple")

    assert simple_module._decode_base64url_bytes(b"\x00\x01") == b"\x00\x01"
    assert simple_module._decode_base64url_bytes("   ") == b""
    assert simple_module._decode_base64url_bytes("abc*") == b""
    assert simple_module._decode_base64url_bytes(12345) == b""

    assert simple_module._extract_assertion_credential_id({"rawId": b"\x10\x11"}) == b"\x10\x11"
    assert simple_module._extract_assertion_credential_id({"rawId": "abc*"}) is None
    assert simple_module._extract_assertion_credential_id({"id": 12345}) is None


def test_simple_register_begin_clears_cached_session_fields_when_client_credentials_are_empty(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    class _FakeServer:
        def register_begin(self, *_args, **_kwargs):
            return {"publicKey": "not-a-mapping"}, {"challenge": "simple-register-state"}

    monkeypatch.setattr(simple_module, "determine_rp_id", lambda: "example.com", raising=False)
    monkeypatch.setattr(simple_module, "create_fido_server", lambda **_kwargs: _FakeServer(), raising=False)
    monkeypatch.setattr(simple_module, "_parse_client_credentials", lambda _raw: ([], []), raising=False)

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["simple_credentials"] = [{"credentialId": "stale"}]
            session_state["simple_register_public_key"] = {"challenge": "stale"}

        response = client.post(
            "/api/register/begin?email=user@example.com",
            json={"credentials": []},
        )

        assert response.status_code == 200
        assert response.get_json()["__session_state"] == {"challenge": "simple-register-state"}

        with client.session_transaction() as session_state:
            assert "simple_credentials" not in session_state
            assert "simple_register_public_key" not in session_state


def test_simple_register_complete_non_mapping_payload_returns_state_expired_error(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(
        simple_module,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {}, None, []),
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/register/complete?email=user@example.com",
            json=["not", "a", "mapping"],
        )

    assert response.status_code == 400
    assert "Registration state not found or has expired" in response.get_json()["error"]


def test_simple_authenticate_complete_aborts_when_session_credentials_cannot_be_rebuilt(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(simple_module, "_parse_client_credentials", lambda _raw: ([], []), raising=False)

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["simple_credentials"] = [{"credentialId": "stale"}]
            session_state["state"] = {"challenge": "auth-state"}
            session_state["authenticate_rp_id"] = "example.com"

        response = client.post(
            "/api/authenticate/complete?email=user@example.com",
            json={"rawId": "stale", "response": {}},
        )

    assert response.status_code == 400


def test_simple_register_complete_covers_warning_metadata_transport_and_session_fallback_paths(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    rp_id = "example.com"
    credential_id = b"branch-focus-register"
    auth_data = _RegisterAuthData(_RegisterCredentialData(credential_id), rp_id)

    saved = {}
    events = []

    monkeypatch.setattr(simple_module, "determine_rp_id", lambda: rp_id, raising=False)
    monkeypatch.setattr(
        simple_module,
        "create_fido_server",
        lambda **_kwargs: _RegisterServer(auth_data),
        raising=False,
    )
    monkeypatch.setattr(
        simple_module,
        "extract_attestation_details",
        lambda _response: (
            "packed",
            {"sig": b"\x01"},
            {"fmt": "packed"},
            {"type": "webauthn.create"},
            {"largeBlob": "written"},
            {"subject": "CN=Leaf"},
            [{"subject": "CN=Intermediate"}],
        ),
        raising=False,
    )
    monkeypatch.setattr(simple_module, "extract_min_pin_length", lambda _results: 6, raising=False)
    monkeypatch.setattr(
        simple_module,
        "perform_attestation_checks",
        lambda *_args, **_kwargs: {
            "signature_valid": False,
            "root_valid": True,
            "rp_id_hash_valid": None,
            "aaguid_match": None,
            "metadata": {"description": "FocusKey Device"},
            "warnings": ["  keep me  ", "", {"code": "W1"}, None],
        },
        raising=False,
    )
    monkeypatch.setattr(simple_module, "add_public_key_material", lambda *_args, **_kwargs: None, raising=False)
    monkeypatch.setattr(simple_module, "ensure_metadata_session_id", lambda: "meta-session", raising=False)
    monkeypatch.setattr(simple_module, "readkey", lambda *_args, **_kwargs: {"not": "a-list"}, raising=False)

    def _savekey(email, credentials, *, session_id=None):
        saved["email"] = email
        saved["credentials"] = credentials
        saved["session_id"] = session_id

    monkeypatch.setattr(simple_module, "savekey", _savekey, raising=False)
    monkeypatch.setattr(simple_module, "record_registration_event", lambda event: events.append(event), raising=False)

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["state"] = {"challenge": "register-state"}
            session_state["register_rp_id"] = rp_id
            session_state["simple_register_public_key"] = {"challenge": "AQID"}
            session_state["simple_credentials"] = [
                "discard-me",
                {"credentialId": "kept", "aaguid": "x", "publicKey": "y", "type": "simple"},
            ]

        response = client.post(
            "/api/register/complete?email=user@example.com",
            json={
                "rawId": _b64url(credential_id),
                "authenticatorAttachment": "  PLATFORM ",
                "transports": ["usb", 123, "nfc"],
                "response": {
                    "attestationObject": _b64url(b"attestation"),
                    "clientDataJSON": _b64url(b"client-data"),
                },
            },
        )

        assert response.status_code == 200
        payload = response.get_json()
        assert payload["status"] == "OK"
        assert payload["algo"] == "RS256 (RSA)"
        assert payload["warnings"] == ["keep me"]
        assert payload["storedCredential"]["authenticatorAttachment"] == "platform"
        assert payload["storedCredential"]["properties"]["minPinLength"] == 6
        assert payload["storedCredential"]["properties"]["attestationWarnings"] == ["keep me"]
        assert payload["storedCredential"]["properties"]["attestationCertificates"] == [
            {"subject": "CN=Intermediate"}
        ]
        assert payload["relyingParty"]["registrationData"]["warnings"] == ["keep me"]

        with client.session_transaction() as session_state:
            assert "state" not in session_state
            assert "register_rp_id" not in session_state
            assert len(session_state["simple_credentials"]) == 2
            assert all(isinstance(entry, dict) for entry in session_state["simple_credentials"])

    assert saved["email"] == "user@example.com"
    assert saved["session_id"] == "meta-session"
    assert isinstance(saved["credentials"], list)
    assert len(saved["credentials"]) == 1

    assert len(events) == 1
    event = events[0]
    assert list(event.transports) == ["usb", "nfc"]
    assert event.device_name_mds == "FocusKey Device"


def test_simple_credentials_route_covers_scalar_registration_metadata_and_listing_fallbacks(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(simple_module, "ensure_metadata_session_id", lambda: "meta-list", raising=False)

    def _add_public_key_material(target, public_key):
        if isinstance(public_key, dict) and 3 in public_key:
            target.setdefault("publicKeyAlgorithm", public_key[3])

    def _augment_aaguid_fields(target):
        if target.get("aaguid"):
            target.setdefault("aaguidHex", target["aaguid"])

    monkeypatch.setattr(simple_module, "add_public_key_material", _add_public_key_material, raising=False)
    monkeypatch.setattr(simple_module, "augment_aaguid_fields", _augment_aaguid_fields, raising=False)

    dict_backed = {
        "credential_data": {
            "credential_id": b"dict-fallback-cred",
            "public_key": {3: -7},
            "aaguid": bytes.fromhex("00112233445566778899aabbccddeeff"),
        },
        "auth_data": _AuthDataMapping(counter=5, flags={"be": False}),
        "user_info": {
            "name": "mixed@example.com",
            "display_name": "Mixed User",
            "user_handle": b"mixed-user",
        },
        "registration_time": 1700000100.0,
        "client_extension_outputs": {},
        "attestation_format": "none",
        "attestation_statement": {},
        "attestation_object": {"fmt": "packed"},
        "registration_response": "opaque-registration-response",
        "relying_party": "opaque-relying-party",
        "client_data_json": "opaque-client-data",
        "properties": {"authenticator_attachment": "  PLATFORM "},
    }

    object_backed = {
        "credential_data": _ObjectCredentialData(b"object-fallback-cred"),
        "auth_data": _ObjectAuthData(counter=9),
        "user_info": {
            "name": "mixed@example.com",
            "display_name": "Object User",
            "user_handle": b"object-user",
        },
        "registration_time": 1700000200.0,
        "client_extension_outputs": {"credProps": {"rk": True}},
        "attestation_format": "packed",
        "attestation_statement": {},
        "attestation_certificate": {"subject": "CN=ObjectCert"},
        "authenticator_attachment": "  HYBRID ",
        "properties": {},
    }

    monkeypatch.setattr(
        simple_module,
        "iter_credentials",
        lambda session_id=None: iter(
            [
                ("broken@example.com", None),
                ("mixed@example.com", [dict_backed, object_backed]),
            ]
        ),
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.get("/api/credentials")

    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload) == 2

    dict_id = base64.b64encode(b"dict-fallback-cred").decode("utf-8")
    object_id = base64.b64encode(b"object-fallback-cred").decode("utf-8")

    dict_entry = next(item for item in payload if item["credentialId"] == dict_id)
    assert dict_entry["registrationResponse"] == "opaque-registration-response"
    assert dict_entry["relyingParty"] == "opaque-relying-party"
    assert dict_entry["clientDataJSON"] == "opaque-client-data"
    assert dict_entry["attestationObjectDecoded"] == {"fmt": "packed"}
    assert dict_entry["authenticatorDataRaw"] == "AQID"
    assert dict_entry["authenticatorDataHex"] == "010203"
    assert dict_entry["properties"]["authenticatorAttachment"] == "platform"

    object_entry = next(item for item in payload if item["credentialId"] == object_id)
    assert object_entry["attestationCertificate"] == {"subject": "CN=ObjectCert"}
    assert object_entry["properties"]["authenticatorAttachment"] == "hybrid"
