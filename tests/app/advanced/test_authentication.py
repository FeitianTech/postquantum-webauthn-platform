"""Tests for the advanced authenticate complete route."""

from __future__ import annotations

import types
from types import SimpleNamespace

from server.app.config import relying_party
from server.app.routes.advanced import algorithms as advanced_algorithms
from server.app.routes.advanced import parsing as advanced_parsing
from server.app.webauthn import assertion_hash
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import Authenticator, assertion_payload, b64u
from tests.app.storage.codec_examples import _stored_credential_entry
from tests.app.storage.credential_seed import sample_public_key_bytes

from .assertion_ceremony import CHALLENGE, begin, complete


def _complete(client, body):
    return client.post("/api/advanced/authenticate/complete", json=body)


def test_a_complete_without_public_key_options_is_refused():
    response = _complete(entry_app().test_client(), {"__assertion_response": {"response": {}}})

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid request: Missing publicKey in JSON editor content"}


def test_a_verified_assertion_reports_the_credentials_algorithm_and_counter():
    authenticator = Authenticator()
    credentials = [authenticator.stored_credential_entry()]
    client = entry_app().test_client()
    begin(client, credentials)

    response = complete(client, credentials, assertion_payload(authenticator, challenge=CHALLENGE, counter=7))

    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    assert (body["status"], body["algorithm"], body["signCount"]) == ("OK", -7, 7)
    assert body["authenticatedCredentialId"] == b64u(authenticator.credential_id)


def test_a_complete_that_sends_no_credentials_finds_none_whatever_its_begin_was_sent():
    authenticator = Authenticator()
    credentials = [authenticator.stored_credential_entry()]
    client = entry_app().test_client()
    begin(client, credentials)

    response = complete(client, None, assertion_payload(authenticator, challenge=CHALLENGE, counter=7))

    assert response.status_code == 404
    assert response.get_json()["error"] == "No credentials found"


def test_a_complete_whose_sent_credentials_cannot_be_read_says_so():
    authenticator = Authenticator()
    client = entry_app().test_client()
    begin(client, [authenticator.stored_credential_entry()])

    response = complete(client, ["unparseable"], assertion_payload(authenticator, challenge=CHALLENGE, counter=7))

    assert response.status_code == 400
    assert response.get_json()["error"] == (
        "None of the saved credentials sent with this authentication could be read. "
        "Please register a credential and try again."
    )


def test_begin_gives_the_browser_the_requests_hints():
    authenticator = Authenticator(credential_id=b"\x04" * 32)

    entry = {**authenticator.stored_credential_entry(), "authenticatorAttachment": "cross-platform"}

    response = begin(entry_app().test_client(), [entry], hints=["security-key"])

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["publicKey"]["hints"] == ["security-key"]


def test_begin_names_no_hints_when_the_request_has_none():
    authenticator = Authenticator(credential_id=b"\x04" * 32)

    response = begin(entry_app().test_client(), [authenticator.stored_credential_entry()])

    assert response.status_code == 200, response.get_json()
    assert "hints" not in response.get_json()["publicKey"]


def test_begin_refuses_an_extension_value_it_cannot_read():
    authenticator = Authenticator(credential_id=b"\x04" * 32)

    response = begin(
        entry_app().test_client(),
        [authenticator.stored_credential_entry()],
        extensions={"largeBlob": {"write": "not hex"}},
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid extension value: input is not hexadecimal"}


def test_begin_refuses_a_public_key_that_is_no_object():
    response = entry_app().test_client().post("/api/advanced/authenticate/begin", json={"publicKey": ["challenge"]})

    assert response.status_code == 400
    assert response.get_json() == {"error": "publicKey must be an object."}


def test_advanced_authenticate_complete_without_session_state_returns_400(monkeypatch):
    credential_id = b"advanced-invalid-fallback"
    encoded_id = b64u(credential_id)

    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: [{"id": credential_id, "data": object(), "attachment": None, "algorithm": -7, "resident": True}]
    )

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "__session_state": "invalid",
                "__storedCredentials": [{}],
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": encoded_id}],
                },
                "__assertion_response": {
                    "rawId": encoded_id,
                    "response": {},
                },
            },
        )

        assert response.status_code == 400
        assert "Authentication state not found or has expired" in response.get_json()["error"]

        with client.session_transaction() as session_state:
            assert "advanced_auth_rp" not in session_state


def test_advanced_authenticate_complete_requires_attachment_when_session_scopes_allowed_attachments():
    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_authenticate_allowed_attachments"] = ["platform"]

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {"challenge": "AQID"},
                "__assertion_response": {"response": {}},
            },
        )

        assert response.status_code == 400
        assert "Authenticator attachment could not be determined" in response.get_json()["error"]

        with client.session_transaction() as session_state:
            assert "advanced_authenticate_allowed_attachments" not in session_state


def test_advanced_authenticate_complete_rejects_attachment_not_allowed_by_session_scope():
    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_authenticate_allowed_attachments"] = ["platform"]

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {"challenge": "AQID"},
                "__assertion_response": {
                    "authenticatorAttachment": "cross-platform",
                    "response": {},
                },
            },
        )

        assert response.status_code == 400
        assert "Authenticator attachment is not permitted by the selected hints" in response.get_json()["error"]

        with client.session_transaction() as session_state:
            assert "advanced_authenticate_allowed_attachments" not in session_state


def test_advanced_authenticate_complete_forwards_hash_algorithm_override(monkeypatch):
    credential_id = b"advanced-hash-forward"
    encoded_id = b64u(credential_id)
    captured = {}

    class _FakeServer:
        allowed_algorithms = []

        def authenticate_complete(self, _state, _credentials, response):
            captured["response"] = response
            return SimpleNamespace(public_key={3: -7})

    def _hashed_with(response, algorithm):
        captured["hash_algorithm"] = algorithm
        return response


    monkeypatch.setattr(assertion_hash, "response_hashed_with", _hashed_with)

    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())
    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or "example.com")
    monkeypatch.setattr(advanced_algorithms, "_derive_algorithms_from_credentials", lambda _credentials: [])
    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: [{"id": credential_id, "data": object(), "attachment": None, "algorithm": -7, "resident": True}]
    )

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_state"] = {"challenge": "state"}
            session_state["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "__hash_algorithm": "SHA-512",
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": encoded_id}],
                },
                "__storedCredentials": [{}],
                "__assertion_response": {"rawId": encoded_id, "response": {}},
            },
        )

    assert response.status_code == 200
    assert captured["hash_algorithm"] == "SHA-512"


def test_advanced_authenticate_complete_defaults_hash_algorithm_when_override_invalid(monkeypatch):
    credential_id = b"advanced-hash-default"
    encoded_id = b64u(credential_id)
    captured = {}

    class _FakeServer:
        allowed_algorithms = []

        def authenticate_complete(self, _state, _credentials, response):
            captured["response"] = response
            return SimpleNamespace(public_key={3: -7})

    def _hashed_with(response, algorithm):
        captured["hash_algorithm"] = algorithm
        return response


    monkeypatch.setattr(assertion_hash, "response_hashed_with", _hashed_with)

    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())
    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or "example.com")
    monkeypatch.setattr(advanced_algorithms, "_derive_algorithms_from_credentials", lambda _credentials: [])
    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: [{"id": credential_id, "data": object(), "attachment": None, "algorithm": -7, "resident": True}]
    )

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_state"] = {"challenge": "state"}
            session_state["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "__hash_algorithm": {"invalid": True},
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": encoded_id}],
                },
                "__storedCredentials": [{}],
                "__assertion_response": {"rawId": encoded_id, "response": {}},
            },
        )

    assert response.status_code == 200
    assert captured["hash_algorithm"] == "SHA-256"


def _credential_record(credential_id: bytes, *, data=None, attachment=None, resident=False, algorithm=-7):
    return {
        "id": credential_id,
        "data": object() if data is None else data,
        "attachment": attachment,
        "algorithm": algorithm,
        "resident": resident,
    }


def _install_fake_auth_begin_server(monkeypatch, captured, *, include_allow_credentials=True):
    class _FakeServer:
        def __init__(self):
            self.allowed_algorithms = []
            self.timeout = None

        def authenticate_begin(self, credentials, *, user_verification, challenge, extensions):
            captured["credentials"] = credentials
            captured["user_verification"] = user_verification
            captured["challenge"] = challenge
            captured["extensions"] = extensions
            captured["allowed_algorithms"] = self.allowed_algorithms
            captured["timeout"] = self.timeout

            public_key = {"challenge": "AQID"}
            if include_allow_credentials:
                public_key["allowCredentials"] = [{"type": "public-key", "id": "placeholder"}]

            return {"publicKey": public_key}, {"challenge": "state-token"}

    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())
    monkeypatch.setattr(
        relying_party,
        "determine_rp_id",
        lambda value=None: value or "example.com"
    )


def test_advanced_authenticate_begin_uses_allow_credentials_subset_and_dedupes(monkeypatch):
    cred_one = b"cred-one"
    cred_two = b"cred-two"

    marker_one = object()
    marker_two = object()

    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: [
            _credential_record(cred_one, data=marker_one, attachment="platform"),
            _credential_record(cred_two, data=marker_two, attachment="cross-platform"),
        ]
    )

    captured = {}
    _install_fake_auth_begin_server(monkeypatch, captured)

    request_payload = {
        "publicKey": {
            "challenge": "010203",
            "allowCredentials": [
                {"type": "public-key", "id": cred_one.hex()},
                {"type": "public-key", "id": cred_one.hex()},
                {"type": "public-key", "id": cred_two.hex()},
                {"type": "public-key", "id": b"missing".hex()},
            ],
        },
        "__storedCredentials": [{"record": 1}],
    }

    with entry_app().test_client() as client:
        response = client.post("/api/advanced/authenticate/begin", json=request_payload)

        assert response.status_code == 200
        assert captured["credentials"] == [marker_one, marker_two]

        payload = response.get_json()
        assert "__session_state" not in payload
        assert payload["publicKey"]["allowCredentials"] == [{"type": "public-key", "id": "placeholder"}]

        with client.session_transaction() as session_state:
            assert session_state["advanced_authenticate_allowed_attachments"] == []
            assert session_state["advanced_auth_state"]["challenge"] == "state-token"
            assert isinstance(session_state["advanced_auth_state"]["issued_at"], float)
            assert session_state["advanced_auth_rp"]["id"] == "example.com"


def test_advanced_authenticate_begin_falls_back_to_all_records_when_allow_credentials_do_not_match(monkeypatch):
    marker_one = object()
    marker_two = object()

    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: [
            _credential_record(b"fallback-one", data=marker_one, attachment="platform"),
            _credential_record(b"fallback-two", data=marker_two, attachment="cross-platform"),
        ]
    )

    captured = {}
    _install_fake_auth_begin_server(monkeypatch, captured)

    with entry_app().test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/begin",
            json={
                "publicKey": {
                    "challenge": "010203",
                    "allowCredentials": [{"type": "public-key", "id": b"unknown".hex()}],
                },
                "__storedCredentials": [{"record": 1}],
            },
        )

    assert response.status_code == 200
    assert captured["credentials"] == [marker_one, marker_two]


def test_advanced_authenticate_begin_resident_mode_prefers_resident_records_and_hides_allow_credentials(monkeypatch):
    resident_marker = object()
    nonresident_marker = object()

    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: [
            _credential_record(b"resident", data=resident_marker, resident=True, attachment="platform"),
            _credential_record(
                b"nonresident",
                data=nonresident_marker,
                resident=False,
                attachment="platform",
            ),
        ]
    )

    captured = {}
    _install_fake_auth_begin_server(monkeypatch, captured, include_allow_credentials=True)

    with entry_app().test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/begin",
            json={
                "publicKey": {
                    "challenge": "010203",
                    "hints": ["client-device"],
                },
                "__storedCredentials": [{"record": 1}],
            },
        )

    assert response.status_code == 200
    assert captured["credentials"] == [resident_marker]
    payload = response.get_json()
    assert "allowCredentials" not in payload["publicKey"]


def test_advanced_authenticate_begin_propagates_algorithms_extensions_and_uv_preferences(monkeypatch):
    records = [_credential_record(b"credential-id", resident=True, attachment="platform")]

    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: records
    )

    expected_algorithms = [types.SimpleNamespace(alg=-7), types.SimpleNamespace(alg=-257)]
    monkeypatch.setattr(
        advanced_algorithms,
        "_derive_algorithms_from_credentials",
        lambda source: expected_algorithms if list(source) == [records[0]["data"]] else []
    )

    captured = {}
    _install_fake_auth_begin_server(monkeypatch, captured)

    with entry_app().test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/begin",
            json={
                "publicKey": {
                    "challenge": "010203",
                    "timeout": 15000,
                    "userVerification": "discouraged",
                    "extensions": {
                        "largeBlob": {"write": "616263"},
                        "prf": {
                            "eval": {
                                "first": "0102",
                                "second": "aabb",
                            }
                        },
                    },
                },
                "__storedCredentials": [{"record": 1}],
            },
        )

    assert response.status_code == 200
    assert captured["challenge"] == b"\x01\x02\x03"
    assert captured["timeout"] == 15000
    assert captured["allowed_algorithms"] == expected_algorithms
    assert captured["extensions"] == {
        "largeBlob": {"write": b"abc"},
        "prf": {"eval": {"first": b"\x01\x02", "second": b"\xaa\xbb"}},
    }
    assert getattr(captured["user_verification"], "value", captured["user_verification"]) == "discouraged"


def test_advanced_authenticate_begin_accepts_storedcredentials_without_dunder(monkeypatch):
    captured = {}

    class _FakeServer:
        def __init__(self):
            self.allowed_algorithms = []
            self.timeout = None

        def authenticate_begin(self, credentials, **kwargs):
            captured["credential_count"] = 0 if credentials is None else len(credentials)
            captured["challenge"] = kwargs.get("challenge")
            return {
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": "placeholder"}],
                }
            }, {"challenge": "advanced-auth-state"}

    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or "example.com")
    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())

    credential_id = b"frontend-adv-auth"
    challenge = b"frontend-auth-challenge"

    wrapped_entry = {
        "credentialId": {"$base64url": b64u(credential_id)},
        "publicKey": {"$base64url": b64u(sample_public_key_bytes())},
        "aaguid": {"$hex": "00112233445566778899aabbccddeeff"},
        "resident": True,
        "authenticatorAttachment": "platform",
        "algorithm": -7,
    }

    with entry_app().test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/begin",
            json={
                "publicKey": {"challenge": {"$base64url": b64u(challenge)}},
                "storedCredentials": [wrapped_entry],
            },
        )

        assert response.status_code == 200
        payload = response.get_json()
        assert "__session_state" not in payload
        assert "allowCredentials" not in payload["publicKey"]
        assert captured["credential_count"] == 1
        assert captured["challenge"] == challenge


def test_advanced_authenticate_begin_accepts_credentials_fallback_field(monkeypatch):
    captured = {}

    class _FakeServer:
        def __init__(self):
            self.allowed_algorithms = []
            self.timeout = None

        def authenticate_begin(self, credentials, **_kwargs):
            captured["credential_count"] = 0 if credentials is None else len(credentials)
            return {"publicKey": {"challenge": "AQID"}}, {"challenge": "advanced-auth-state"}

    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or "example.com")
    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())

    with entry_app().test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/begin",
            json={
                "publicKey": {"challenge": "010203"},
                "credentials": [_stored_credential_entry(b"advanced-auth-credentials-field")],
            },
        )

    assert response.status_code == 200
    assert captured["credential_count"] == 1


def test_advanced_authenticate_complete_accepts_storedcredentials_without_dunder(monkeypatch):
    credential_id = b"adv-complete-storedCredentials"
    encoded_credential_id = b64u(credential_id)

    class _FakeServer:
        allowed_algorithms = []

        def authenticate_complete(self, *_args, **_kwargs):
            return SimpleNamespace(public_key={3: -7})

    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or "example.com")
    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())
    monkeypatch.setattr(advanced_algorithms, "_derive_algorithms_from_credentials", lambda _credentials: [])

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_state"] = {"challenge": "state"}
            session_state["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": encoded_credential_id}],
                },
                "storedCredentials": [_stored_credential_entry(credential_id)],
                "__assertion_response": {"rawId": encoded_credential_id, "response": {}},
            },
        )

    assert response.status_code == 200
    assert response.get_json()["authenticatedCredentialId"] == encoded_credential_id


def test_advanced_authenticate_complete_accepts_credentials_fallback_field(monkeypatch):
    credential_id = b"adv-complete-credentials-field"
    encoded_credential_id = b64u(credential_id)

    class _FakeServer:
        allowed_algorithms = []

        def authenticate_complete(self, *_args, **_kwargs):
            return SimpleNamespace(public_key={3: -7})

    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or "example.com")
    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())
    monkeypatch.setattr(advanced_algorithms, "_derive_algorithms_from_credentials", lambda _credentials: [])

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_state"] = {"challenge": "state"}
            session_state["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": encoded_credential_id}],
                },
                "credentials": [_stored_credential_entry(credential_id)],
                "__assertion_response": {"rawId": encoded_credential_id, "response": {}},
            },
        )

    assert response.status_code == 200
    assert response.get_json()["authenticatedCredentialId"] == encoded_credential_id
