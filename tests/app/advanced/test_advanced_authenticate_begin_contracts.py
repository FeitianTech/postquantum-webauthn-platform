import types

import pytest


def _credential_record(
    credential_id: bytes,
    *,
    data=None,
    attachment=None,
    resident=False,
    algorithm=-7,
):
    return {
        "id": credential_id,
        "data": object() if data is None else data,
        "attachment": attachment,
        "algorithm": algorithm,
        "resident": resident,
    }


def _serialized_record(*, resident=False):
    return {
        "credentialId": "credential",
        "publicKey": "public-key",
        "resident": resident,
    }


def _install_fake_auth_begin_server(monkeypatch, advanced_module, captured, *, include_allow_credentials=True):
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

    monkeypatch.setattr(
        advanced_module,
        "create_fido_server",
        lambda **_kwargs: _FakeServer(),
        raising=False,
    )
    monkeypatch.setattr(
        advanced_module,
        "determine_rp_id",
        lambda value=None: value or "example.com",
        raising=False,
    )


def test_advanced_authenticate_begin_requires_public_key_payload():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/authenticate/begin", json={})

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "Invalid request: Missing publicKey in CredentialRequestOptions"
    }


def test_advanced_authenticate_begin_requires_challenge():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/begin",
            json={"publicKey": {"timeout": 90000}},
        )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Missing required field: challenge"}


def test_advanced_authenticate_begin_rejects_invalid_challenge_format():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/begin",
            json={"publicKey": {"challenge": "g$"}},
        )

    assert response.status_code == 400
    assert "Invalid challenge format" in response.get_json()["error"]


def test_advanced_authenticate_begin_returns_404_when_no_credentials_detected():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/begin",
            json={"publicKey": {"challenge": "0102"}},
        )

    assert response.status_code == 404
    assert response.get_json() == {
        "error": "No credentials detected. Please register a credential first."
    }


def test_advanced_authenticate_begin_uses_allow_credentials_subset_and_dedupes(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    cred_one = b"cred-one"
    cred_two = b"cred-two"

    marker_one = object()
    marker_two = object()

    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [
                _credential_record(cred_one, data=marker_one, attachment="platform"),
                _credential_record(cred_two, data=marker_two, attachment="cross-platform"),
            ],
            [_serialized_record(resident=True), _serialized_record(resident=False)],
        ),
        raising=False,
    )

    captured = {}
    _install_fake_auth_begin_server(monkeypatch, advanced_module, captured)

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

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/authenticate/begin", json=request_payload)

        assert response.status_code == 200
        assert captured["credentials"] == [marker_one, marker_two]

        payload = response.get_json()
        assert payload["__session_state"] == {"challenge": "state-token"}
        assert payload["publicKey"]["allowCredentials"] == [{"type": "public-key", "id": "placeholder"}]

        with client.session_transaction() as session_state:
            assert session_state["advanced_auth_credentials_meta"] == {
                "count": 2,
                "resident_count": 1,
            }
            assert session_state["advanced_authenticate_allowed_attachments"] == []
            assert session_state["advanced_auth_state"] == {"challenge": "state-token"}
            assert session_state["advanced_auth_rp"]["id"] == "example.com"


def test_advanced_authenticate_begin_falls_back_to_all_records_when_allow_credentials_do_not_match(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    marker_one = object()
    marker_two = object()

    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [
                _credential_record(b"fallback-one", data=marker_one, attachment="platform"),
                _credential_record(b"fallback-two", data=marker_two, attachment="cross-platform"),
            ],
            [_serialized_record(resident=False), _serialized_record(resident=False)],
        ),
        raising=False,
    )

    captured = {}
    _install_fake_auth_begin_server(monkeypatch, advanced_module, captured)

    with config_module.app.test_client() as client:
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


def test_advanced_authenticate_begin_returns_hints_error_when_filtered_allow_credentials_empty(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    cred_id = b"platform-only-credential"

    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [_credential_record(cred_id, attachment="platform", resident=True)],
            [_serialized_record(resident=True)],
        ),
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/begin",
            json={
                "publicKey": {
                    "challenge": "010203",
                    "hints": ["security-key"],
                    "allowCredentials": [{"type": "public-key", "id": cred_id.hex()}],
                },
                "__storedCredentials": [{"record": 1}],
            },
        )

    assert response.status_code == 404
    assert "No credentials matched the selected hints" in response.get_json()["error"]


def test_advanced_authenticate_begin_resident_mode_prefers_resident_records_and_hides_allow_credentials(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    resident_marker = object()
    nonresident_marker = object()

    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [
                _credential_record(b"resident", data=resident_marker, resident=True, attachment="platform"),
                _credential_record(
                    b"nonresident",
                    data=nonresident_marker,
                    resident=False,
                    attachment="platform",
                ),
            ],
            [_serialized_record(resident=True), _serialized_record(resident=False)],
        ),
        raising=False,
    )

    captured = {}
    _install_fake_auth_begin_server(monkeypatch, advanced_module, captured, include_allow_credentials=True)

    with config_module.app.test_client() as client:
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


def test_advanced_authenticate_begin_resident_mode_returns_hints_error_when_resident_candidates_filtered(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [
                _credential_record(
                    b"resident-platform",
                    resident=True,
                    attachment="platform",
                ),
                _credential_record(
                    b"nonresident-cross-platform",
                    resident=False,
                    attachment="cross-platform",
                ),
            ],
            [_serialized_record(resident=True), _serialized_record(resident=False)],
        ),
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/begin",
            json={
                "publicKey": {
                    "challenge": "010203",
                    "hints": ["security-key"],
                },
                "__storedCredentials": [{"record": 1}],
            },
        )

    assert response.status_code == 404
    assert "No resident key credentials matched the selected hints" in response.get_json()["error"]


def test_advanced_authenticate_begin_propagates_algorithms_extensions_and_uv_preferences(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    records = [_credential_record(b"credential-id", resident=True, attachment="platform")]
    serialized = [_serialized_record(resident=True)]

    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (records, serialized),
        raising=False,
    )

    expected_algorithms = [types.SimpleNamespace(alg=-7), types.SimpleNamespace(alg=-257)]
    monkeypatch.setattr(
        advanced_module,
        "_derive_algorithms_from_credentials",
        lambda source: expected_algorithms if list(source) == [records[0]["data"]] else [],
        raising=False,
    )

    captured = {}
    _install_fake_auth_begin_server(monkeypatch, advanced_module, captured)

    with config_module.app.test_client() as client:
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
    assert captured["timeout"] == pytest.approx(15.0)
    assert captured["allowed_algorithms"] == expected_algorithms
    assert captured["extensions"] == {
        "largeBlob": {"write": b"abc"},
        "prf": {"eval": {"first": b"\x01\x02", "second": b"\xaa\xbb"}},
    }
    assert getattr(captured["user_verification"], "value", captured["user_verification"]) == "discouraged"
