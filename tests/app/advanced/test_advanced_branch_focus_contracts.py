from __future__ import annotations

import base64
import types

import pytest


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _authenticator_data_b64url(counter: int) -> str:
    raw = b"\x00" * 32 + b"\x01" + int(counter).to_bytes(4, "big")
    return _b64url(raw)


def _credential_record(
    credential_id,
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


def _install_fake_auth_begin_server(monkeypatch, advanced_module, captured):
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
            return {
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": "placeholder"}],
                }
            }, {"challenge": "state-token"}

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


def test_advanced_put_snapshot_route_returns_400_when_store_fails(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(advanced_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(advanced_module, "store_credential_artifact", lambda *_args, **_kwargs: False, raising=False)

    with config_module.app.test_client() as client:
        response = client.put(
            "/api/advanced/credential-artifacts/snapshot-fail/snapshot",
            json={"snapshot": {"html": "<p>snapshot</p>"}},
        )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Unable to store artifact snapshot."}


def test_advanced_authenticate_begin_returns_no_matching_credentials_for_invalid_record_ids(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [_credential_record("not-bytes", resident=False)],
            [_serialized_record(resident=False)],
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
                    "allowCredentials": [{"type": "public-key", "id": "00"}],
                },
                "__storedCredentials": [{"record": 1}],
            },
        )

    assert response.status_code == 404
    assert response.get_json() == {
        "error": "No matching credentials found. Please register first."
    }


def test_advanced_authenticate_begin_resident_mode_reports_no_resident_keys_when_ids_invalid(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [_credential_record("not-bytes", resident=True)],
            [_serialized_record(resident=True)],
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
                },
                "__storedCredentials": [{"record": 1}],
            },
        )

    assert response.status_code == 404
    assert response.get_json() == {
        "error": "No resident key credentials are available. Please register a discoverable credential first."
    }


def test_advanced_authenticate_begin_uses_algorithm_source_fallback_and_extension_passthrough(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    marker = object()

    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [_credential_record("not-bytes", data=marker, resident=False)],
            [_serialized_record(resident=False)],
        ),
        raising=False,
    )

    captured = {}

    def _derive(source):
        captured["algorithm_source"] = list(source)
        return [types.SimpleNamespace(alg=-7)]

    monkeypatch.setattr(
        advanced_module,
        "_derive_algorithms_from_credentials",
        _derive,
        raising=False,
    )

    _install_fake_auth_begin_server(monkeypatch, advanced_module, captured)

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/begin",
            json={
                "publicKey": {
                    "challenge": "010203",
                    "extensions": {
                        "largeBlob": {"read": True},
                        "prf": {"salt": "abc"},
                        "txAuthSimple": "hello",
                    },
                },
                "__storedCredentials": [{"record": 1}],
            },
        )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["__session_state"] == {"challenge": "state-token"}
    assert "allowCredentials" not in payload["publicKey"]
    assert captured["credentials"] is None
    assert captured["algorithm_source"] == [marker]
    assert captured["extensions"] == {
        "largeBlob": {"read": True},
        "prf": {"salt": "abc"},
        "txAuthSimple": "hello",
    }
    assert [entry.alg for entry in captured["allowed_algorithms"]] == [-7]


def test_advanced_authenticate_begin_largeblob_dict_passthrough_when_no_read_or_write(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [_credential_record(b"credential", resident=True)],
            [_serialized_record(resident=True)],
        ),
        raising=False,
    )
    monkeypatch.setattr(advanced_module, "_derive_algorithms_from_credentials", lambda _source: [], raising=False)

    captured = {}
    _install_fake_auth_begin_server(monkeypatch, advanced_module, captured)

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/begin",
            json={
                "publicKey": {
                    "challenge": "010203",
                    "extensions": {"largeBlob": {"support": "preferred"}},
                },
                "__storedCredentials": [{"record": 1}],
            },
        )

    assert response.status_code == 200
    assert captured["extensions"] == {"largeBlob": {"support": "preferred"}}


def test_advanced_authenticate_begin_largeblob_non_dict_and_prf_passthrough(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [_credential_record(b"credential", resident=True)],
            [_serialized_record(resident=True)],
        ),
        raising=False,
    )
    monkeypatch.setattr(advanced_module, "_derive_algorithms_from_credentials", lambda _source: [], raising=False)

    captured = {}
    _install_fake_auth_begin_server(monkeypatch, advanced_module, captured)

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/begin",
            json={
                "publicKey": {
                    "challenge": "010203",
                    "extensions": {
                        "largeBlob": "required",
                        "prf": {"salt": "abc"},
                    },
                },
                "__storedCredentials": [{"record": 1}],
            },
        )

    assert response.status_code == 200
    assert captured["extensions"] == {
        "largeBlob": "required",
        "prf": {"salt": "abc"},
    }


def test_advanced_authenticate_complete_requires_assertion_response():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/complete",
            json={"publicKey": {"challenge": "AQID"}},
        )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Assertion response is required"}


def test_advanced_authenticate_complete_requires_public_key_payload():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/complete",
            json={"__assertion_response": {"response": {}}},
        )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid request: Missing publicKey in JSON editor content"}


def test_advanced_authenticate_complete_uses_legacy_session_credentials_fallback(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    credential_id = b"legacy-credential"
    encoded_id = _b64url(credential_id)

    legacy_payload = [{"legacy": True}]

    def _parse(raw):
        if raw == legacy_payload:
            return (
                [_credential_record(credential_id, resident=True)],
                [_serialized_record(resident=True)],
            )
        return ([], [])

    class _AuthResult:
        public_key = {3: -7}

    class _FakeServer:
        allowed_algorithms = []

        def authenticate_complete(self, *_args, **_kwargs):
            return _AuthResult()

    monkeypatch.setattr(advanced_module, "_parse_client_supplied_credentials", _parse, raising=False)
    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FakeServer(), raising=False)
    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or "example.com", raising=False)
    monkeypatch.setattr(advanced_module, "_derive_algorithms_from_credentials", lambda _source: [], raising=False)

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_state"] = {"challenge": "state-token"}
            session_state["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}
            session_state["advanced_auth_credentials"] = legacy_payload

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": encoded_id}],
                },
                "__assertion_response": {"rawId": encoded_id, "response": {}},
            },
        )

        assert response.status_code == 200
        assert response.get_json()["status"] == "OK"

        with client.session_transaction() as session_state:
            assert "advanced_auth_credentials" not in session_state


def test_advanced_authenticate_complete_returns_404_when_no_credentials_found_anywhere():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_credentials_meta"] = {"count": 2, "resident_count": 1}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {"challenge": "AQID"},
                "__assertion_response": {"response": {}},
            },
        )

        assert response.status_code == 404
        assert response.get_json() == {"error": "No credentials found"}

        with client.session_transaction() as session_state:
            assert "advanced_auth_credentials_meta" not in session_state


def test_advanced_authenticate_complete_uses_request_rpid_sets_algorithms_and_sign_count(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    credential_id = b"request-rpid-credential"
    encoded_id = _b64url(credential_id)

    captured = {}

    class _PublicKeyGettable:
        def get(self, key, default=None):
            if key == 3:
                return -7
            return default

    class _AuthResult:
        public_key = _PublicKeyGettable()

    class _FakeServer:
        def __init__(self):
            self.allowed_algorithms = []

        def authenticate_complete(self, *_args, **_kwargs):
            captured["server_allowed_algorithms"] = [
                getattr(entry, "alg", None) for entry in self.allowed_algorithms
            ]
            return _AuthResult()

    def _create_fido_server(**kwargs):
        captured["create_server_kwargs"] = kwargs
        return _FakeServer()

    def _derive_algorithms(source):
        captured["derive_source_len"] = len(list(source))
        return [types.SimpleNamespace(alg=-7)]

    def _determine_rp_id(value=None):
        captured["determine_rp_id_arg"] = value
        return value or "default.example"

    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [_credential_record(credential_id, resident=True)],
            [_serialized_record(resident=True)],
        ),
        raising=False,
    )
    monkeypatch.setattr(advanced_module, "create_fido_server", _create_fido_server, raising=False)
    monkeypatch.setattr(advanced_module, "determine_rp_id", _determine_rp_id, raising=False)
    monkeypatch.setattr(advanced_module, "_derive_algorithms_from_credentials", _derive_algorithms, raising=False)

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_state"] = {"challenge": "state-token"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {
                    "challenge": "AQID",
                    "rpId": "request-rp.example",
                    "allowCredentials": [{"type": "public-key", "id": encoded_id}],
                },
                "__storedCredentials": [{"record": 1}],
                "__assertion_response": {
                    "rawId": encoded_id,
                    "response": {"authenticatorData": _authenticator_data_b64url(7)},
                },
            },
        )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "OK"
    assert payload["algorithm"] == -7
    assert payload["signCount"] == 7

    assert captured["determine_rp_id_arg"] == "request-rp.example"
    assert captured["create_server_kwargs"]["rp_id"] == "request-rp.example"
    assert captured["server_allowed_algorithms"] == [-7]


def test_advanced_authenticate_complete_error_path_uses_failed_id_fallback_extractor(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    credential_id = b"error-fallback-credential"
    encoded_id = _b64url(credential_id)

    class _FailingServer:
        allowed_algorithms = []

        def authenticate_complete(self, *_args, **_kwargs):
            raise ValueError("verification failure")

    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [_credential_record(credential_id, resident=True)],
            [_serialized_record(resident=True)],
        ),
        raising=False,
    )
    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FailingServer(), raising=False)
    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or "example.com", raising=False)
    monkeypatch.setattr(advanced_module, "_derive_algorithms_from_credentials", lambda _source: [], raising=False)

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_state"] = {"challenge": "state-token"}
            session_state["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": encoded_id}],
                },
                "__storedCredentials": [{"record": 1}],
                "__assertion_response": {"response": {}},
            },
        )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "verification failure"
    assert "failedCredentialId" not in payload


def test_advanced_helper_binary_and_algorithm_edge_fallbacks():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    assert advanced_module._decode_client_binary({"base64": base64.b64encode(b"abc").decode("ascii")}) == b"abc"

    with pytest.raises(ValueError, match="empty binary value"):
        advanced_module._decode_client_binary({"hex": "  "})

    with pytest.raises(ValueError, match="empty binary value"):
        advanced_module._decode_client_binary({"base64": "   "})

    assert advanced_module._coerce_cose_algorithm(float("inf")) is None
    assert advanced_module._coerce_cose_algorithm(float("-inf")) is None
    assert advanced_module._coerce_cose_algorithm(float("nan")) is None
    assert advanced_module._coerce_cose_algorithm("fido custom alg (-12345)") == -12345
