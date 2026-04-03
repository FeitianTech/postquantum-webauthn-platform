import types

import pytest


def _base_payload():
    return {
        "publicKey": {
            "rp": {"id": "example.com", "name": "Example"},
            "user": {
                "id": "01020304",
                "name": "user@example.com",
                "displayName": "User",
            },
            "challenge": "0a0b0c0d",
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        }
    }


def _install_fake_register_server(monkeypatch, advanced_module, captured):
    class _FakeServer:
        def __init__(self):
            self.allowed_algorithms = []
            self.timeout = None
            self.attestation = None

        def register_begin(self, *args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            captured["allowed_algorithms"] = [
                getattr(param, "alg", None) for param in self.allowed_algorithms
            ]
            captured["timeout"] = self.timeout
            captured["attestation"] = self.attestation
            return {
                "publicKey": {
                    "challenge": "AQID",
                    "pubKeyCredParams": [
                        {
                            "type": "public-key",
                            "alg": getattr(param, "alg", None),
                        }
                        for param in self.allowed_algorithms
                        if isinstance(getattr(param, "alg", None), int)
                    ],
                }
            }, {"challenge": "state-token"}

    def _create_fido_server(**kwargs):
        captured["create_fido_server_kwargs"] = kwargs
        return _FakeServer()

    monkeypatch.setattr(
        advanced_module,
        "create_fido_server",
        _create_fido_server,
        raising=False,
    )


def test_advanced_register_begin_requires_public_key_payload():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/register/begin", json={})

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "Invalid request: Missing publicKey in CredentialCreationOptions"
    }


@pytest.mark.parametrize(
    "missing_key,expected_error",
    [
        ("rp", "Missing required field: rp"),
        ("user", "Missing required field: user"),
        ("challenge", "Missing required field: challenge"),
    ],
)
def test_advanced_register_begin_requires_mandatory_fields(missing_key, expected_error):
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    payload = _base_payload()
    payload["publicKey"].pop(missing_key)

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/register/begin", json=payload)

    assert response.status_code == 400
    assert response.get_json() == {"error": expected_error}


def test_advanced_register_begin_requires_user_name():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    payload = _base_payload()
    payload["publicKey"]["user"]["name"] = ""

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/register/begin", json=payload)

    assert response.status_code == 400
    assert response.get_json() == {"error": "Username is required in user.name"}


def test_advanced_register_begin_rejects_invalid_user_id_format():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    payload = _base_payload()
    payload["publicKey"]["user"]["id"] = "g$"

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/register/begin", json=payload)

    assert response.status_code == 400
    assert "Invalid user ID format" in response.get_json()["error"]


def test_advanced_register_begin_rejects_invalid_challenge_format():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    payload = _base_payload()
    payload["publicKey"]["challenge"] = "not-hex"

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/register/begin", json=payload)

    assert response.status_code == 400
    assert "Invalid challenge format" in response.get_json()["error"]


def test_advanced_register_begin_normalizes_rp_and_persists_session_state(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    captured = {}

    monkeypatch.setattr(
        advanced_module,
        "build_rp_entity",
        lambda _rp: types.SimpleNamespace(id="normalized.example", name="Normalized RP"),
        raising=False,
    )
    monkeypatch.setattr(
        advanced_module,
        "detect_available_pqc_algorithms",
        lambda: ({-50, -49, -48}, None),
        raising=False,
    )
    _install_fake_register_server(monkeypatch, advanced_module, captured)

    payload = _base_payload()
    payload["publicKey"]["rp"] = {
        "id": "ignored.example",
        "name": "Ignored Name",
        "icon": "https://example.com/icon.png",
    }

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/register/begin", json=payload)

        assert response.status_code == 200
        body = response.get_json()
        assert body["__session_state"] == {"challenge": "state-token"}

        create_kwargs = captured["create_fido_server_kwargs"]
        assert create_kwargs["rp_data"] == {
            "id": "normalized.example",
            "name": "Normalized RP",
            "icon": "https://example.com/icon.png",
        }

        with client.session_transaction() as session_state:
            assert session_state["advanced_state"] == {"challenge": "state-token"}
            assert session_state["advanced_rp"] == {
                "id": "normalized.example",
                "name": "Normalized RP",
            }
            assert session_state["advanced_original_request"]["publicKey"]["rp"] == {
                "id": "normalized.example",
                "name": "Normalized RP",
                "icon": "https://example.com/icon.png",
            }


def test_advanced_register_begin_normalizes_pubkeycredparams_and_filters_invalid_entries(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    captured = {}
    monkeypatch.setattr(
        advanced_module,
        "detect_available_pqc_algorithms",
        lambda: ({-50, -49, -48}, None),
        raising=False,
    )
    _install_fake_register_server(monkeypatch, advanced_module, captured)

    payload = _base_payload()
    payload["publicKey"]["pubKeyCredParams"] = [
        {"type": "public-key", "alg": "-7"},
        {"type": "public-key", "id": "-257"},
        {"type": "public-key", "value": "ES384"},
        {"type": "public-key", "alg": "invalid"},
        {"type": "not-public-key", "alg": -8},
        {"type": 123, "alg": -8},
        -8,
    ]

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/register/begin", json=payload)

    assert response.status_code == 200
    body = response.get_json()
    assert body["publicKey"]["pubKeyCredParams"] == [
        {"type": "public-key", "alg": -7},
        {"type": "public-key", "alg": -257},
        {"type": "public-key", "alg": -35},
        {"type": "public-key", "alg": -8},
    ]
    assert captured["allowed_algorithms"] == [-7, -257, -35, -8]


def test_advanced_register_begin_uses_default_algorithms_without_pubkeycredparams(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    captured = {}
    monkeypatch.setattr(
        advanced_module,
        "detect_available_pqc_algorithms",
        lambda: ({-50, -49, -48}, None),
        raising=False,
    )
    _install_fake_register_server(monkeypatch, advanced_module, captured)

    payload = _base_payload()
    payload["publicKey"].pop("pubKeyCredParams")

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/register/begin", json=payload)

    assert response.status_code == 200
    body = response.get_json()
    assert [entry["alg"] for entry in body["publicKey"]["pubKeyCredParams"]] == [
        -50,
        -48,
        -49,
        -7,
        -257,
    ]
    assert captured["allowed_algorithms"] == [-50, -48, -49, -7, -257]


def test_advanced_register_begin_filters_unavailable_pqc_when_classical_algorithms_remain(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    captured = {}
    monkeypatch.setattr(
        advanced_module,
        "detect_available_pqc_algorithms",
        lambda: ({-49}, "limited pqc"),
        raising=False,
    )
    _install_fake_register_server(monkeypatch, advanced_module, captured)

    payload = _base_payload()
    payload["publicKey"]["pubKeyCredParams"] = [
        {"type": "public-key", "alg": -50},
        {"type": "public-key", "alg": -7},
    ]

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/register/begin", json=payload)

    assert response.status_code == 200
    body = response.get_json()
    assert [entry["alg"] for entry in body["publicKey"]["pubKeyCredParams"]] == [-7]
    assert any("Unsupported PQC algorithms were skipped" in warning for warning in body.get("warnings", []))


def test_advanced_register_begin_falls_back_to_classical_when_no_requested_pqc_available(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    captured = {}
    monkeypatch.setattr(
        advanced_module,
        "detect_available_pqc_algorithms",
        lambda: (set(), "no oqs available"),
        raising=False,
    )
    _install_fake_register_server(monkeypatch, advanced_module, captured)

    payload = _base_payload()
    payload["publicKey"]["pubKeyCredParams"] = [{"type": "public-key", "alg": -50}]

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/register/begin", json=payload)

    assert response.status_code == 200
    body = response.get_json()
    assert [entry["alg"] for entry in body["publicKey"]["pubKeyCredParams"]] == [-7, -8, -257]
    assert any("falling back to classical algorithms" in warning for warning in body.get("warnings", []))


def test_advanced_register_begin_maps_auth_selection_exclusions_extensions_and_timeout(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    captured = {}
    monkeypatch.setattr(
        advanced_module,
        "detect_available_pqc_algorithms",
        lambda: ({-50, -49, -48}, None),
        raising=False,
    )
    _install_fake_register_server(monkeypatch, advanced_module, captured)

    payload = _base_payload()
    payload["publicKey"].update(
        {
            "timeout": 15000,
            "hints": ["client-device"],
            "authenticatorSelection": {
                "userVerification": "required",
                "residentKey": "required",
                "authenticatorAttachment": "platform",
            },
            "excludeCredentials": [
                {"type": "public-key", "id": "0102"},
                {"type": "not-public-key", "id": "0304"},
            ],
            "extensions": {
                "credProps": 1,
                "minPinLength": 0,
                "credProtect": 2,
                "enforceCredProtect": True,
                "largeBlob": "preferred",
                "prf": {
                    "eval": {
                        "first": "0a0b",
                        "second": "0c0d",
                    }
                },
            },
        }
    )

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/register/begin", json=payload)

        assert response.status_code == 200
        kwargs = captured["kwargs"]
        args = captured["args"]

        user_entity = args[0]
        exclude_list = args[1]
        assert getattr(user_entity, "name") == "user@example.com"
        assert getattr(user_entity, "display_name") == "User"
        assert bytes(getattr(user_entity, "id")) == bytes.fromhex("01020304")

        assert len(exclude_list) == 1
        assert bytes(getattr(exclude_list[0], "id")) == bytes.fromhex("0102")

        assert captured["timeout"] == pytest.approx(15.0)
        assert getattr(captured["attestation"], "value", captured["attestation"]) == "none"

        assert getattr(kwargs["user_verification"], "value", kwargs["user_verification"]) == "required"
        assert (
            getattr(kwargs["resident_key_requirement"], "value", kwargs["resident_key_requirement"])
            == "required"
        )
        assert getattr(kwargs["authenticator_attachment"], "value", kwargs["authenticator_attachment"]) == "platform"
        assert kwargs["challenge"] == bytes.fromhex("0a0b0c0d")
        assert kwargs["extensions"] == {
            "credProps": True,
            "minPinLength": False,
            "credentialProtectionPolicy": "userVerificationOptionalWithCredentialIDList",
            "enforceCredentialProtectionPolicy": True,
            "largeBlob": {"support": "preferred"},
            "prf": {"eval": {"first": bytes.fromhex("0a0b"), "second": bytes.fromhex("0c0d")}},
        }

        with client.session_transaction() as session_state:
            assert session_state["advanced_register_allowed_attachments"] == ["platform"]
