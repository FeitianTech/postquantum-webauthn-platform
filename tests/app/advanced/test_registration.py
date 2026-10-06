"""Tests for the advanced register complete route."""

from __future__ import annotations

import hashlib
import types

from fido2 import cbor

from server.app.config import relying_party
from server.app.routes.advanced import algorithms as advanced_algorithms
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import (
    ORIGIN,
    Authenticator,
    advanced_public_key_options,
    b64u,
    registration_payload,
    unb64u,
)

from .registration_ceremony import register

_FLAG_ED = 0x80


def _with_cred_protect_output(authenticator):
    auth_data = bytearray(authenticator.authenticator_data())
    auth_data[32] |= _FLAG_ED
    return bytes(auth_data) + cbor.encode({"credProtect": 2})


def test_authenticator_extension_outputs_are_reported_with_the_registration(advanced_stores):
    response = register(entry_app().test_client(), auth_data=_with_cred_protect_output)

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["relyingParty"]["registrationData"]["authenticatorExtensions"] == {
        "credProtect": 2,
        "credProtectLabel": "userVerificationOptionalWithCredentialIDList",
    }


def test_a_registration_without_extension_outputs_reports_none(advanced_stores):
    response = register(entry_app().test_client())

    assert response.status_code == 200, response.get_json()
    assert "authenticatorExtensions" not in response.get_json()["relyingParty"]["registrationData"]


def test_requested_extensions_that_are_no_object_fail_the_registration(advanced_stores):
    response = register(entry_app().test_client(), public_key_changes={"extensions": "not an object"})

    assert response.status_code == 400
    assert response.get_json()["error"]
    assert response.get_json()["challengeStatus"] == "fresh"


def test_a_4096_byte_excluded_id_still_fits_the_session_cookie(advanced_stores):
    # The largest fake credential ID the Advanced form adds (logic/advanced/fake-credentials.js).
    excluded = [{"type": "public-key", "id": {"$base64url": b64u(hashlib.shake_256(b"fake").digest(4096))}}]
    client = entry_app().test_client()
    options = {**advanced_public_key_options(challenge=b"\x73" * 32), "excludeCredentials": excluded}

    begin = client.post("/api/advanced/register/begin", json={"publicKey": options})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    complete = client.post(
        "/api/advanced/register/complete",
        json={
            "publicKey": {**advanced_public_key_options(challenge=challenge), "excludeCredentials": excluded},
            "__credential_response": registration_payload(Authenticator(), challenge=challenge),
        },
        headers={"Origin": ORIGIN},
    )

    # Werkzeug's limit for a Set-Cookie header, just under what browsers keep.
    assert all(len(header) <= 4093 for header in begin.headers.getlist("Set-Cookie"))
    assert complete.status_code == 200, complete.get_json()


def _begin(public_key_changes):
    options = {**advanced_public_key_options(challenge=b"\x73" * 32), **public_key_changes}
    return entry_app().test_client().post("/api/advanced/register/begin", json={"publicKey": options})


def test_begin_gives_the_browser_the_requests_hints_in_its_order():
    response = _begin({"hints": ["hybrid", 7, "security-key"]})

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["publicKey"]["hints"] == ["hybrid", "security-key"]


def test_begin_names_no_hints_when_the_request_has_none():
    response = _begin({"hints": []})

    assert response.status_code == 200, response.get_json()
    assert "hints" not in response.get_json()["publicKey"]


def test_begin_gives_the_browser_the_attestation_formats_the_request_prefers():
    response = _begin({"attestationFormats": ["packed", None, "tpm"]})

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["publicKey"]["attestationFormats"] == ["packed", "tpm"]


def test_begin_refuses_an_extension_value_it_cannot_read():
    response = _begin({"extensions": {"prf": {"eval": {"first": "not hex"}}}})

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid extension value: input is not hexadecimal"}


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


def _install_fake_register_server(monkeypatch, captured):
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

    monkeypatch.setattr(relying_party, "create_fido_server", _create_fido_server)


def test_advanced_register_begin_normalizes_rp_and_persists_session_state(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        relying_party,
        "build_rp_entity",
        lambda _rp: types.SimpleNamespace(id="normalized.example", name="Normalized RP")
    )
    monkeypatch.setattr(advanced_algorithms, "_verifiable_algorithms", lambda: {-50, -49, -48})
    _install_fake_register_server(monkeypatch, captured)

    payload = _base_payload()
    payload["publicKey"]["rp"] = {
        "id": "ignored.example",
        "name": "Ignored Name",
        "icon": "https://example.com/icon.png",
    }

    with entry_app().test_client() as client:
        response = client.post("/api/advanced/register/begin", json=payload)

        assert response.status_code == 200
        body = response.get_json()
        assert "__session_state" not in body

        create_kwargs = captured["create_fido_server_kwargs"]
        assert create_kwargs["rp_data"] == {
            "id": "normalized.example",
            "name": "Normalized RP",
            "icon": "https://example.com/icon.png",
        }

        with client.session_transaction() as session_state:
            # Stamped at issue, so /complete can tell fresh from replayed or stale.
            stored_state = dict(session_state["advanced_state"])
            assert isinstance(stored_state.pop("issued_at"), float)
            assert stored_state == {"challenge": "state-token"}
            assert session_state["advanced_rp"] == {
                "id": "normalized.example",
                "name": "Normalized RP",
            }
            # Only what complete's checks read of the request: no rp, user or excluded IDs.
            kept = session_state["advanced_original_request"]["publicKey"]
            assert set(kept) == {"pubKeyCredParams", "challenge"}
            assert kept["pubKeyCredParams"] == payload["publicKey"]["pubKeyCredParams"]


def test_advanced_register_begin_normalizes_pubkeycredparams_and_filters_invalid_entries(monkeypatch):
    captured = {}
    monkeypatch.setattr(advanced_algorithms, "_verifiable_algorithms", lambda: {-50, -49, -48})
    _install_fake_register_server(monkeypatch, captured)

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

    with entry_app().test_client() as client:
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
    captured = {}
    monkeypatch.setattr(advanced_algorithms, "_verifiable_algorithms", lambda: {-50, -49, -48})
    _install_fake_register_server(monkeypatch, captured)

    payload = _base_payload()
    payload["publicKey"].pop("pubKeyCredParams")

    with entry_app().test_client() as client:
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
    captured = {}
    monkeypatch.setattr(advanced_algorithms, "_verifiable_algorithms", lambda: {-49})
    _install_fake_register_server(monkeypatch, captured)

    payload = _base_payload()
    payload["publicKey"]["pubKeyCredParams"] = [
        {"type": "public-key", "alg": -50},
        {"type": "public-key", "alg": -7},
    ]

    with entry_app().test_client() as client:
        response = client.post("/api/advanced/register/begin", json=payload)

    assert response.status_code == 200
    body = response.get_json()
    assert [entry["alg"] for entry in body["publicKey"]["pubKeyCredParams"]] == [-7]
    assert any("Unsupported PQC algorithms were skipped" in warning for warning in body.get("warnings", []))


def test_advanced_register_begin_refuses_when_no_requested_algorithm_is_verifiable(monkeypatch):
    captured = {}
    monkeypatch.setattr(advanced_algorithms, "_verifiable_algorithms", lambda: set())
    _install_fake_register_server(monkeypatch, captured)

    payload = _base_payload()
    payload["publicKey"]["pubKeyCredParams"] = [{"type": "public-key", "alg": -50}]

    with entry_app().test_client() as client:
        response = client.post("/api/advanced/register/begin", json=payload)

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "None of the requested algorithms can be verified by this server (ML-DSA-87)."
    }
    assert "create_fido_server_kwargs" in captured and "allowed_algorithms" not in captured


def test_advanced_register_begin_maps_auth_selection_exclusions_extensions_and_timeout(monkeypatch):
    captured = {}
    monkeypatch.setattr(advanced_algorithms, "_verifiable_algorithms", lambda: {-50, -49, -48})
    _install_fake_register_server(monkeypatch, captured)

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

    with entry_app().test_client() as client:
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

        assert captured["timeout"] == 15000
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
