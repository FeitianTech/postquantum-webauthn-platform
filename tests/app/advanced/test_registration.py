"""Tests for the advanced register complete route."""
from __future__ import annotations

from fido2 import cbor

from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import advanced_public_key_options

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
