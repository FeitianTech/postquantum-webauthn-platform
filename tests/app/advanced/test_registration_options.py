"""Tests for the options advanced register begin gives fido2 and the browser."""
from __future__ import annotations

import pytest

from server.app.routes.advanced import registration_options
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import advanced_public_key_options


def _begin(client=None, **changes):
    client = client or entry_app().test_client()
    response = client.post(
        "/api/advanced/register/begin",
        json={"publicKey": {**advanced_public_key_options(challenge=b"\x01" * 32), **changes}},
    )
    assert response.status_code == 200, response.get_json()
    return response.get_json()["publicKey"]


@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"extensions": None}, "extensions must be an object."),
        ({"extensions": "credProps"}, "extensions must be an object."),
        ({"rp": "example.com"}, "rp must be an object."),
        ({"user": "alice"}, "user must be an object."),
        ({"excludeCredentials": None}, "excludeCredentials must be a list."),
        ({"timeout": "60s"}, "timeout must be a number of milliseconds."),
        ({"timeout": True}, "timeout must be a number of milliseconds."),
    ],
)
def test_a_member_of_the_wrong_type_is_refused(changes, error):
    response = entry_app().test_client().post(
        "/api/advanced/register/begin",
        json={"publicKey": {**advanced_public_key_options(challenge=b"\x01" * 32), **changes}},
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": error}


@pytest.mark.parametrize(
    ("body", "error"),
    [
        ({"publicKey": "options"}, "publicKey must be an object."),
        (["publicKey"], "Invalid request: Missing publicKey in CredentialCreationOptions"),
    ],
)
def test_a_request_that_is_no_object_is_refused(body, error):
    response = entry_app().test_client().post("/api/advanced/register/begin", json=body)

    assert response.status_code == 400
    assert response.get_json() == {"error": error}


@pytest.mark.parametrize("attestation", ["direct", "indirect", "enterprise"])
def test_the_requested_attestation_is_asked_for(attestation):
    assert _begin(attestation=attestation)["attestation"] == attestation


def test_the_hints_choose_the_attachment_when_the_request_names_none():
    client = entry_app().test_client()

    options = _begin(client, hints=["security-key"], authenticatorSelection="not an object")

    assert options["authenticatorSelection"]["authenticatorAttachment"] == "cross-platform"
    with client.session_transaction() as session:
        assert session["advanced_register_allowed_attachments"] == ["cross-platform"]


def test_a_required_resident_key_and_discouraged_verification_are_asked_for():
    options = _begin(authenticatorSelection={"userVerification": "discouraged", "requireResidentKey": True})

    assert options["authenticatorSelection"] == {
        "requireResidentKey": True,
        "residentKey": "required",
        "userVerification": "discouraged",
    }


def test_extensions_are_passed_on_with_cred_protect_by_its_name():
    options = _begin(
        extensions={
            "credProtect": "userVerificationOptionalWithCredentialIdList",
            "prf": {"eval": "not an object"},
            "customExtension": {"enabled": True},
        }
    )

    assert options["extensions"] == {
        "credentialProtectionPolicy": "userVerificationOptionalWithCredentialIDList",
        "customExtension": {"enabled": True},
        "prf": {"eval": "not an object"},
    }


def test_extension_values_of_an_unexpected_shape_are_passed_on_as_they_are():
    options = _begin(extensions={"credProtect": ["a list"], "prf": "text", "largeBlob": {"support": "required"}})

    assert options["extensions"] == {
        "credentialProtectionPolicy": ["a list"],
        "largeBlob": {"support": "required"},
        "prf": "text",
    }


def test_attestation_formats_are_the_text_items_of_the_requests_list():
    assert registration_options.attestation_formats({"attestationFormats": ["none", 1, "packed"]}) == ["none", "packed"]
    assert registration_options.attestation_formats({"attestationFormats": "packed"}) == []
    assert registration_options.attestation_formats({}) == []


@pytest.mark.parametrize("cred_blob", [{"$base64url": "YmxvYg"}, {"$hex": "626c6f62"}, "626c6f62"])
def test_a_cred_blob_is_given_to_the_browser_as_base64url(cred_blob):
    assert _begin(extensions={"credBlob": cred_blob})["extensions"] == {"credBlob": "YmxvYg"}
