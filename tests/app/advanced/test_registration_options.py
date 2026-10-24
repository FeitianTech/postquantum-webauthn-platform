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


@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"user": {"id": 5, "name": "alice"}}, "Invalid user ID format: not hex text or a $hex, $base64 or $base64url value"),
        ({"challenge": 5}, "Invalid challenge format: not hex text or a $hex, $base64 or $base64url value"),
        ({"challenge": {"value": "00"}}, "Invalid challenge format: not hex text or a $hex, $base64 or $base64url value"),
    ],
)
def test_a_user_id_or_challenge_that_does_not_read_as_bytes_is_refused(changes, error):
    response = entry_app().test_client().post(
        "/api/advanced/register/begin",
        json={"publicKey": {**advanced_public_key_options(challenge=b"\x01" * 32), **changes}},
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": error}


@pytest.mark.parametrize(
    ("exclude_credentials", "error"),
    [
        ([{"type": "public-key", "id": "%%%"}], "Invalid excludeCredentials[0].id format: input is not hexadecimal"),
        (
            [{"type": "public-key", "id": "0102"}, {"type": "public-key", "id": {"$base64url": "%%"}}],
            "Invalid excludeCredentials[1].id format: input is not base64url",
        ),
        (
            [{"type": "public-key", "id": 5}],
            "Invalid excludeCredentials[0].id format: not hex text or a $hex, $base64 or $base64url value",
        ),
    ],
)
def test_an_excluded_id_that_does_not_read_as_bytes_is_refused(exclude_credentials, error):
    response = entry_app().test_client().post(
        "/api/advanced/register/begin",
        json={
            "publicKey": {
                **advanced_public_key_options(challenge=b"\x01" * 32),
                "excludeCredentials": exclude_credentials,
            }
        },
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": error}


def test_an_excluded_entry_of_another_type_is_left_out_whatever_its_id():
    excluded = _begin(excludeCredentials=[{"type": "other", "id": "%%%"}, "not-an-entry"])["excludeCredentials"]

    assert excluded == []


def _begin_with_allowed_origins(make_app, rp_id):
    app = make_app({"FIDO_SERVER_ALLOWED_ORIGINS": "https://webauthndev.com", "FIDO_SERVER_RP_ID": "webauthndev.com"})
    options = {**advanced_public_key_options(challenge=b"\x01" * 32), "rp": {"id": rp_id, "name": "Example"}}
    return app.test_client().post("/api/advanced/register/begin", json={"publicKey": options})


def test_with_allowed_origins_begin_takes_an_rp_id_they_can_use(make_app):
    response = _begin_with_allowed_origins(make_app, "webauthndev.com")

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["publicKey"]["rp"]["id"] == "webauthndev.com"


def test_with_allowed_origins_begin_refuses_an_rp_id_none_of_them_can_use(make_app):
    response = _begin_with_allowed_origins(make_app, "evil.example")

    assert response.status_code == 400
    assert response.get_json() == {
        "error": 'rp.id "evil.example" is not the host of an allowed origin (https://webauthndev.com) '
        "or a registrable suffix of one."
    }


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
