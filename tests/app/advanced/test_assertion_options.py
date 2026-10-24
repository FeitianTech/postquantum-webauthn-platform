"""Tests for the options advanced authenticate begin gives fido2 and the browser."""
from __future__ import annotations

import pytest

from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import (
    Authenticator,
    advanced_public_key_options,
)

from .assertion_ceremony import begin


def _options(response):
    assert response.status_code == 200, response.get_json()
    return response.get_json()["publicKey"]


def test_authentication_is_for_the_rp_id_the_request_names():
    client = entry_app().test_client()

    options = _options(begin(client, [Authenticator().stored_credential_entry()], rpId="sub.localhost"))

    assert options["rpId"] == "sub.localhost"
    with client.session_transaction() as session:
        assert session["advanced_auth_rp"] == {"id": "sub.localhost"}


@pytest.mark.parametrize("changes", [{"rpId": "localhost"}, {}])
def test_a_registration_begin_left_unfinished_names_no_rp_for_authentication(changes):
    client = entry_app().test_client()
    registration_options = advanced_public_key_options(challenge=b"\x01" * 32, rp_id="other.localhost")
    client.post("/api/advanced/register/begin", json={"publicKey": registration_options})

    options = _options(begin(client, [Authenticator().stored_credential_entry()], **changes))

    # The request's rpId, else the RP ID derived from the request's host.
    assert options["rpId"] == "localhost"


def test_with_allowed_origins_an_rp_id_none_of_them_can_use_is_refused(make_app):
    app = make_app({"FIDO_SERVER_ALLOWED_ORIGINS": "https://webauthndev.com", "FIDO_SERVER_RP_ID": "webauthndev.com"})

    response = begin(app.test_client(), [Authenticator().stored_credential_entry()], rpId="evil.example")

    assert response.status_code == 400
    assert response.get_json() == {
        "error": 'rpId "evil.example" is not the host of an allowed origin (https://webauthndev.com) '
        "or a registrable suffix of one."
    }


@pytest.mark.parametrize(
    ("requested", "asked"),
    [("required", "required"), ("discouraged", "discouraged"), ("anything else", "preferred")],
)
def test_the_requested_user_verification_is_asked_for(requested, asked):
    options = _options(begin(entry_app().test_client(), [Authenticator().stored_credential_entry()], userVerification=requested))

    assert options["userVerification"] == asked


@pytest.mark.parametrize(
    "extensions",
    [
        {"largeBlob": {"read": True}, "prf": {"salt": "abc"}, "txAuthSimple": "hello"},
        {"largeBlob": {"support": "preferred"}},
        {"largeBlob": "required"},
    ],
)
def test_extensions_without_bytes_to_read_are_passed_on_as_they_are(extensions):
    options = _options(begin(entry_app().test_client(), [Authenticator().stored_credential_entry()], extensions=extensions))

    assert options["extensions"] == extensions


def test_prf_inputs_for_each_credential_are_given_to_the_browser_with_the_general_ones():
    extensions = {
        "prf": {
            "eval": {"first": {"$hex": "0101"}},
            "evalByCredential": {"BAQE": {"first": "0202", "second": {"$base64url": "AwM"}}},
        }
    }

    options = _options(begin(entry_app().test_client(), [Authenticator().stored_credential_entry()], extensions=extensions))

    assert options["extensions"] == {
        "prf": {"eval": {"first": "AQE"}, "evalByCredential": {"BAQE": {"first": "AgI", "second": "AwM"}}},
    }


def test_prf_with_no_input_to_read_asks_for_no_prf():
    options = _options(
        begin(entry_app().test_client(), [Authenticator().stored_credential_entry()], extensions={"prf": {"eval": {}}})
    )

    assert "extensions" not in options or "prf" not in options["extensions"]
