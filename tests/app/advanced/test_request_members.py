"""Tests for the members of an Advanced request that must be of one JSON type."""
from __future__ import annotations

import pytest

from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import (
    Authenticator,
    advanced_public_key_options,
)

from .assertion_ceremony import begin


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
        ({"rp": {"id": 5, "name": "x"}}, "rp.id must be a non-empty string."),
        ({"rp": {"id": "", "name": "x"}}, "rp.id must be a non-empty string."),
        ({"rp": {"id": None, "name": "x"}}, "rp.id must be a non-empty string."),
        ({"rp": {"id": "localhost", "name": 5}}, "rp.name must be a string."),
        ({"user": {"name": 5, "displayName": "x"}}, "user.name must be a string."),
        ({"user": {"id": "00", "name": "alice", "displayName": 5}}, "user.displayName must be a string."),
    ],
)
def test_a_registration_member_of_the_wrong_type_is_refused(changes, error):
    response = entry_app().test_client().post(
        "/api/advanced/register/begin",
        json={"publicKey": {**advanced_public_key_options(challenge=b"\x01" * 32), **changes}},
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": error}


@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"extensions": "x"}, "extensions must be an object."),
        ({"timeout": "soon"}, "timeout must be a number of milliseconds."),
        ({"allowCredentials": 5}, "allowCredentials must be a list."),
        ({"rpId": 5}, "rpId must be a non-empty string."),
        ({"rpId": ""}, "rpId must be a non-empty string."),
    ],
)
def test_an_authentication_member_of_the_wrong_type_is_refused(changes, error):
    response = begin(entry_app().test_client(), [Authenticator().stored_credential_entry()], **changes)

    assert response.status_code == 400
    assert response.get_json() == {"error": error}
