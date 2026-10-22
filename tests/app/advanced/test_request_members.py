"""Tests for the members of an Advanced request that must be of one JSON type."""
from __future__ import annotations

import pytest

from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import advanced_public_key_options


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
def test_a_registration_member_of_the_wrong_type_is_refused(changes, error):
    response = entry_app().test_client().post(
        "/api/advanced/register/begin",
        json={"publicKey": {**advanced_public_key_options(challenge=b"\x01" * 32), **changes}},
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": error}
