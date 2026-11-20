"""Tests for the members of an Advanced request that must be of one JSON type."""
from __future__ import annotations

import pytest

from server.app.routes.advanced import algorithms, registration_options, request_members
from server.app.webauthn import client_credentials
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
        ({"pubKeyCredParams": "ES256"}, "pubKeyCredParams must be a list."),
        ({"pubKeyCredParams": {"alg": -7}}, "pubKeyCredParams must be a list."),
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


# Where a registration begin builds one fido2 object for each entry of a list.
_BUILT_THROUGH = {
    "excludeCredentials": (registration_options, "PublicKeyCredentialDescriptor"),
    "pubKeyCredParams": (algorithms, "PublicKeyCredentialParameters"),
}


def _counting(monkeypatch, member):
    """Count the objects a registration begin builds for ``member``'s entries."""

    built = []
    module, name = _BUILT_THROUGH[member]
    real = getattr(module, name)

    def build(*args, **kwargs):
        built.append(None)
        return real(*args, **kwargs)

    monkeypatch.setattr(module, name, build)
    return built


_EXCLUDED = {"type": "public-key", "id": "0102"}
_ALGORITHM = {"type": "public-key", "alg": -7}


@pytest.mark.parametrize(
    ("member", "entry", "cap", "error"),
    [
        ("excludeCredentials", _EXCLUDED, client_credentials.MAX_SENT_CREDENTIALS, request_members.TOO_MANY_EXCLUDED),
        ("pubKeyCredParams", _ALGORITHM, request_members.MAX_ALGORITHM_PARAMS, request_members.TOO_MANY_ALGORITHMS),
    ],
    ids=["excludeCredentials", "pubKeyCredParams"],
)
def test_a_registration_list_past_its_cap_is_refused_before_its_objects_are_built(monkeypatch, member, entry, cap, error):
    built = _counting(monkeypatch, member)
    client = entry_app().test_client()

    def begin(count):
        options = {**advanced_public_key_options(challenge=b"\x01" * 32), member: [entry] * count}
        return client.post("/api/advanced/register/begin", json={"publicKey": options})

    refused = begin(cap + 1)
    assert refused.status_code == 400
    assert refused.get_json() == {"error": error}
    assert built == []

    accepted = begin(cap)
    assert accepted.status_code == 200, accepted.get_json()
    assert len(built) == cap
