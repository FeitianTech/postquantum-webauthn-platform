"""A refused ceremony leaves one WARNING line, on all four completes: the route and the
refusal's cause (fido2's finding, else the exception's type and where it was raised),
never text the request carried."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable

import pytest

from server.app.config import relying_party
from tests.app.advanced import assertion_ceremony
from tests.app.entry_app import entry_app

from .ceremony_helpers import (
    ORIGIN,
    SIMPLE_EMAIL,
    Authenticator,
    advanced_public_key_options,
    assertion_payload,
    begin_simple_registration,
    registration_payload,
    simple_complete_body,
    unb64u,
)

MARKER = "MARKER-c0ffee-written-by-a-client"
WRONG_CHALLENGE = b"\x00" * 32


def _simple_registration(client, signed: Callable[[bytes], bytes], before_complete: Callable[[], None]):
    authenticator = Authenticator()
    challenge = begin_simple_registration(client)
    before_complete()
    return client.post(
        f"/api/register/complete?email={SIMPLE_EMAIL}",
        json=registration_payload(authenticator, challenge=signed(challenge)),
        headers={"Origin": ORIGIN},
    )


def _simple_sign_in(client, signed, before_complete):
    authenticator = Authenticator()
    entry = authenticator.stored_credential_entry()
    begin = client.post(f"/api/authenticate/begin?email={SIMPLE_EMAIL}", json={"credentials": [entry]})
    assert begin.status_code == 200, begin.get_json()
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    before_complete()
    return client.post(
        f"/api/authenticate/complete?email={SIMPLE_EMAIL}",
        json=simple_complete_body(assertion_payload(authenticator, challenge=signed(challenge)), [entry]),
        headers={"Origin": ORIGIN},
    )


def _advanced_registration(client, signed, before_complete):
    authenticator = Authenticator()
    begin = client.post(
        "/api/advanced/register/begin", json={"publicKey": advanced_public_key_options(challenge=b"\x73" * 32)}
    )
    assert begin.status_code == 200, begin.get_json()
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    before_complete()
    return client.post(
        "/api/advanced/register/complete",
        json={
            "publicKey": advanced_public_key_options(challenge=challenge),
            "__credential_response": registration_payload(authenticator, challenge=signed(challenge)),
        },
        headers={"Origin": ORIGIN},
    )


def _advanced_sign_in(client, signed, before_complete):
    authenticator = Authenticator()
    credentials = [authenticator.stored_credential_entry()]
    begin = assertion_ceremony.begin(client, credentials)
    assert begin.status_code == 200, begin.get_json()
    before_complete()
    assertion = assertion_payload(authenticator, challenge=signed(assertion_ceremony.CHALLENGE))
    return assertion_ceremony.complete(client, credentials, assertion)


COMPLETES = [
    pytest.param(_simple_registration, "/api/register/complete", id="simple-registration"),
    pytest.param(_simple_sign_in, "/api/authenticate/complete", id="simple-sign-in"),
    pytest.param(_advanced_registration, "/api/advanced/register/complete", id="advanced-registration"),
    pytest.param(_advanced_sign_in, "/api/advanced/authenticate/complete", id="advanced-sign-in"),
]


def _warning_lines(caplog) -> list[str]:
    return [record.getMessage() for record in caplog.records if record.levelno >= logging.WARNING]


class _ServerThatCannotRead:
    """A fido2 server whose refusal's text holds what the client sent, as a parser's can."""

    def register_complete(self, _state, _response):
        raise ValueError(f"cannot read the response: {MARKER}")

    def authenticate_complete(self, _state, _credentials, _response):
        raise ValueError(f"cannot read the response: {MARKER}")


@pytest.mark.parametrize(("ceremony", "path"), COMPLETES)
def test_a_refusal_fido2_found_is_logged_once_with_its_route_and_finding(own_stores, caplog, ceremony, path):
    with caplog.at_level(logging.DEBUG):
        response = ceremony(entry_app().test_client(), lambda _challenge: WRONG_CHALLENGE, lambda: None)

    assert response.status_code == 400
    assert response.get_json()["error"] == "Wrong challenge in response."
    assert _warning_lines(caplog) == [f"POST {path} refused: Wrong challenge in response."]


@pytest.mark.parametrize(("ceremony", "path"), COMPLETES)
def test_a_refusal_is_logged_once_by_its_type_and_place_without_the_text_it_carries(
    own_stores, monkeypatch, caplog, ceremony, path
):
    def _cannot_read():
        monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _ServerThatCannotRead())

    with caplog.at_level(logging.DEBUG):
        response = ceremony(entry_app().test_client(), lambda challenge: challenge, _cannot_read)

    assert response.status_code == 400
    assert response.get_json()["error"].endswith("could not be completed.")
    [line] = _warning_lines(caplog)
    assert re.fullmatch(rf"POST {re.escape(path)} refused: ValueError at {re.escape(__name__)}:\d+", line)
    assert MARKER not in caplog.text
