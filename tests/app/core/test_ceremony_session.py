"""A ceremony's begin whose session cookie would not fit is refused, and the session kept as it was."""
from __future__ import annotations

import hashlib

from flask import jsonify, session

from server.app.config import session_cookie
from server.app.routes import ceremony_session
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import (
    Authenticator,
    advanced_public_key_options,
    b64u,
)


def _incompressible_text(length: int) -> str:
    return b64u(hashlib.shake_256(b"ceremony-session").digest(length))[:length]


def _session_cookies(response) -> list[str]:
    return [value for value in response.headers.getlist("Set-Cookie") if value.startswith("session=")]


def _authentication_begin(client, challenge: bytes):
    authenticator = Authenticator()
    return client.post(
        "/api/advanced/authenticate/begin",
        json={
            "publicKey": {"challenge": {"$base64url": b64u(challenge)}},
            "__storedCredentials": [authenticator.stored_credential_entry()],
        },
    )


def test_a_registration_begin_with_a_5000_character_rp_name_is_refused_and_the_session_kept():
    client = entry_app().test_client()
    assert _authentication_begin(client, b"\x01" * 32).status_code == 200
    with client.session_transaction() as before:
        kept = dict(before)
    options = advanced_public_key_options(challenge=b"\x73" * 32)
    options["rp"]["name"] = _incompressible_text(5000)

    response = client.post("/api/advanced/register/begin", json={"publicKey": options})

    assert response.status_code == 400
    assert response.get_json() == {"error": ceremony_session.TOO_LARGE}
    assert all(len(cookie) <= 4093 for cookie in _session_cookies(response))
    with client.session_transaction() as after:
        assert dict(after) == kept


def test_an_authentication_begin_with_a_typed_4_kb_challenge_is_refused():
    client = entry_app().test_client()

    response = _authentication_begin(client, hashlib.shake_256(b"challenge").digest(4096))

    assert response.status_code == 400
    assert response.get_json() == {"error": ceremony_session.TOO_LARGE}
    with client.session_transaction() as after:
        assert "advanced_auth_state" not in after


def test_a_begin_that_fits_answers_as_it_would_and_keeps_its_state():
    client = entry_app().test_client()

    response = _authentication_begin(client, b"\x02" * 32)

    assert response.status_code == 200, response.get_json()
    assert all(len(cookie) <= 4093 for cookie in _session_cookies(response))
    with client.session_transaction() as after:
        assert "advanced_auth_state" in after


def test_a_refused_view_keeps_its_own_answer_and_the_session_as_it_was():
    app = entry_app()

    @ceremony_session.ceremony_begin
    def failing_begin():
        session["state"] = _incompressible_text(6000)
        return jsonify({"error": "Invalid request"}), 422

    with app.test_request_context("/api/advanced/register/begin", method="POST"):
        session["kept"] = "as it was"
        response = failing_begin()

        assert response.status_code == 422
        assert response.get_json() == {"error": "Invalid request"}
        assert dict(session) == {"kept": "as it was"}


def test_the_cookie_size_is_the_length_of_the_set_cookie_header_flask_sends():
    app = entry_app()
    client = app.test_client()

    response = _authentication_begin(client, b"\x03" * 32)

    [cookie] = _session_cookies(response)
    with client.session_transaction() as sent:
        with app.test_request_context():
            assert session_cookie.cookie_size(app, sent) == len(cookie)
