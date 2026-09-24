"""A ceremony challenge is single-use, even against a resent session cookie.

Flask sessions here are client-side signed cookies, so removing the ceremony
state from the session on ``/complete`` is not enough: a caller who kept the
cookie from just after ``/begin`` can send it again, and it still carries a
validly signed state. These tests do exactly that, with real key material and
real signatures, and require the server-side challenge registry to refuse the
second use.
"""
from __future__ import annotations

import time

from .ceremony_helpers import (
    ORIGIN,
    Authenticator,
    assertion_payload,
    b64u,
    registration_payload,
    unb64u,
)

SESSION_COOKIE = "session"


def _snapshot_cookie(client) -> str:
    cookie = client.get_cookie(SESSION_COOKIE)
    assert cookie is not None
    return cookie.value


def _restore_cookie(client, value: str) -> None:
    client.set_cookie(SESSION_COOKIE, value)


def _begin_simple_authentication(client, authenticator):
    begin = client.post(
        "/api/authenticate/begin?email=user@example.com",
        json={"credentials": [authenticator.stored_credential_entry()]},
    )
    assert begin.status_code == 200, begin.get_json()
    return unb64u(begin.get_json()["publicKey"]["challenge"])


def _complete_simple_authentication(client, payload):
    return client.post(
        "/api/authenticate/complete?email=user@example.com",
        json=payload,
        headers={"Origin": ORIGIN},
    )


# --------------------------------------------------------------------------
# NEGATIVE -- replaying a consumed challenge.
# --------------------------------------------------------------------------


def test_simple_assertion_replayed_with_earlier_cookie_is_rejected(config_module, simple_module, simple_storage):
    authenticator = Authenticator()
    client = config_module.app.test_client()

    challenge = _begin_simple_authentication(client, authenticator)
    cookie_with_state = _snapshot_cookie(client)
    assertion = assertion_payload(authenticator, challenge=challenge, counter=1)

    first = _complete_simple_authentication(client, assertion)
    assert first.status_code == 200, first.get_json()
    assert first.get_json()["status"] == "OK"

    # The attacker resends the cookie that still holds the ceremony state,
    # together with the exact same, genuinely signed assertion.
    _restore_cookie(client, cookie_with_state)
    replay = _complete_simple_authentication(client, assertion)

    assert replay.status_code == 400
    body = replay.get_json()
    assert body.get("status") != "OK"
    assert "already been used" in body["error"]


def test_simple_challenge_is_consumed_even_when_the_first_attempt_fails(config_module, simple_module, simple_storage):
    """A failed completion burns the challenge too; it cannot be retried."""

    authenticator = Authenticator()
    client = config_module.app.test_client()

    challenge = _begin_simple_authentication(client, authenticator)
    cookie_with_state = _snapshot_cookie(client)

    failed = _complete_simple_authentication(
        client, assertion_payload(authenticator, challenge=challenge, valid_signature=False)
    )
    assert failed.status_code == 400

    _restore_cookie(client, cookie_with_state)
    retry = _complete_simple_authentication(
        client, assertion_payload(authenticator, challenge=challenge, counter=1)
    )

    assert retry.status_code == 400
    assert retry.get_json().get("status") != "OK"
    assert "already been used" in retry.get_json()["error"]


def test_simple_registration_replayed_with_earlier_cookie_is_rejected(config_module, simple_module, simple_storage):
    authenticator = Authenticator()
    client = config_module.app.test_client()

    begin = client.post("/api/register/begin?email=user@example.com", json={"credentials": []})
    assert begin.status_code == 200
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    cookie_with_state = _snapshot_cookie(client)
    payload = registration_payload(authenticator, challenge=challenge)

    first = client.post(
        "/api/register/complete?email=user@example.com", json=payload, headers={"Origin": ORIGIN}
    )
    assert first.status_code == 200, first.get_json()
    simple_storage.clear()

    _restore_cookie(client, cookie_with_state)
    replay = client.post(
        "/api/register/complete?email=user@example.com", json=payload, headers={"Origin": ORIGIN}
    )

    assert replay.status_code == 400
    assert "already been used" in replay.get_json()["error"]
    # Nothing was persisted by the replay.
    assert simple_storage == {}


def test_simple_state_older_than_the_ttl_is_rejected(config_module, simple_module, simple_storage, monkeypatch):
    """A validly signed but stale state is refused, even on first use.

    Without this, a replay would succeed again once the registry's record of
    the challenge had been evicted.
    """

    monkeypatch.setenv("FIDO_SERVER_CHALLENGE_TTL_SECONDS", "60")
    authenticator = Authenticator()
    challenge = b"\x5A" * 32
    client = config_module.app.test_client()

    with client.session_transaction() as session:
        session["simple_credentials"] = [authenticator.stored_credential_entry()]
        session["authenticate_rp_id"] = "localhost"
        session["state"] = {
            "challenge": b64u(challenge),
            "user_verification": "discouraged",
            "issued_at": time.time() - 61,
        }

    response = _complete_simple_authentication(
        client, assertion_payload(authenticator, challenge=challenge, counter=1)
    )

    assert response.status_code == 400
    assert response.get_json().get("status") != "OK"
    assert "expired" in response.get_json()["error"]


def test_simple_state_without_issued_at_stamp_is_rejected(config_module, simple_module, simple_storage):
    """A state from before stamping existed cannot be told apart from a stale one."""

    authenticator = Authenticator()
    challenge = b"\x5B" * 32
    client = config_module.app.test_client()

    with client.session_transaction() as session:
        session["simple_credentials"] = [authenticator.stored_credential_entry()]
        session["authenticate_rp_id"] = "localhost"
        session["state"] = {"challenge": b64u(challenge), "user_verification": "discouraged"}

    response = _complete_simple_authentication(
        client, assertion_payload(authenticator, challenge=challenge, counter=1)
    )

    assert response.status_code == 400
    assert "expired" in response.get_json()["error"]


# --------------------------------------------------------------------------
# POSITIVE -- a fresh ceremony still works and leaves no state behind.
# --------------------------------------------------------------------------


def test_simple_ceremonies_succeed_back_to_back_and_clear_session_state(config_module, simple_module, simple_storage):
    authenticator = Authenticator()
    client = config_module.app.test_client()

    for counter in (1, 2):
        challenge = _begin_simple_authentication(client, authenticator)
        response = _complete_simple_authentication(
            client, assertion_payload(authenticator, challenge=challenge, counter=counter)
        )
        assert response.status_code == 200, response.get_json()
        assert response.get_json()["status"] == "OK"

        with client.session_transaction() as session:
            assert "state" not in session
            assert "authenticate_rp_id" not in session
            assert "simple_credentials" not in session


# --------------------------------------------------------------------------
# ADVANCED flow -- replays are reported, not rejected.
# --------------------------------------------------------------------------


def _advanced_begin(client, stored_entry, challenge=b"\x71" * 32):
    begin = client.post(
        "/api/advanced/authenticate/begin",
        json={
            "publicKey": {"challenge": {"$base64url": b64u(challenge)}},
            "__storedCredentials": [stored_entry],
        },
    )
    assert begin.status_code == 200, begin.get_json()
    return begin.get_json()


def _advanced_complete(client, stored_entry, assertion, challenge, **extra):
    return client.post(
        "/api/advanced/authenticate/complete",
        json={
            "publicKey": {"challenge": {"$base64url": b64u(challenge)}},
            "__storedCredentials": [stored_entry],
            "__assertion_response": assertion,
            **extra,
        },
        headers={"Origin": ORIGIN},
    )


def test_advanced_replayed_server_challenge_is_reported_as_replayed(config_module, advanced_module):
    authenticator = Authenticator()
    stored_entry = authenticator.stored_credential_entry(declared_algorithm=-7)
    client = config_module.app.test_client()

    body = _advanced_begin(client, stored_entry)
    challenge = unb64u(body["publicKey"]["challenge"])
    cookie_with_state = _snapshot_cookie(client)
    assertion = assertion_payload(authenticator, challenge=challenge, counter=1)

    first = _advanced_complete(client, stored_entry, assertion, challenge)
    assert first.status_code == 200, first.get_json()
    assert first.get_json()["challengeSource"] == "server-session"
    assert first.get_json()["challengeStatus"] == "fresh"

    _restore_cookie(client, cookie_with_state)
    replay = _advanced_complete(client, stored_entry, assertion, challenge)

    # Permissive: the request editor is not blocked ...
    assert replay.status_code == 200, replay.get_json()
    # ... but it is never told the challenge was fresh.
    assert replay.get_json()["challengeSource"] == "server-session"
    assert replay.get_json()["challengeStatus"] == "replayed"


def test_advanced_replay_is_reported_on_failure_responses_too(config_module, advanced_module):
    authenticator = Authenticator()
    stored_entry = authenticator.stored_credential_entry(declared_algorithm=-7)
    client = config_module.app.test_client()

    challenge = unb64u(_advanced_begin(client, stored_entry)["publicKey"]["challenge"])
    cookie_with_state = _snapshot_cookie(client)
    bad = assertion_payload(authenticator, challenge=challenge, valid_signature=False)

    first = _advanced_complete(client, stored_entry, bad, challenge)
    assert first.status_code == 400
    assert first.get_json()["challengeStatus"] == "fresh"

    _restore_cookie(client, cookie_with_state)
    replay = _advanced_complete(client, stored_entry, bad, challenge)
    assert replay.status_code == 400
    assert replay.get_json()["challengeStatus"] == "replayed"


def test_advanced_client_supplied_challenge_is_reported_as_not_tracked(config_module, advanced_module):
    authenticator = Authenticator()
    stored_entry = authenticator.stored_credential_entry(declared_algorithm=-7)
    challenge = b"\x72" * 32
    client = config_module.app.test_client()

    # No /begin: the request editor supplies its own state.
    response = _advanced_complete(
        client,
        stored_entry,
        assertion_payload(authenticator, challenge=challenge, counter=1),
        challenge,
        __session_state={"challenge": b64u(challenge), "user_verification": "discouraged"},
    )

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["challengeSource"] == "client-supplied"
    assert response.get_json()["challengeStatus"] == "not-tracked"


# The advanced flow burns its challenge before anything can fail, like the simple
# flow, and reports ``challengeStatus`` on every response -- registration too.


def _advanced_register_begin(client, challenge=b"\x73" * 32):
    from .ceremony_helpers import advanced_public_key_options

    begin = client.post("/api/advanced/register/begin", json={"publicKey": advanced_public_key_options(challenge=challenge)})
    assert begin.status_code == 200, begin.get_json()
    return begin.get_json()


def _advanced_register_complete(client, body, authenticator, **overrides):
    from .ceremony_helpers import advanced_public_key_options

    challenge = unb64u(body["publicKey"]["challenge"])
    payload = {
        "publicKey": advanced_public_key_options(challenge=challenge),
        "__credential_response": registration_payload(authenticator, challenge=challenge),
        **overrides,
    }
    return client.post("/api/advanced/register/complete", json=payload, headers={"Origin": ORIGIN})


def test_advanced_registration_reports_a_replayed_challenge(config_module, advanced_module, advanced_storage):
    authenticator = Authenticator()
    client = config_module.app.test_client()
    body = _advanced_register_begin(client)
    cookie_with_state = _snapshot_cookie(client)

    first = _advanced_register_complete(client, body, authenticator)
    assert first.status_code == 200, first.get_json()
    assert (first.get_json()["challengeSource"], first.get_json()["challengeStatus"]) == ("server-session", "fresh")

    _restore_cookie(client, cookie_with_state)
    replay = _advanced_register_complete(client, body, authenticator)

    # Reported, not rejected: the request editor is permissive.
    assert replay.status_code == 200, replay.get_json()
    assert replay.get_json()["challengeStatus"] == "replayed"


def test_an_advanced_registration_that_fails_early_still_burns_its_challenge(config_module, advanced_module, advanced_storage):
    authenticator = Authenticator()
    client = config_module.app.test_client()
    body = _advanced_register_begin(client)
    cookie_with_state = _snapshot_cookie(client)

    early = _advanced_register_complete(client, body, authenticator, __credential_response=None)
    assert early.status_code == 400
    assert early.get_json()["challengeStatus"] == "fresh"

    _restore_cookie(client, cookie_with_state)
    retry = _advanced_register_complete(client, body, authenticator)

    assert retry.status_code == 200, retry.get_json()
    assert retry.get_json()["challengeStatus"] == "replayed"


def test_an_advanced_authentication_that_fails_early_still_burns_its_challenge(config_module, advanced_module):
    authenticator = Authenticator()
    stored_entry = authenticator.stored_credential_entry(declared_algorithm=-7)
    client = config_module.app.test_client()
    challenge = unb64u(_advanced_begin(client, stored_entry)["publicKey"]["challenge"])
    cookie_with_state = _snapshot_cookie(client)

    # No assertion at all: refused before any credential or state is looked at.
    early = client.post(
        "/api/advanced/authenticate/complete",
        json={"publicKey": {"challenge": {"$base64url": b64u(challenge)}}},
        headers={"Origin": ORIGIN},
    )
    assert early.status_code == 400
    assert (early.get_json()["challengeSource"], early.get_json()["challengeStatus"]) == ("server-session", "fresh")

    _restore_cookie(client, cookie_with_state)
    retry = _advanced_complete(client, stored_entry, assertion_payload(authenticator, challenge=challenge), challenge)

    assert retry.status_code == 200, retry.get_json()
    assert retry.get_json()["challengeStatus"] == "replayed"
