"""signCount regression detection (WebAuthn L3 §7.2 step 21).

The simple flow must reject an assertion whose signature counter did not
increase, except when both stored and received counters are 0 (synced
passkeys), and must persist the new counter on success. The advanced request
editor must never reject on the counter but must report ``signCountStatus``.

Every assertion here is genuinely signed. The simple-flow tests run against the
real credential store, redirected to a temporary directory, so "persisted"
means read back from disk.
"""
from __future__ import annotations

import pytest

from server.app.storage import credentials as storage
from server.app.storage import github_mirror
from tests.app.entry_app import entry_app

from .ceremony_helpers import (
    ORIGIN,
    Authenticator,
    assertion_payload,
    authenticate_simple,
    b64u,
    register_simple,
    simple_complete_body,
    unb64u,
)

EMAIL = "user@example.com"


@pytest.fixture
def credential_store(tmp_path, monkeypatch):
    """Point the real credential store at a temporary directory."""

    monkeypatch.delenv("FIDO_SERVER_GCS_ENABLED", raising=False)
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_DIR", str(tmp_path / "credentials"))
    monkeypatch.setattr(github_mirror, "record_registration_event", lambda _event: None)

    def _stored_counter(credential_id: bytes):
        base = tmp_path / "credentials"
        session_dirs = [entry.name for entry in base.iterdir() if entry.is_dir()] if base.exists() else []
        assert len(session_dirs) == 1, session_dirs
        records = storage.readkey(EMAIL, session_id=session_dirs[0])
        for record in records:
            if bytes(record["credential_data"].credential_id) == credential_id:
                return record.get("sign_count")
        raise AssertionError("credential not found in the store")

    return _stored_counter


def _register(client, authenticator, *, counter):
    complete = register_simple(client, authenticator, counter=counter)
    assert complete.get_json()["storedCredential"]["signCount"] == counter


def _assert_cloned_rejection(response, authenticator):
    assert response.status_code == 400, response.get_json()
    body = response.get_json()
    assert body.get("status") != "OK"
    assert "cloned" in body["error"]
    assert body["signCountStatus"] == "regressed"
    assert body["failedCredentialId"] == b64u(authenticator.credential_id)


# --------------------------------------------------------------------------
# SIMPLE flow -- strict.
# --------------------------------------------------------------------------


def test_simple_sign_count_going_backwards_is_rejected(credential_store):
    authenticator = Authenticator()
    client = entry_app().test_client()
    _register(client, authenticator, counter=5)

    response = authenticate_simple(client, authenticator, counter=4)

    _assert_cloned_rejection(response, authenticator)
    # A rejected assertion does not move the stored counter.
    assert credential_store(authenticator.credential_id) == 5


def test_simple_sign_count_equal_to_stored_is_rejected(credential_store):
    authenticator = Authenticator()
    client = entry_app().test_client()
    _register(client, authenticator, counter=5)

    response = authenticate_simple(client, authenticator, counter=5)

    _assert_cloned_rejection(response, authenticator)


def test_simple_sign_count_dropping_to_zero_is_rejected(credential_store):
    """Only 0/0 is exempt; a counter that was non-zero may not fall back to 0."""

    authenticator = Authenticator()
    client = entry_app().test_client()
    _register(client, authenticator, counter=0)
    assert authenticate_simple(client, authenticator, counter=1).status_code == 200

    response = authenticate_simple(client, authenticator, counter=0)

    _assert_cloned_rejection(response, authenticator)


def test_simple_persisted_counter_is_what_the_next_assertion_is_compared_to(credential_store):
    """Replaying the counter of the previous *authentication* is caught.

    This fails if the new counter is not persisted, because the comparison
    would then still be against the registration-time value.
    """

    authenticator = Authenticator()
    client = entry_app().test_client()
    _register(client, authenticator, counter=1)

    assert authenticate_simple(client, authenticator, counter=10).status_code == 200

    response = authenticate_simple(client, authenticator, counter=9)

    _assert_cloned_rejection(response, authenticator)
    assert credential_store(authenticator.credential_id) == 10


def test_simple_client_supplied_sign_count_cannot_lower_the_stored_value(credential_store):
    """The browser's copy of signCount is attacker-controlled; the server's wins."""

    authenticator = Authenticator()
    client = entry_app().test_client()
    _register(client, authenticator, counter=5)

    response = authenticate_simple(client, authenticator, counter=3, client_sign_count=0)

    _assert_cloned_rejection(response, authenticator)


def test_simple_synced_passkey_reporting_zero_is_accepted(credential_store):
    authenticator = Authenticator()
    client = entry_app().test_client()
    _register(client, authenticator, counter=0)

    for _ in range(3):
        response = authenticate_simple(client, authenticator, counter=0)
        assert response.status_code == 200, response.get_json()
        assert response.get_json()["status"] == "OK"
        assert response.get_json()["signCount"] == 0

    assert credential_store(authenticator.credential_id) == 0


def test_simple_increasing_sign_count_succeeds_and_is_persisted(credential_store):
    authenticator = Authenticator()
    client = entry_app().test_client()
    _register(client, authenticator, counter=5)
    assert credential_store(authenticator.credential_id) == 5

    for counter in (6, 42):
        response = authenticate_simple(client, authenticator, counter=counter)
        assert response.status_code == 200, response.get_json()
        body = response.get_json()
        assert body["status"] == "OK"
        assert body["signCount"] == counter
        assert body["authenticatedCredentialId"] == b64u(authenticator.credential_id)
        assert credential_store(authenticator.credential_id) == counter


def test_simple_success_reports_the_counter_state(credential_store):
    zero = Authenticator()
    client = entry_app().test_client()
    _register(client, zero, counter=0)
    no_counter = authenticate_simple(client, zero, counter=0)

    counting = Authenticator()
    _register(client, counting, counter=5)
    increased = authenticate_simple(client, counting, counter=6)

    assert no_counter.status_code == 200, no_counter.get_json()
    assert increased.status_code == 200, increased.get_json()
    assert no_counter.get_json()["signCountStatus"] == "not-supported"
    assert increased.get_json()["signCountStatus"] == "ok"


def test_simple_counter_with_base64url_only_characters_is_read_correctly(credential_store):
    """authenticatorData is base64url; a standard-alphabet decode mishandles it.

    Counter 0xFBEFBE01 encodes its own bytes as "----AQ". The previous
    standard-base64 decode dropped or rejected such characters, so the counter
    was misread or silently omitted.
    """

    authenticator = Authenticator()
    client = entry_app().test_client()
    _register(client, authenticator, counter=0)

    counter = 0xFBEFBE01
    response = authenticate_simple(client, authenticator, counter=counter)

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["signCount"] == counter
    assert credential_store(authenticator.credential_id) == counter


def _in_the_standard_alphabet(assertion):
    """``assertion`` with its authenticatorData in standard base64: fido2 still reads it, the counter's reader does not."""

    auth_data = assertion["response"]["authenticatorData"]
    assert "-" in auth_data
    assertion["response"]["authenticatorData"] = auth_data.replace("-", "+").replace("_", "/")
    return assertion


def test_simple_authenticator_data_not_in_base64url_is_refused_its_counter_unread(credential_store):
    authenticator = Authenticator()
    client = entry_app().test_client()
    _register(client, authenticator, counter=0)
    entry = authenticator.stored_credential_entry()
    query = f"?email={EMAIL}"
    begin = client.post(f"/api/authenticate/begin{query}", json={"credentials": [entry]})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    assertion = _in_the_standard_alphabet(assertion_payload(authenticator, challenge=challenge, counter=0xFBEFBE01))

    response = client.post(
        f"/api/authenticate/complete{query}",
        json=simple_complete_body(assertion, [entry]),
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "The signature counter could not be read from the authenticator data, so authentication was rejected."
    }
    assert credential_store(authenticator.credential_id) == 0
    with client.session_transaction() as session_state:
        assert "simple_credentials_email" not in session_state


# --------------------------------------------------------------------------
# ADVANCED flow -- permissive, but reports the counter verdict honestly.
# --------------------------------------------------------------------------


def _advanced_authenticate(authenticator, *, stored_sign_count, counter, rewrite=lambda assertion: assertion):
    stored_entry = authenticator.stored_credential_entry(declared_algorithm=-7)
    if stored_sign_count is not None:
        stored_entry["signCount"] = stored_sign_count

    client = entry_app().test_client()
    begin = client.post(
        "/api/advanced/authenticate/begin",
        json={
            "publicKey": {"challenge": {"$base64url": b64u(b"\x61" * 32)}},
            "__storedCredentials": [stored_entry],
        },
    )
    assert begin.status_code == 200, begin.get_json()
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])

    return client.post(
        "/api/advanced/authenticate/complete",
        json={
            "publicKey": {"challenge": {"$base64url": b64u(challenge)}},
            "__storedCredentials": [stored_entry],
            "__assertion_response": rewrite(assertion_payload(authenticator, challenge=challenge, counter=counter)),
        },
        headers={"Origin": ORIGIN},
    )


@pytest.mark.parametrize(
    ("stored", "received"),
    [(10, 3), (10, 10), (7, 0)],
    ids=["backwards", "equal", "dropped-to-zero"],
)
def test_advanced_reports_regressed_without_rejecting(stored, received):
    authenticator = Authenticator()

    response = _advanced_authenticate(
        authenticator, stored_sign_count=stored, counter=received
    )

    # Not rejected: the signature genuinely verified ...
    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    assert body["status"] == "OK"
    assert body["signatureVerified"] is True
    assert body["signCount"] == received
    # ... but the counter verdict is reported, not hidden.
    assert body["signCountStatus"] == "regressed"


def test_advanced_reports_ok_for_an_increasing_counter():
    authenticator = Authenticator()

    response = _advanced_authenticate(
        authenticator, stored_sign_count=3, counter=4
    )

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["status"] == "OK"
    assert response.get_json()["signCountStatus"] == "ok"


@pytest.mark.parametrize("stored", [0, None], ids=["stored-zero", "stored-absent"])
def test_advanced_reports_not_supported_for_zero_counters(stored):
    authenticator = Authenticator()

    response = _advanced_authenticate(
        authenticator, stored_sign_count=stored, counter=0
    )

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["status"] == "OK"
    assert response.get_json()["signCountStatus"] == "not-supported"


def test_the_stored_counter_is_the_last_authentications(credential_store):
    authenticator = Authenticator()
    client = entry_app().test_client()
    _register(client, authenticator, counter=5)
    assert authenticate_simple(client, authenticator, counter=9).status_code == 200

    # Not 5, the counter the authenticator reported at registration.
    assert credential_store(authenticator.credential_id) == 9


def test_advanced_authenticator_data_not_in_base64url_reports_no_counter():
    response = _advanced_authenticate(
        Authenticator(), stored_sign_count=None, counter=0xFBEFBE01, rewrite=_in_the_standard_alphabet
    )

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["status"] == "OK"
    assert "signCount" not in response.get_json()
