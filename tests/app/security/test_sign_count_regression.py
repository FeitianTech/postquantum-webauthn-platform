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
from fido2.webauthn import AuthenticatorData

from server.app.routes.simple import stored_sign_count
from server.app.storage import credentials as storage
from server.app.storage import github_mirror
from tests.app import visitor_namespace
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
            if stored_sign_count.record_credential_id(record) == credential_id:
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


def test_an_authentication_keeps_a_record_stored_whole_as_its_counter_record(credential_store):
    authenticator = Authenticator()
    client = entry_app().test_client()
    _register(client, authenticator, counter=5)
    # As versions before the counter record kept it: the whole registration.
    namespace = visitor_namespace.of(client)
    registered = AuthenticatorData(authenticator.authenticator_data(counter=5))
    records, version = storage.read_for_update(EMAIL, session_id=namespace)
    whole = {
        "credential_data": registered.credential_data,
        "auth_data": registered,
        "sign_count": 5,
        "user_info": {"name": EMAIL, "user_handle": records[0]["user_handle"]},
        "registration_time": records[0]["registration_time"],
        "attestation_object": "o2NmbXRkbm9uZQ",
    }
    assert storage.save_if_unchanged(EMAIL, [whole], version, session_id=namespace)

    response = authenticate_simple(client, authenticator, counter=6)

    assert response.status_code == 200, response.get_json()
    assert storage.readkey(EMAIL, session_id=namespace) == [
        {
            "credential_id": authenticator.credential_id,
            "sign_count": 6,
            "registration_time": records[0]["registration_time"],
            "user_handle": records[0]["user_handle"],
        }
    ]


# --------------------------------------------------------------------------
# A SIMPLE credential in the ADVANCED authentication -- the tabs share the
# saved list; the Advanced tab writes nothing on the server.
# --------------------------------------------------------------------------


def _as_the_advanced_tab_sends(saved):
    """The entry the page sends the Advanced authentication for a saved record (``advanced-server-payload.js``)."""

    return {
        "credentialId": saved["credentialIdBase64Url"],
        "publicKey": saved["publicKey"],
        "aaguid": saved["aaguid"],
        "signCount": saved["signCount"],
        "algorithm": saved["publicKeyAlgorithm"],
        "authenticatorAttachment": saved.get("authenticatorAttachment"),
        # credProps.rk as the browser reported it, else null (``resident-key.js``).
        "resident": ((saved.get("clientExtensionOutputs") or {}).get("credProps") or {}).get("rk"),
    }


def _authenticate_in_advanced(client, authenticator, entry, *, counter):
    begin = client.post(
        "/api/advanced/authenticate/begin",
        json={"publicKey": {"challenge": {"$base64url": b64u(b"\x62" * 32)}}, "__storedCredentials": [entry]},
    )
    assert begin.status_code == 200, begin.get_json()
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    return client.post(
        "/api/advanced/authenticate/complete",
        json={
            "publicKey": {"challenge": {"$base64url": b64u(challenge)}},
            "__storedCredentials": [entry],
            "__assertion_response": assertion_payload(authenticator, challenge=challenge, counter=counter),
        },
        headers={"Origin": ORIGIN},
    )


def test_a_simple_credential_authenticates_in_advanced_and_simple_then_stores_the_latest_counter(credential_store):
    authenticator = Authenticator()
    client = entry_app().test_client()
    saved = register_simple(client, authenticator, counter=5).get_json()["storedCredential"]

    advanced = _authenticate_in_advanced(client, authenticator, _as_the_advanced_tab_sends(saved), counter=6)

    # The server read the record's key (the signature verified) and its counter (5, so 6 is ok).
    assert advanced.status_code == 200, advanced.get_json()
    body = advanced.get_json()
    assert body["status"] == "OK"
    assert body["signatureVerified"] is True
    assert body["signCount"] == 6
    assert body["signCountStatus"] == "ok"
    # The Simple tab's record on the server is left as it was ...
    assert credential_store(authenticator.credential_id) == 5

    # ... and the next Simple sign-in, the page's copy at 6, stores the authenticator's latest.
    simple = authenticate_simple(client, authenticator, counter=7, client_sign_count=6)
    assert simple.status_code == 200, simple.get_json()
    assert simple.get_json()["signCountStatus"] == "ok"
    assert credential_store(authenticator.credential_id) == 7


def test_a_simple_sign_in_refuses_the_counter_an_advanced_authentication_already_saw(credential_store):
    authenticator = Authenticator()
    client = entry_app().test_client()
    saved = register_simple(client, authenticator, counter=5).get_json()["storedCredential"]
    assert _authenticate_in_advanced(client, authenticator, _as_the_advanced_tab_sends(saved), counter=6).status_code == 200

    # The page's copy holds 6 once the Advanced authentication updated it: 6 again is a replay.
    response = authenticate_simple(client, authenticator, counter=6, client_sign_count=6)

    _assert_cloned_rejection(response, authenticator)
    assert credential_store(authenticator.credential_id) == 5
