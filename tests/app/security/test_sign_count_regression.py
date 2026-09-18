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

import os

import pytest

from .ceremony_helpers import (
    ORIGIN,
    Authenticator,
    assertion_payload,
    b64u,
    registration_payload,
    unb64u,
)

EMAIL = "user@example.com"


@pytest.fixture
def credential_store(simple_module, tmp_path, monkeypatch, device_logs_module):
    """Point the real credential store at a temporary directory."""

    storage = pytest.importorskip("server.app.storage")
    monkeypatch.delenv("FIDO_SERVER_GCS_ENABLED", raising=False)
    monkeypatch.setattr(storage, "_LOCAL_CREDENTIAL_BASE", str(tmp_path / "credentials"))
    monkeypatch.setattr(storage, "_LEGACY_LOCAL_CREDENTIAL_BASE", str(tmp_path / "legacy"))
    monkeypatch.setattr(device_logs_module, "record_registration_event", lambda _event: None)

    def _stored_counter(credential_id: bytes):
        base = tmp_path / "credentials"
        session_dirs = [entry for entry in os.listdir(base)] if base.exists() else []
        assert len(session_dirs) == 1, session_dirs
        records = storage.readkey(EMAIL, session_id=session_dirs[0])
        for record in records:
            if bytes(record["credential_data"].credential_id) == credential_id:
                return record.get("sign_count")
        raise AssertionError("credential not found in the store")

    return _stored_counter


def _register(client, authenticator, *, counter):
    begin = client.post(f"/api/register/begin?email={EMAIL}", json={"credentials": []})
    assert begin.status_code == 200
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    complete = client.post(
        f"/api/register/complete?email={EMAIL}",
        json=registration_payload(authenticator, challenge=challenge, counter=counter),
        headers={"Origin": ORIGIN},
    )
    assert complete.status_code == 200, complete.get_json()
    assert complete.get_json()["storedCredential"]["signCount"] == counter


def _authenticate(client, authenticator, *, counter, client_sign_count=None):
    entry = authenticator.stored_credential_entry()
    if client_sign_count is not None:
        entry["signCount"] = client_sign_count
    begin = client.post(f"/api/authenticate/begin?email={EMAIL}", json={"credentials": [entry]})
    assert begin.status_code == 200, begin.get_json()
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    return client.post(
        f"/api/authenticate/complete?email={EMAIL}",
        json=assertion_payload(authenticator, challenge=challenge, counter=counter),
        headers={"Origin": ORIGIN},
    )


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


def test_simple_sign_count_going_backwards_is_rejected(config_module, credential_store):
    authenticator = Authenticator()
    client = config_module.app.test_client()
    _register(client, authenticator, counter=5)

    response = _authenticate(client, authenticator, counter=4)

    _assert_cloned_rejection(response, authenticator)
    # A rejected assertion does not move the stored counter.
    assert credential_store(authenticator.credential_id) == 5


def test_simple_sign_count_equal_to_stored_is_rejected(config_module, credential_store):
    authenticator = Authenticator()
    client = config_module.app.test_client()
    _register(client, authenticator, counter=5)

    response = _authenticate(client, authenticator, counter=5)

    _assert_cloned_rejection(response, authenticator)


def test_simple_sign_count_dropping_to_zero_is_rejected(config_module, credential_store):
    """Only 0/0 is exempt; a counter that was non-zero may not fall back to 0."""

    authenticator = Authenticator()
    client = config_module.app.test_client()
    _register(client, authenticator, counter=0)
    assert _authenticate(client, authenticator, counter=1).status_code == 200

    response = _authenticate(client, authenticator, counter=0)

    _assert_cloned_rejection(response, authenticator)


def test_simple_persisted_counter_is_what_the_next_assertion_is_compared_to(
    config_module, credential_store
):
    """Replaying the counter of the previous *authentication* is caught.

    This fails if the new counter is not persisted, because the comparison
    would then still be against the registration-time value.
    """

    authenticator = Authenticator()
    client = config_module.app.test_client()
    _register(client, authenticator, counter=1)

    assert _authenticate(client, authenticator, counter=10).status_code == 200

    response = _authenticate(client, authenticator, counter=9)

    _assert_cloned_rejection(response, authenticator)
    assert credential_store(authenticator.credential_id) == 10


def test_simple_client_supplied_sign_count_cannot_lower_the_stored_value(
    config_module, credential_store
):
    """The browser's copy of signCount is attacker-controlled; the server's wins."""

    authenticator = Authenticator()
    client = config_module.app.test_client()
    _register(client, authenticator, counter=5)

    response = _authenticate(client, authenticator, counter=3, client_sign_count=0)

    _assert_cloned_rejection(response, authenticator)


def test_simple_synced_passkey_reporting_zero_is_accepted(config_module, credential_store):
    authenticator = Authenticator()
    client = config_module.app.test_client()
    _register(client, authenticator, counter=0)

    for _ in range(3):
        response = _authenticate(client, authenticator, counter=0)
        assert response.status_code == 200, response.get_json()
        assert response.get_json()["status"] == "OK"
        assert response.get_json()["signCount"] == 0

    assert credential_store(authenticator.credential_id) == 0


def test_simple_increasing_sign_count_succeeds_and_is_persisted(config_module, credential_store):
    authenticator = Authenticator()
    client = config_module.app.test_client()
    _register(client, authenticator, counter=5)
    assert credential_store(authenticator.credential_id) == 5

    for counter in (6, 42):
        response = _authenticate(client, authenticator, counter=counter)
        assert response.status_code == 200, response.get_json()
        body = response.get_json()
        assert body["status"] == "OK"
        assert body["signCount"] == counter
        assert body["authenticatedCredentialId"] == b64u(authenticator.credential_id)
        assert credential_store(authenticator.credential_id) == counter


def test_simple_counter_with_base64url_only_characters_is_read_correctly(
    config_module, credential_store
):
    """authenticatorData is base64url; a standard-alphabet decode mishandles it.

    Counter 0xFBEFBE01 encodes its own bytes as "----AQ". The previous
    standard-base64 decode dropped or rejected such characters, so the counter
    was misread or silently omitted.
    """

    authenticator = Authenticator()
    client = config_module.app.test_client()
    _register(client, authenticator, counter=0)

    counter = 0xFBEFBE01
    response = _authenticate(client, authenticator, counter=counter)

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["signCount"] == counter
    assert credential_store(authenticator.credential_id) == counter


# --------------------------------------------------------------------------
# ADVANCED flow -- permissive, but reports the counter verdict honestly.
# --------------------------------------------------------------------------


def _advanced_authenticate(config_module, authenticator, *, stored_sign_count, counter):
    stored_entry = authenticator.stored_credential_entry(declared_algorithm=-7)
    if stored_sign_count is not None:
        stored_entry["signCount"] = stored_sign_count

    client = config_module.app.test_client()
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
            "__assertion_response": assertion_payload(
                authenticator, challenge=challenge, counter=counter
            ),
        },
        headers={"Origin": ORIGIN},
    )


@pytest.mark.parametrize(
    ("stored", "received"),
    [(10, 3), (10, 10), (7, 0)],
    ids=["backwards", "equal", "dropped-to-zero"],
)
def test_advanced_reports_regressed_without_rejecting(
    config_module, advanced_module, stored, received
):
    authenticator = Authenticator()

    response = _advanced_authenticate(
        config_module, authenticator, stored_sign_count=stored, counter=received
    )

    # Not rejected: the signature genuinely verified ...
    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    assert body["status"] == "OK"
    assert body["signatureVerified"] is True
    assert body["signCount"] == received
    # ... but the counter verdict is reported, not hidden.
    assert body["signCountStatus"] == "regressed"


def test_advanced_reports_ok_for_an_increasing_counter(config_module, advanced_module):
    authenticator = Authenticator()

    response = _advanced_authenticate(
        config_module, authenticator, stored_sign_count=3, counter=4
    )

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["status"] == "OK"
    assert response.get_json()["signCountStatus"] == "ok"


@pytest.mark.parametrize("stored", [0, None], ids=["stored-zero", "stored-absent"])
def test_advanced_reports_not_supported_for_zero_counters(
    config_module, advanced_module, stored
):
    authenticator = Authenticator()

    response = _advanced_authenticate(
        config_module, authenticator, stored_sign_count=stored, counter=0
    )

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["status"] == "OK"
    assert response.get_json()["signCountStatus"] == "not-supported"
