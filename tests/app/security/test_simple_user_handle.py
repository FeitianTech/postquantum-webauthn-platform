"""A Simple account's user handle: one per account, never the username, and stored as the
authenticator was given it.

Each registration's begin issues ``user.id``, an HMAC of the visitor's namespace and
the username (``routes/simple/account.py``), with the username as ``name`` and
``displayName``; its complete stores that id as the credential's user handle: in the
answer, the relying party's view and the server's record. Records stored before,
whose handle is the username's bytes, are read by their credential ID as ever.

A sign-in's userHandle, when it carries one, must be the one the account's record keeps
(WebAuthn L3 section 7.2 step 6), or the sign-in is refused; with no record, or one
stored before accounts had handles, none is compared.
"""
from __future__ import annotations

from server.app.storage import credentials as storage_credentials

from .. import visitor_namespace
from ..entry_app import entry_app
from .ceremony_helpers import (
    ORIGIN,
    SIMPLE_EMAIL,
    Authenticator,
    authenticate_simple,
    b64u,
    register_simple,
    registration_payload,
    unb64u,
)


def _begin(client, email: str) -> dict:
    begin = client.post(f"/api/register/begin?email={email}", json={"credentials": []})
    assert begin.status_code == 200, begin.get_json()
    return begin.get_json()["publicKey"]


def _register(client, email: str, authenticator: Authenticator) -> tuple[dict, dict]:
    """The options begin issued for ``email``, and complete's answer."""

    public_key = _begin(client, email)
    complete = client.post(
        f"/api/register/complete?email={email}",
        json=registration_payload(authenticator, challenge=unb64u(public_key["challenge"])),
        headers={"Origin": ORIGIN},
    )
    assert complete.status_code == 200, complete.get_json()
    return public_key, complete.get_json()


def test_two_usernames_on_one_authenticator_get_two_user_handles_named_by_their_usernames(credential_store):
    client = entry_app().test_client()
    authenticator = Authenticator()

    alice, _ = _register(client, "alice@example.com", authenticator)
    bob, _ = _register(client, "bob@example.com", authenticator)

    assert alice["user"]["id"] != bob["user"]["id"]
    assert (alice["user"]["name"], alice["user"]["displayName"]) == ("alice@example.com", "alice@example.com")
    assert (bob["user"]["name"], bob["user"]["displayName"]) == ("bob@example.com", "bob@example.com")


def test_one_username_registering_again_keeps_its_user_handle(credential_store):
    client = entry_app().test_client()

    first, _ = _register(client, SIMPLE_EMAIL, Authenticator(credential_id=b"\x01" * 32))
    second, _ = _register(client, SIMPLE_EMAIL, Authenticator(credential_id=b"\x02" * 32))

    assert first["user"]["id"] == second["user"]["id"]


def test_the_stored_user_handle_is_the_one_the_authenticator_was_given(credential_store):
    client = entry_app().test_client()

    public_key, answer = _register(client, SIMPLE_EMAIL, Authenticator())

    handle = public_key["user"]["id"]
    assert len(unb64u(handle)) == 32
    assert SIMPLE_EMAIL.encode() not in unb64u(handle)
    assert answer["storedCredential"]["userHandle"] == handle
    assert answer["relyingParty"]["userHandle"]["base64url"] == handle
    [record] = storage_credentials.readkey(SIMPLE_EMAIL, session_id=visitor_namespace.of(client))
    assert record["user_handle"] == unb64u(handle)


def test_the_same_username_in_another_visitors_namespace_gets_another_user_handle(credential_store):
    one, another = entry_app().test_client(), entry_app().test_client()

    assert _begin(one, SIMPLE_EMAIL)["user"]["id"] != _begin(another, SIMPLE_EMAIL)["user"]["id"]


def test_a_credential_stored_with_the_username_as_its_user_handle_still_authenticates(credential_store):
    client = entry_app().test_client()
    authenticator = Authenticator()
    register_simple(client, authenticator, counter=1)
    # As records were stored before: the username's bytes as the user handle.
    namespace = visitor_namespace.of(client)
    records, version = storage_credentials.read_for_update(SIMPLE_EMAIL, session_id=namespace)
    records[0]["user_handle"] = SIMPLE_EMAIL.encode()
    assert storage_credentials.save_if_unchanged(SIMPLE_EMAIL, records, version, session_id=namespace)

    response = authenticate_simple(client, authenticator, counter=2)

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["signCount"] == 2


def _stored_user_handle(client) -> bytes:
    [record] = storage_credentials.readkey(SIMPLE_EMAIL, session_id=visitor_namespace.of(client))
    return record["user_handle"]


def _rewrite_records(client, change) -> None:
    namespace = visitor_namespace.of(client)
    records, version = storage_credentials.read_for_update(SIMPLE_EMAIL, session_id=namespace)
    assert storage_credentials.save_if_unchanged(SIMPLE_EMAIL, change(records), version, session_id=namespace)


def test_a_sign_in_whose_user_handle_is_the_accounts_is_accepted_and_says_so(credential_store):
    client = entry_app().test_client()
    authenticator = Authenticator()
    register_simple(client, authenticator, counter=1)

    matched = authenticate_simple(client, authenticator, counter=2, user_handle=_stored_user_handle(client))
    absent = authenticate_simple(client, authenticator, counter=3)

    assert (matched.status_code, matched.get_json()["userHandleStatus"]) == (200, "match")
    assert (absent.status_code, absent.get_json()["userHandleStatus"]) == (200, "absent")


def test_a_sign_in_whose_user_handle_is_another_accounts_is_refused_before_its_counter_is_kept(credential_store):
    client = entry_app().test_client()
    authenticator = Authenticator()
    register_simple(client, authenticator, counter=1)

    refused = authenticate_simple(client, authenticator, counter=5, user_handle=b"\x22" * 32)
    accepted = authenticate_simple(client, authenticator, counter=2)

    assert refused.status_code == 400
    assert refused.get_json() == {
        "error": "The user handle the authenticator returned is not this account's, so authentication was rejected.",
        "failedCredentialId": b64u(authenticator.credential_id),
        "assertionErrors": ["user_handle_mismatch"],
        "userHandleStatus": "mismatch",
    }
    assert (accepted.status_code, accepted.get_json()["signCountStatus"]) == (200, "ok")


def test_a_credential_stored_with_the_username_as_its_user_handle_compares_none(credential_store):
    client = entry_app().test_client()
    authenticator = Authenticator()
    register_simple(client, authenticator, counter=1)

    def _as_stored_before(records):
        records[0]["user_handle"] = SIMPLE_EMAIL.encode()
        return records

    _rewrite_records(client, _as_stored_before)
    # What such a registration gave its authenticator.
    response = authenticate_simple(client, authenticator, counter=2, user_handle=b"user_id")

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["userHandleStatus"] == "not-compared"


def test_without_the_servers_record_no_user_handle_is_compared(credential_store):
    client = entry_app().test_client()
    authenticator = Authenticator()
    register_simple(client, authenticator, counter=1)
    _rewrite_records(client, lambda records: [])

    response = authenticate_simple(client, authenticator, counter=2, user_handle=b"\x22" * 32)

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["userHandleStatus"] == "not-compared"
