"""A Simple account's user handle: one per account, never the username, and stored as the
authenticator was given it.

Each registration's begin issues ``user.id``, an HMAC of the visitor's namespace and
the username (``routes/simple/account.py``), with the username as ``name`` and
``displayName``; its complete stores that id as the credential's user handle: in the
answer, the relying party's view and the server's record. Records stored before,
whose handle is the username's bytes, are read by their credential ID as ever.
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
    assert record["user_info"]["user_handle"] == unb64u(handle)


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
    records[0]["user_info"]["user_handle"] = SIMPLE_EMAIL.encode()
    assert storage_credentials.save_if_unchanged(SIMPLE_EMAIL, records, version, session_id=namespace)

    response = authenticate_simple(client, authenticator, counter=2)

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["signCount"] == 2
