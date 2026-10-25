"""Simple usernames are compared exactly, after the trim the page and the server share:
"Alice" and "alice" are two accounts, from the user handle to the stored list, the
counter check, the delete and the cap.

On the in-memory bucket: Cloud Storage's names are case-sensitive, as production's
are. A case-insensitive disk (macOS's default) gives both names one local file,
where records are still told apart by credential ID (docs/STORAGE.md).
"""
from __future__ import annotations

import pytest

from server.app.config import request_limits
from server.app.routes.simple import stored_sign_count
from server.app.storage import credentials as storage_credentials
from server.app.storage import github_mirror
from tests.app import visitor_namespace
from tests.app.security.ceremony_helpers import (
    Authenticator,
    authenticate_simple,
    b64u,
    register_simple,
)
from tests.app.storage import fake_gcs

UPPER = Authenticator(credential_id=b"\x0a" * 32)
LOWER = Authenticator(credential_id=b"\x0b" * 32)


@pytest.fixture
def client(monkeypatch, make_app):
    """A visitor whose stores are on the in-memory bucket, keeping one credential per username."""

    fake_gcs.install(monkeypatch, "every store")
    monkeypatch.setattr(github_mirror, "record_registration_event", lambda _event: None)
    return make_app({request_limits.SIMPLE_CREDENTIALS_PER_USERNAME_KEY: 1}).test_client()


def _ids(client, username: str) -> list:
    records = storage_credentials.readkey(username, session_id=visitor_namespace.of(client))
    return [stored_sign_count.record_credential_id(record) for record in records]


def test_alice_and_alice_in_lower_case_are_two_accounts(client):
    upper = register_simple(client, UPPER, counter=5, email="Alice").get_json()["storedCredential"]
    # The cap counts each username's own list: Alice's one credential leaves alice's empty.
    lower = register_simple(client, LOWER, counter=5, email="alice").get_json()["storedCredential"]

    assert (upper["email"], lower["email"]) == ("Alice", "alice")
    assert upper["userHandle"] != lower["userHandle"]
    assert (_ids(client, "Alice"), _ids(client, "alice")) == ([UPPER.credential_id], [LOWER.credential_id])


def test_the_counter_check_and_the_delete_read_the_named_accounts_list_alone(client):
    register_simple(client, UPPER, counter=5, email="Alice")
    register_simple(client, LOWER, counter=5, email="alice")

    # Sent as alice's, Alice's credential has no stored counter there: the browser's alone is checked.
    assert authenticate_simple(client, UPPER, counter=3, email="alice").status_code == 200
    refused = authenticate_simple(client, UPPER, counter=3, email="Alice")
    assert (refused.status_code, refused.get_json()["signCountStatus"]) == (400, "regressed")

    path = f"/api/simple/credentials/{b64u(UPPER.credential_id)}"
    assert client.delete(f"{path}?email=alice").get_json() == {"status": "absent"}
    assert client.delete(f"{path}?email=Alice").get_json() == {"status": "deleted"}
    assert (_ids(client, "Alice"), _ids(client, "alice")) == ([], [LOWER.credential_id])
