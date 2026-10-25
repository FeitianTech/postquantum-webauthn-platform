"""``routes.simple.deletion``: a Simple credential's record deleted from its username's
list, by compare-and-swap like the rest (the page's side is
``web/src/logic/credentials/delete-flow.js``)."""
from __future__ import annotations

import pytest

from server.app.routes.simple import stored_sign_count
from server.app.storage import credentials as storage_credentials
from tests.app import visitor_namespace
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import Authenticator, b64u, register_simple
from tests.app.storage.credential_seed import seed_records

EMAIL = "user@example.com"
FIRST = Authenticator(credential_id=b"\x01" * 32)
SECOND = Authenticator(credential_id=b"\x02" * 32)
UNREADABLE = {"error": "The stored credentials could not be read. Please try again."}


def _delete(client, credential_id: bytes, email: str = EMAIL):
    return client.delete(f"/api/simple/credentials/{b64u(credential_id)}?email={email}")


def _stored(client, email: str = EMAIL) -> list:
    return storage_credentials.readkey(email, session_id=visitor_namespace.of(client))


def _registered_twice():
    client = entry_app().test_client()
    register_simple(client, FIRST)
    register_simple(client, SECOND)
    return client


def test_a_credential_is_deleted_from_its_usernames_list_and_then_absent(credential_store):
    client = _registered_twice()

    response = _delete(client, FIRST.credential_id)

    assert response.get_json() == {"status": "deleted"}
    assert response.headers["Cache-Control"] == "no-store"
    assert "Cookie" in response.headers["Vary"]
    assert [stored_sign_count.record_credential_id(record) for record in _stored(client)] == [SECOND.credential_id]
    assert _delete(client, FIRST.credential_id).get_json() == {"status": "absent"}
    # Under another username nothing of it is.
    assert _delete(client, SECOND.credential_id, email="other@example.com").get_json() == {"status": "absent"}
    assert len(_stored(client)) == 1


def test_a_visitor_without_a_namespace_has_nothing_to_delete_and_is_given_none(credential_store):
    response = _delete(entry_app().test_client(), FIRST.credential_id)

    assert response.get_json() == {"status": "absent"}
    assert response.headers.getlist("Set-Cookie") == []


@pytest.mark.parametrize(
    ("path", "error"),
    [
        ("AQID", "Invalid username."),
        ("AQID?email=../escape", "Invalid username."),
        (f"not*base64url?email={EMAIL}", "Invalid credential ID."),
    ],
    ids=["no-username", "a-name-the-store-refuses", "an-id-that-is-no-base64url"],
)
def test_a_name_the_store_refuses_or_an_id_that_is_no_base64url_is_refused(credential_store, path, error):
    response = entry_app().test_client().delete(f"/api/simple/credentials/{path}")

    assert response.status_code == 400
    assert response.get_json() == {"status": "failed", "error": error}


def test_a_username_longer_than_the_begins_take_now_can_still_have_its_credential_deleted(credential_store):
    # Stored by a version that took names of more than 64 bytes.
    client = _registered_twice()
    namespace = visitor_namespace.of(client)
    long_name = "a" * 100 + "@example.com"
    seed_records(
        storage_credentials,
        long_name,
        [stored_sign_count.counter_record(b"\x05" * 32, 0, 1.0, b"handle")],
        session_id=namespace,
    )

    assert _delete(client, b"\x05" * 32, email=long_name).get_json() == {"status": "deleted"}
    assert storage_credentials.readkey(long_name, session_id=namespace) == []


def test_the_lists_other_records_stored_whole_are_kept_as_counter_records(credential_store):
    client = _registered_twice()
    namespace = visitor_namespace.of(client)
    records, version = storage_credentials.read_for_update(EMAIL, session_id=namespace)
    whole = [{"credential_data": "unreadable", "sign_count": 1}, {**records[1], "properties": {"kept": "whole"}}]
    assert storage_credentials.save_if_unchanged(EMAIL, [records[0], *whole], version, session_id=namespace)

    assert _delete(client, FIRST.credential_id).get_json() == {"status": "deleted"}

    # One whose ID cannot be read is kept as it is.
    assert _stored(client) == [whole[0], records[1]]


def test_a_list_that_changed_meanwhile_is_read_again(credential_store, monkeypatch):
    client = _registered_twice()
    saves = []
    real_save = storage_credentials.save_if_unchanged

    def _losing_once(*args, **kwargs):
        saves.append(args[0])
        return False if len(saves) == 1 else real_save(*args, **kwargs)

    monkeypatch.setattr(storage_credentials, "save_if_unchanged", _losing_once)

    assert _delete(client, FIRST.credential_id).get_json() == {"status": "deleted"}
    assert saves == [EMAIL, EMAIL]
    assert len(_stored(client)) == 1


def test_a_list_that_keeps_changing_keeps_the_credential_with_a_409(credential_store, monkeypatch):
    client = _registered_twice()
    monkeypatch.setattr(storage_credentials, "save_if_unchanged", lambda *_args, **_kwargs: False)

    response = _delete(client, FIRST.credential_id)

    assert response.status_code == 409
    assert response.get_json() == {
        "status": "failed",
        "error": "The stored credentials kept changing while this one was being deleted. Please try again.",
    }
    assert len(_stored(client)) == 2


@pytest.mark.parametrize(("lands", "status", "answer"), [
    (True, 200, {"status": "deleted"}),
    (False, 500, {"status": "failed", "error": "Unable to delete credential from server storage."}),
])
def test_a_save_that_raised_is_deleted_only_if_it_landed(credential_store, monkeypatch, lands, status, answer):
    client = _registered_twice()
    real_save = storage_credentials.save_if_unchanged

    def _raising(*args, **kwargs):
        if lands:
            real_save(*args, **kwargs)
        raise OSError("the reply was lost")

    monkeypatch.setattr(storage_credentials, "save_if_unchanged", _raising)

    response = _delete(client, FIRST.credential_id)

    assert (response.status_code, response.get_json()) == (status, answer)
    assert len(_stored(client)) == (1 if lands else 2)


def test_a_list_whose_save_raised_and_cannot_be_read_again_fails(credential_store, monkeypatch):
    client = _registered_twice()

    def _raising(*_args, **_kwargs):
        raise OSError("the store went away")

    monkeypatch.setattr(storage_credentials, "save_if_unchanged", _raising)
    monkeypatch.setattr(storage_credentials, "readkey", _raising)

    assert _delete(client, FIRST.credential_id).status_code == 500


def test_a_list_that_cannot_be_decoded_or_read_answers_503_and_is_kept(credential_store, monkeypatch, tmp_path):
    client = _registered_twice()
    [stored_file] = (tmp_path / "credentials").rglob(f"{EMAIL}_credential_data.json")
    stored_file.write_bytes(b"not a credential list")

    response = _delete(client, FIRST.credential_id)

    assert (response.status_code, response.get_json()) == (503, UNREADABLE)
    assert stored_file.read_bytes() == b"not a credential list"

    stored_file.unlink()
    stored_file.mkdir()
    assert (_delete(client, FIRST.credential_id).status_code, stored_file.is_dir()) == (503, True)
