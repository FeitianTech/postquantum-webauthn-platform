"""Tests for which saved credentials an advanced authentication may use."""
from __future__ import annotations

import pytest

from server.app.routes.advanced import assertion_credentials
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import (
    Authenticator,
    assertion_payload,
    b64u,
    unb64u,
)

from .assertion_ceremony import begin, complete


def test_allow_list_entries_that_name_no_saved_credential_are_passed_over():
    authenticator = Authenticator()

    response = begin(
        entry_app().test_client(),
        [authenticator.stored_credential_entry()],
        allowCredentials=[
            {"type": "not-public-key", "id": authenticator.credential_id.hex()},
            {"type": "public-key", "id": "not hex"},
            {"type": "public-key", "id": 7},
            {"type": "public-key", "id": {"$hex": "zz"}},
            {"type": "public-key", "id": {"$base64url": "%%"}},
            {"type": "public-key", "id": authenticator.credential_id.hex()},
        ],
    )

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["publicKey"]["allowCredentials"] == [
        {"id": b64u(authenticator.credential_id), "type": "public-key"}
    ]


def test_a_credential_saved_twice_is_offered_once():
    authenticator = Authenticator()
    entry = authenticator.stored_credential_entry()

    # An allow list naming no saved credential offers every saved one instead.
    response = begin(entry_app().test_client(), [entry, entry], allowCredentials=[{"type": "public-key", "id": "00" * 16}])

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["publicKey"]["allowCredentials"] == [
        {"id": b64u(authenticator.credential_id), "type": "public-key"}
    ]


def test_a_record_without_credential_id_bytes_is_never_offered():
    records = [{"id": "not bytes", "data": "unread"}, {"id": b"\x01", "data": "offered"}]

    assert assertion_credentials.select_begin_credentials(records, {}, []) == (["offered"], [], True)


@pytest.mark.parametrize(
    ("resident_records", "resident_key_only", "hints", "error"),
    [
        ([], False, [], "No matching credentials found. Please register first."),
        ([], False, ["platform"], "No credentials matched the selected hints."),
        ([{}], True, [], "No resident key credentials are available."),
        ([{}], True, ["platform"], "No resident key credentials matched the selected hints."),
    ],
)
def test_begin_says_why_no_credential_can_be_offered(make_app, resident_records, resident_key_only, hints, error):
    with make_app().test_request_context():
        response, status = assertion_credentials.begin_selection_error([], resident_records, resident_key_only, hints)

        assert status == 404
        assert response.get_json()["error"].startswith(error)
        assert assertion_credentials.begin_selection_error(["offered"], resident_records, resident_key_only, hints) is None


@pytest.mark.parametrize(("resident", "refused"), [(False, True), (None, False), (True, False)])
def test_only_a_record_that_says_it_is_not_discoverable_fails_a_discoverable_only_ceremony(resident, refused):
    record = {"resident": resident}

    error = assertion_credentials.non_discoverable_error(True, record, b"\x01")

    assert (error is not None) is refused
    if refused:
        assert error["failedCredentialId"] == "AQ"


def test_a_credential_whose_discoverability_is_unknown_answers_a_ceremony_without_an_allow_list():
    authenticator = Authenticator()
    entry = authenticator.stored_credential_entry()
    del entry["resident"]
    client = entry_app().test_client()
    challenge = unb64u(begin(client, [entry]).get_json()["publicKey"]["challenge"])

    response = complete(client, [entry], assertion_payload(authenticator, challenge=challenge))

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["verified"] is True
