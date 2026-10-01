"""Tests for which saved credentials an advanced authentication may use."""
from __future__ import annotations

import pytest

from server.app.routes.advanced import assertion_credentials
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import Authenticator, b64u

from .assertion_ceremony import begin


def test_allow_list_entries_that_name_no_saved_credential_are_passed_over():
    authenticator = Authenticator()

    response = begin(
        entry_app().test_client(),
        [authenticator.stored_credential_entry()],
        allowCredentials=[
            {"type": "not-public-key", "id": authenticator.credential_id.hex()},
            {"type": "public-key", "id": "not hex"},
            {"type": "public-key", "id": 7},
            {"type": "public-key", "id": authenticator.credential_id.hex()},
        ],
    )

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
