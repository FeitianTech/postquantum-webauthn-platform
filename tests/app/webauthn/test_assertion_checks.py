"""``webauthn.assertion_checks``: what an assertion says beside what its registration kept."""
from __future__ import annotations

import hashlib

import pytest
from fido2.webauthn import AuthenticatorData

from server.app.webauthn import assertion_checks
from tests.app.security.ceremony_helpers import (
    FLAG_BE,
    FLAG_BS,
    FLAG_UP,
    Authenticator,
    assertion_payload,
    b64u,
)


def test_an_assertion_gives_its_authenticator_data_and_user_handle():
    response = assertion_payload(Authenticator(), challenge=b"\x01" * 32, counter=7, user_handle=b"handle")

    parts = assertion_checks.assertion_parts(response)

    assert (parts.auth_data.counter, parts.user_handle) == (7, b"handle")


def test_an_assertion_without_a_user_handle_gives_none():
    response = assertion_payload(Authenticator(), challenge=b"\x01" * 32)

    assert assertion_checks.assertion_parts(response).user_handle is None
    response["response"]["userHandle"] = None
    assert assertion_checks.assertion_parts(response).user_handle is None
    response["response"]["userHandle"] = ""
    assert assertion_checks.assertion_parts(response).user_handle is None


def test_what_does_not_read_is_none():
    assert assertion_checks.assertion_parts(None) == (None, None)
    assert assertion_checks.assertion_parts({"response": "not a mapping"}) == (None, None)
    assert assertion_checks.assertion_parts({"response": {"authenticatorData": b64u(b"short")}}) == (None, None)
    assert assertion_checks.assertion_parts({"response": {"authenticatorData": "not base64url!"}}) == (None, None)


@pytest.mark.parametrize(
    ("flags", "registered", "errors", "warnings"),
    [
        (0, None, [], []),
        (FLAG_BE, True, [], []),
        (FLAG_BE | FLAG_BS, True, [], []),
        (0, False, [], []),
        (FLAG_BS, None, ["backup_state_without_eligibility"], []),
        (0, True, [], ["backup_eligibility_changed: set at registration, not set now"]),
        (FLAG_BE, False, [], ["backup_eligibility_changed: not set at registration, set now"]),
        (FLAG_BS, True, ["backup_state_without_eligibility"], ["backup_eligibility_changed: set at registration, not set now"]),
        # Only a flag the record kept is compared.
        (FLAG_BE, "true", [], []),
    ],
)
def test_backed_up_needs_backup_eligible_and_backup_eligibility_is_the_registrations(flags, registered, errors, warnings):
    auth_data = AuthenticatorData.create(hashlib.sha256(b"localhost").digest(), FLAG_UP | flags, 1)

    assert assertion_checks.backup_findings(auth_data, registered) == (errors, warnings)
