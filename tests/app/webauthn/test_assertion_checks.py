"""``webauthn.assertion_checks``: what an assertion says beside what its registration kept."""
from __future__ import annotations

from server.app.webauthn import assertion_checks
from tests.app.security.ceremony_helpers import Authenticator, assertion_payload, b64u


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
