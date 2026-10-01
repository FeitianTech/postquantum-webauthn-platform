"""Tests for the attestation checks advanced register complete runs."""
from __future__ import annotations

from server.app.routes.advanced import registration_attestation
from tests.app.security.ceremony_helpers import (
    ORIGIN,
    RP_ID,
    Authenticator,
    advanced_public_key_options,
    registration_payload,
)

_CHALLENGE = b"\x73" * 32


def _checks(make_app, stored_original_request):
    response = registration_payload(Authenticator(), challenge=_CHALLENGE)
    with make_app().test_request_context("/", base_url=ORIGIN):
        return registration_attestation.check_attestation(
            response=response,
            state_ctx={
                "state": None,
                "storedOriginalRequest": stored_original_request,
                "authData": None,
                "resolvedRpId": RP_ID,
            },
            public_key=advanced_public_key_options(challenge=_CHALLENGE),
        )


def test_the_challenge_is_checked_against_the_options_begin_kept(make_app):
    kept = {"publicKey": advanced_public_key_options(challenge=b"\x01" * 32)}

    checks = _checks(make_app, kept)

    assert checks["client_data"]["challenge_matches"] is False
    assert "challenge_mismatch" in checks["errors"]


def test_without_usable_options_from_begin_the_requests_are_checked(make_app):
    for kept in (None, {"publicKey": "not an object"}):
        checks = _checks(make_app, kept)

        assert checks["client_data"]["challenge_matches"] is True
        assert checks["errors"] == []
