"""``decoder.decode.ctap_classify``: which CTAP message a decoded map is, by its shape when no byte says."""
from __future__ import annotations

import hashlib

import pytest
from fido2.cose import CoseKey
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

from server.app.decoder.decode import ctap_classify as decode_ctap_classify

CLIENT_DATA_HASH = b"\x11" * 32
AUTH_DATA = bytes(
    AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        4,
        AttestedCredentialData.create(
            bytes(16), b"credential", CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})
        ),
    )
)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ({1: CLIENT_DATA_HASH, 2: {"id": "example.com"}, 3: {"id": b"u"}}, "make_credential_input"),
        ({1: "example.com", 2: CLIENT_DATA_HASH}, "get_assertion_input"),
        ({1: "packed", 2: AUTH_DATA, 3: {"alg": -7, "sig": b"\xaa"}}, "make_credential_output"),
        ({1: {"id": b"id"}, 2: AUTH_DATA, 3: b"\xaa" * 32}, "get_assertion_output"),
        # Text keys are some other map's: "rpId" is no GetAssertion member 1.
        ({"rpId": "example.com", "clientDataHash": "not-binary"}, "other"),
        ({"rpId": "example.com", 2: b"hash", "authData": bytes(37)}, "other"),
        # A byte-string 3 is a response's, so this is no GetAssertion request.
        ({"rpId": "example.com", 2: b"hash", 3: b"signature"}, "get_assertion_output"),
        ("not-a-map", "other"),
    ],
)
def test_a_map_without_a_prefix_byte_is_the_message_its_shape_is(value, message):
    assert decode_ctap_classify._classify_ctap_payload(value, None) == message


def test_a_shape_rule_given_no_map_matches_nothing():
    # The classifier asks only of maps; a direct call gives it anything else.
    assert decode_ctap_classify._looks_like_get_assertion_request("not-a-map") is False
