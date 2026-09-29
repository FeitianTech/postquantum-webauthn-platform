"""``webauthn.assertion_hash``: an assertion checked over clientDataJSON hashed another way.

Real keys and signatures, and fido2's own ``Fido2Server.authenticate_complete``
doing the checking: the tests change only which hash the authenticator signed.
"""
from __future__ import annotations

import hashlib

import pytest

from fido2.server import Fido2Server
from fido2.webauthn import AttestedCredentialData, PublicKeyCredentialRpEntity
from server.app.webauthn import assertion_hash
from tests.app.security.ceremony_helpers import (
    ORIGIN,
    RP_ID,
    Authenticator,
    b64u,
    client_data,
)

CHALLENGE = b"\x3c" * 32


def _server() -> Fido2Server:
    return Fido2Server(PublicKeyCredentialRpEntity(name="Hash test", id=RP_ID), verify_origin=lambda origin: origin == ORIGIN)


def _assertion(authenticator: Authenticator, digest, *, origin: str = ORIGIN) -> dict:
    data = client_data(challenge=CHALLENGE, ceremony_type="webauthn.get", origin=origin)
    auth_data = authenticator.authenticator_data(rp_id=RP_ID, counter=1, include_credential=False)
    signature = authenticator.sign(auth_data + digest(data).digest())
    return {
        "id": b64u(authenticator.credential_id),
        "rawId": b64u(authenticator.credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64u(data),
            "authenticatorData": b64u(auth_data),
            "signature": b64u(signature),
        },
        "clientExtensionResults": {},
    }


def _ceremony(authenticator: Authenticator):
    credential = AttestedCredentialData.create(b"\x00" * 16, authenticator.credential_id, authenticator.cose_key)
    server = _server()
    _options, state = server.authenticate_begin([credential], challenge=CHALLENGE)
    return server, state, [credential]


@pytest.mark.parametrize("algorithm", sorted(set(assertion_hash.HASH_ALGORITHMS) - {"SHA-256"}))
def test_an_assertion_signed_over_another_hash_verifies_with_that_hash(algorithm):
    authenticator = Authenticator()
    server, state, credentials = _ceremony(authenticator)
    response = _assertion(authenticator, assertion_hash.HASH_ALGORITHMS[algorithm])

    verified = server.authenticate_complete(state, credentials, assertion_hash.response_hashed_with(response, algorithm))

    assert verified.credential_id == authenticator.credential_id
    # The same response checked as WebAuthn defines it does not verify.
    with pytest.raises(ValueError, match="Invalid signature"):
        server.authenticate_complete(state, credentials, response)


def test_sha_256_leaves_the_response_as_it_came():
    authenticator = Authenticator()
    server, state, credentials = _ceremony(authenticator)
    response = _assertion(authenticator, hashlib.sha256)

    assert assertion_hash.response_hashed_with(response, "SHA-256") is response
    assert server.authenticate_complete(state, credentials, response).credential_id == authenticator.credential_id


def test_a_signature_over_another_hash_than_the_chosen_one_fails():
    authenticator = Authenticator(key_type="ed25519")
    server, state, credentials = _ceremony(authenticator)
    response = _assertion(authenticator, hashlib.sha512)

    with pytest.raises(ValueError, match="Invalid signature"):
        server.authenticate_complete(state, credentials, assertion_hash.response_hashed_with(response, "SHA-384"))


def test_an_unknown_algorithm_is_reported_only_after_fidos_own_checks():
    authenticator = Authenticator()
    server, state, credentials = _ceremony(authenticator)

    wrong_origin = _assertion(authenticator, hashlib.sha256, origin="https://elsewhere.example")
    with pytest.raises(ValueError, match="Invalid origin"):
        server.authenticate_complete(state, credentials, assertion_hash.response_hashed_with(wrong_origin, "MD5"))

    response = _assertion(authenticator, hashlib.sha256)
    with pytest.raises(ValueError, match="Unsupported hash algorithm: MD5"):
        server.authenticate_complete(state, credentials, assertion_hash.response_hashed_with(response, "MD5"))


def test_hash_with_algorithm_matches_hashlib_and_refuses_the_rest():
    for name, function in assertion_hash.HASH_ALGORITHMS.items():
        assert assertion_hash.hash_with_algorithm(b"client data", name) == function(b"client data").digest()
    with pytest.raises(ValueError, match="Unsupported hash algorithm: sha256"):
        assertion_hash.hash_with_algorithm(b"client data", "sha256")


def test_a_response_that_does_not_parse_raises_before_the_server():
    with pytest.raises((KeyError, TypeError, ValueError)):
        assertion_hash.response_hashed_with({"id": "AQ", "response": {}}, "SHA-512")
