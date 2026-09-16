"""Fix 2 -- a failed signature check may never be reported as ``status: OK``.

The advanced authentication handler used to substring-match the verification
error and, when the CLIENT-DECLARED algorithm fell outside the known-name map,
return ``{"status": "OK"}`` without verifying anything at all.

The declared ``algorithm`` field is independent of the credential's own COSE
key label 3, so a real key plus ``"algorithm": -12345`` reached that bypass.
"""
from __future__ import annotations

from .ceremony_helpers import (
    ORIGIN,
    Authenticator,
    assertion_payload,
    b64u,
    unb64u,
)

CUSTOM_ALGORITHM = -12345


def _authenticate(client, *, stored_entry, assertion, challenge):
    """Drive the advanced authentication ceremony end to end."""

    begin = client.post(
        "/api/advanced/authenticate/begin",
        json={
            "publicKey": {"challenge": {"$base64url": b64u(challenge)}},
            "__storedCredentials": [stored_entry],
        },
    )
    assert begin.status_code == 200, begin.get_json()
    body = begin.get_json()
    server_challenge = unb64u(body["publicKey"]["challenge"])

    return body, server_challenge


# --------------------------------------------------------------------------
# NEGATIVE -- the bypass itself.
# --------------------------------------------------------------------------


def test_wrong_signature_with_custom_declared_algorithm_is_not_ok(
    config_module, advanced_module
):
    """A real key + a wrong signature + ``"algorithm": -12345`` must not pass.

    The credential's COSE key is a genuine, fully supported ES256 key; only the
    separate client-declared ``algorithm`` field is exotic. The signature is a
    real signature over the wrong message.
    """

    authenticator = Authenticator()
    stored_entry = authenticator.stored_credential_entry(
        declared_algorithm=CUSTOM_ALGORITHM
    )

    client = config_module.app.test_client()
    _, server_challenge = _authenticate(
        client, stored_entry=stored_entry, assertion=None, challenge=b"\x21" * 32
    )

    response = client.post(
        "/api/advanced/authenticate/complete",
        json={
            "publicKey": {
                "challenge": {"$base64url": b64u(server_challenge)},
                "allowCredentials": [
                    {
                        "type": "public-key",
                        "id": b64u(authenticator.credential_id),
                        "alg": CUSTOM_ALGORITHM,
                    }
                ],
            },
            "__storedCredentials": [stored_entry],
            "__assertion_response": assertion_payload(
                authenticator, challenge=server_challenge, valid_signature=False
            ),
        },
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["status"] != "OK"
    assert payload["verified"] is False
    assert payload["signatureVerified"] is False
    # The old bypass marker must not exist anywhere in the response.
    assert "customAlgorithmBypass" not in payload


def test_wrong_signature_with_ordinary_algorithm_is_not_ok(
    config_module, advanced_module
):
    """The plain case: a wrong signature on a normally-declared credential."""

    authenticator = Authenticator()
    stored_entry = authenticator.stored_credential_entry(declared_algorithm=-7)

    client = config_module.app.test_client()
    _, server_challenge = _authenticate(
        client, stored_entry=stored_entry, assertion=None, challenge=b"\x22" * 32
    )

    response = client.post(
        "/api/advanced/authenticate/complete",
        json={
            "publicKey": {"challenge": {"$base64url": b64u(server_challenge)}},
            "__storedCredentials": [stored_entry],
            "__assertion_response": assertion_payload(
                authenticator, challenge=server_challenge, valid_signature=False
            ),
        },
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["status"] == "VERIFICATION_FAILED"
    assert payload["verified"] is False


def test_genuinely_unsupported_algorithm_reports_explicit_non_ok_status(
    config_module, advanced_module
):
    """An algorithm this server cannot verify is reported, but never as OK.

    Here the credential's OWN COSE key declares an algorithm the server has no
    implementation for, so no verification is possible. That is useful to
    report -- as an explicit non-OK status saying nothing was verified.
    """

    authenticator = Authenticator()
    exotic_key = authenticator.cose_key_with_declared_algorithm(CUSTOM_ALGORITHM)
    stored_entry = authenticator.stored_credential_entry(
        declared_algorithm=CUSTOM_ALGORITHM, cose_key_bytes=exotic_key
    )

    client = config_module.app.test_client()
    _, server_challenge = _authenticate(
        client, stored_entry=stored_entry, assertion=None, challenge=b"\x23" * 32
    )

    response = client.post(
        "/api/advanced/authenticate/complete",
        json={
            "publicKey": {"challenge": {"$base64url": b64u(server_challenge)}},
            "__storedCredentials": [stored_entry],
            "__assertion_response": assertion_payload(
                authenticator, challenge=server_challenge, valid_signature=True
            ),
        },
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["status"] == "UNSUPPORTED_ALGORITHM"
    assert payload["verified"] is False
    assert payload["signatureVerified"] is False
    assert payload["algorithm"] == CUSTOM_ALGORITHM
    # The report must make clear that nothing was checked.
    assert "not supported" in payload["error"]
    assert "NOT verified" in payload["error"]


# --------------------------------------------------------------------------
# POSITIVE -- a genuine assertion still authenticates.
# --------------------------------------------------------------------------


def test_valid_assertion_still_authenticates(config_module, advanced_module):
    authenticator = Authenticator()
    stored_entry = authenticator.stored_credential_entry(declared_algorithm=-7)

    client = config_module.app.test_client()
    _, server_challenge = _authenticate(
        client, stored_entry=stored_entry, assertion=None, challenge=b"\x24" * 32
    )

    response = client.post(
        "/api/advanced/authenticate/complete",
        json={
            "publicKey": {"challenge": {"$base64url": b64u(server_challenge)}},
            "__storedCredentials": [stored_entry],
            "__assertion_response": assertion_payload(
                authenticator, challenge=server_challenge, valid_signature=True
            ),
        },
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 200, response.get_json()
    payload = response.get_json()
    assert payload["status"] == "OK"
    assert payload["verified"] is True
    assert payload["signatureVerified"] is True
    assert payload["challengeSource"] == "server-session"


def test_valid_ed25519_assertion_still_authenticates(config_module, advanced_module):
    """A second real algorithm, to prove the fix is not ES256-specific."""

    authenticator = Authenticator(key_type="ed25519")
    stored_entry = authenticator.stored_credential_entry(declared_algorithm=-8)

    client = config_module.app.test_client()
    _, server_challenge = _authenticate(
        client, stored_entry=stored_entry, assertion=None, challenge=b"\x25" * 32
    )

    response = client.post(
        "/api/advanced/authenticate/complete",
        json={
            "publicKey": {"challenge": {"$base64url": b64u(server_challenge)}},
            "__storedCredentials": [stored_entry],
            "__assertion_response": assertion_payload(
                authenticator, challenge=server_challenge, valid_signature=True
            ),
        },
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["status"] == "OK"
