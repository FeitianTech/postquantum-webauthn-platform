"""A genuinely signed advanced registration, begin then complete, for the advanced route tests."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from tests.app.security.ceremony_helpers import (
    ORIGIN,
    Authenticator,
    advanced_public_key_options,
    attestation_object,
    b64u,
    registration_payload,
    unb64u,
)


def register(
    client,
    *,
    public_key_changes: Mapping[str, Any] | None = None,
    auth_data: Callable[[Authenticator], bytes] | None = None,
):
    """Complete a registration begin issued; ``auth_data`` builds the authenticator data to send instead."""

    authenticator = Authenticator()
    begin = client.post(
        "/api/advanced/register/begin",
        json={"publicKey": advanced_public_key_options(challenge=b"\x73" * 32)},
    )
    assert begin.status_code == 200, begin.get_json()
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    credential = registration_payload(authenticator, challenge=challenge)
    if auth_data is not None:
        credential["response"]["attestationObject"] = b64u(attestation_object(auth_data(authenticator)))
    return client.post(
        "/api/advanced/register/complete",
        json={
            "publicKey": {**advanced_public_key_options(challenge=challenge), **(public_key_changes or {})},
            "__credential_response": credential,
        },
        headers={"Origin": ORIGIN},
    )
