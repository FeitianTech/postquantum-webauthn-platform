"""A genuinely signed advanced authentication, begin then complete, for the advanced route tests."""
from __future__ import annotations

from typing import Any

from tests.app.security.ceremony_helpers import ORIGIN, b64u

CHALLENGE = b"\x71" * 32


def _public_key(changes: dict[str, Any]) -> dict[str, Any]:
    return {"challenge": {"$base64url": b64u(CHALLENGE)}, **changes}


def begin(client, credentials: list[Any], **public_key_changes: Any):
    """Authentication begin for ``credentials``, the browser's saved list."""

    return client.post(
        "/api/advanced/authenticate/begin",
        json={"publicKey": _public_key(public_key_changes), "__storedCredentials": credentials},
    )


def complete(client, credentials: list[Any] | None, assertion: Any, **public_key_changes: Any):
    """Authentication complete for ``assertion``; ``credentials`` None sends no saved list."""

    body: dict[str, Any] = {"publicKey": _public_key(public_key_changes), "__assertion_response": assertion}
    if credentials is not None:
        body["__storedCredentials"] = credentials
    return client.post("/api/advanced/authenticate/complete", json=body, headers={"Origin": ORIGIN})
