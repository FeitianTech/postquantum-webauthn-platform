"""What a Simple registration asks for that its record repeats: begin sends it, and the
record says it was asked."""
from __future__ import annotations

from typing import Any

USER_VERIFICATION = "discouraged"
AUTHENTICATOR_ATTACHMENT = "cross-platform"


def request_params() -> dict[str, Any]:
    """The request as the stored record keeps it."""

    return {
        "user_verification": USER_VERIFICATION,
        "authenticator_attachment": AUTHENTICATOR_ATTACHMENT,
        "attestation": "none",
        "resident_key": None,
        "extensions": {},
        "timeout": 90000,
    }
