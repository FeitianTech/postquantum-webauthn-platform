"""What a Simple registration asks for that its record repeats: begin sends it, and the
record says it was asked."""
from __future__ import annotations

from typing import Any

USER_VERIFICATION = "discouraged"
AUTHENTICATOR_ATTACHMENT = "cross-platform"
RESIDENT_KEY = "discouraged"
# credProps, so the browser says whether the credential is discoverable.
EXTENSIONS = {"credProps": True}


def request_params() -> dict[str, Any]:
    """The request as the stored record keeps it. Begin sends no attestation
    preference, which is "none", and no timeout."""

    return {
        "user_verification": USER_VERIFICATION,
        "authenticator_attachment": AUTHENTICATOR_ATTACHMENT,
        "attestation": "none",
        "resident_key": RESIDENT_KEY,
        "extensions": dict(EXTENSIONS),
        "timeout": None,
    }
