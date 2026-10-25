"""What a Simple registration asks for: begin sends it, and the answer's properties say
the resident key it asked for. Begin sends no attestation preference, which is "none",
and no timeout."""
from __future__ import annotations

USER_VERIFICATION = "discouraged"
AUTHENTICATOR_ATTACHMENT = "cross-platform"
RESIDENT_KEY = "discouraged"
# credProps, so the browser says whether the credential is discoverable.
EXTENSIONS = {"credProps": True}
