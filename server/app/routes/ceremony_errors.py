"""What a ceremony's complete answers when fido2 or the app refuses the response.

fido2 says in a sentence what in a response did not match its ceremony: the client
data's type or origin, the challenge, the RP ID hash, the user present and verified
flags, the signature, the credential. Those are answered as fido2 wrote them
(``FIDO2_FINDINGS``, fido2 2.2.1's). Any other exception's text was written for whoever
reads the code (fido2's parsers name their classes and arguments, a store its paths):
the answer is a sentence of the app's own, and the exception is logged at INFO.
"""
from __future__ import annotations

import logging

from flask import request

logger = logging.getLogger(__name__)

# fido2 2.2.1's own sentences (fido2/server.py; cose.py's for a key it cannot verify with).
FIDO2_FINDINGS = frozenset(
    {
        "Incorrect type in CollectedClientData.",
        "Invalid origin in CollectedClientData.",
        "Wrong challenge in response.",
        "Wrong RP ID hash in response.",
        "User Present flag not set.",
        "User verification required, but User Verified flag not set.",
        "User verification required, but user verified flag not set.",
        "Invalid signature.",
        "Unknown credential ID.",
        "Signature verification not supported.",
    }
)

REGISTRATION_FAILED = "The registration could not be completed."
AUTHENTICATION_FAILED = "The authentication could not be completed."


def answer_text(exc: Exception, sentence: str) -> str:
    """fido2's finding when ``exc`` is one, else ``sentence``, with ``exc`` logged at INFO."""

    if isinstance(exc, (ValueError, NotImplementedError)) and str(exc) in FIDO2_FINDINGS:
        return str(exc)
    logger.info("%s %s: %s", request.method, request.path, sentence, exc_info=exc)
    return sentence
