"""What a ceremony's complete answers when fido2 or the app refuses the response.

fido2 says in a sentence what in a response did not match its ceremony: the client
data's type or origin, the challenge, the RP ID hash, the user present and verified
flags, the signature, the credential. Those are answered as fido2 wrote them
(``FIDO2_FINDINGS``, fido2 2.2.1's). Any other exception's text was written for whoever
reads the code (fido2's parsers name their classes and arguments, a store its paths):
the answer is a sentence of the app's own, and the exception is logged at INFO.

A sign-in's credential response over a registration's limit (``config/request_limits.py``) is
refused before anything reads it: fido2 parses its clientDataJSON, one string in the body,
which the cap on a body's values does not see.
"""
from __future__ import annotations

import logging
from typing import Any

from flask import current_app, jsonify, request

from ..config import request_limits

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


def authentication_response_too_large(response: Any) -> Any | None:
    """The 413 for a sign-in's credential response over its limit, else None.

    The response alone is measured, as a registration's is: the saved credentials sent beside it are not.
    """

    limit = current_app.config[request_limits.REGISTRATION_RESPONSE_LIMIT_KEY]
    size = request_limits.credential_response_size(response)
    if size <= limit:
        return None
    return (
        jsonify(
            {
                "error": (
                    f"This authentication's response is {size:,} bytes, more than the {limit:,} this server "
                    "reads for one. Please restart the authentication flow."
                )
            }
        ),
        413,
    )
