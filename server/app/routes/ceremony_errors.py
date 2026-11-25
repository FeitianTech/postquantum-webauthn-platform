"""What a ceremony's complete answers when fido2 or the app refuses the response.

fido2 says in a sentence what in a response did not match its ceremony: the client
data's type or origin, the challenge, the RP ID hash, the user present and verified
flags, the signature, the credential. Those are answered as fido2 wrote them
(``FIDO2_FINDINGS``, fido2 2.2.1's). Any other exception's text was written for whoever
reads the code (fido2's parsers name their classes and arguments, a store its paths):
the answer is a sentence of the app's own. Each refusal is one WARNING line naming the
route and its cause: fido2's finding, else the exception's type and where it was raised,
never its text, which may carry what the client sent.

A sign-in's credential response over a registration's limit (``config/request_limits.py``) is
refused before anything reads it: fido2 parses its clientDataJSON, one string in the body,
which the cap on a body's values does not see. So is a response whose CBOR nests deeper or
holds more items than any real one (``webauthn/cbor_bounds.py``), which fido2's decoder would
take seconds or tens of MiB to read.
"""
from __future__ import annotations

import logging
from typing import Any

from flask import current_app, jsonify, request

from ..config import request_limits
from ..webauthn import cbor_bounds

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


def _raised_where(exc: Exception) -> str:
    """``exc``'s type, and the module and line of its innermost frame when it was raised."""

    tb = exc.__traceback__
    while tb is not None and tb.tb_next is not None:
        tb = tb.tb_next
    if tb is None:
        return type(exc).__name__
    return f"{type(exc).__name__} at {tb.tb_frame.f_globals.get('__name__')}:{tb.tb_lineno}"


def answer_text(exc: Exception, sentence: str) -> str:
    """fido2's finding when ``exc`` is one, else ``sentence``; the refusal logged in one WARNING line."""

    finding = isinstance(exc, (ValueError, NotImplementedError)) and str(exc) in FIDO2_FINDINGS
    logger.warning("%s %s refused: %s", request.method, request.path, str(exc) if finding else _raised_where(exc))
    return str(exc) if finding else sentence


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


def _cbor_refusal(ceremony: str, excess: str | None) -> Any | None:
    if excess is None:
        return None
    what = (
        f"nests its CBOR more than {cbor_bounds.MAX_DEPTH} levels deep"
        if excess == cbor_bounds.DEPTH
        else f"holds more than {cbor_bounds.MAX_ITEMS:,} CBOR items"
    )
    return jsonify({"error": f"This {ceremony}'s response {what}, far more than any real one, so it was not read."}), 400


def registration_cbor_refused(response: Any) -> Any | None:
    """The 400 for a registration response whose attestation object or authenticator data
    nests or holds more than ``cbor_bounds`` reads, else None."""

    return _cbor_refusal("registration", cbor_bounds.registration_excess(response))


def authentication_cbor_refused(response: Any) -> Any | None:
    """The 400 for an assertion whose authenticator data nests or holds more than ``cbor_bounds`` reads, else None."""

    return _cbor_refusal("authentication", cbor_bounds.assertion_excess(response))
