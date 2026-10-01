"""What the codec's encoder answers for a CTAP message, for the encoder tests."""
from __future__ import annotations

import json

from server.app.decoder.encode import text as encode_text

CTAP = "CBOR (CTAP/WebAuthn Data)"


def encoded_members(value) -> dict:
    """The members of the one CTAP message the encoder writes for ``value``, by name."""

    (members,) = encode_text.encode_payload_text(json.dumps(value), CTAP)["data"]["ctapDecoded"].values()
    return members
