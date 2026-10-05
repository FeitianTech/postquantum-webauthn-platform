"""An AAGUID's GUID spelling: the one conversion from its 16 bytes.

Only this conversion is shared. The AAGUID string normalisers keep their own
contracts: ``mds.statement_fields.normalise_aaguid_key`` (the explorer's key, "" when there
is none), ``mds.entries._normalise_aaguid`` (a statement's field as written,
any length), ``webauthn.attestation.aaguid.normalize_aaguid_string`` (exactly
32 hex digits, anything else dropped); and the decoder's view of authenticator
data shows the AAGUID it read, refusing none.
"""
from __future__ import annotations

import uuid
from typing import Any


def guid(value: Any) -> str | None:
    """``value`` as a GUID (``xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx``) when it is 16 ``bytes``; else ``None``."""

    if not isinstance(value, bytes) or len(value) != 16:
        return None
    return str(uuid.UUID(bytes=value))
