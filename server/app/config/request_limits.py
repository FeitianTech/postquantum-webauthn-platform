"""How large a request body the app reads: ``MAX_CONTENT_LENGTH``, and the metadata upload's own limit.

A body over the limit is answered 413 before any route reads it
(``routes/errors.py`` answers it as JSON). Without one, only Cloud Run's 32 MiB
cap bounded a body, and the decoder read whatever it was sent.

The sizes the limits are chosen from (Phase 21, measured):

- an advanced registration with an ML-DSA-87 attestation and its full chain
  (leaf, intermediate and root, about 7.5 KB each): about 41 KB, and the
  credential artifact the page uploads for it about 61 KB;
- the decoder given that attestation object as hex: about 60 KB;
- an authentication that sends every saved credential: about 3.7 KB each for
  ML-DSA-87, bounded by what the browser's local storage holds (about 5 MB);
- a result snapshot at the page's caps: under 1 MB;
- the metadata upload of the whole MDS metadata (fido-mds3.verified.json):
  about 7.4 MB.

So 8 MiB for every route, and 16 MiB for the metadata upload, which sets its
own limit on the request before reading it. Both can be set in the environment.
"""
from __future__ import annotations

import os
from typing import Any

_MIB = 1024 * 1024
DEFAULT_MAX_REQUEST_BYTES = 8 * _MIB
DEFAULT_MAX_METADATA_UPLOAD_BYTES = 16 * _MIB

# The app.config key the metadata upload reads its limit from.
METADATA_UPLOAD_LIMIT_KEY = "MAX_METADATA_UPLOAD_LENGTH"


def _positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw:
        try:
            parsed = int(raw.strip())
        except ValueError:
            return default
        if parsed > 0:
            return parsed
    return default


def config_from_env() -> dict[str, Any]:
    """The request-size limits ``create_app()`` puts into ``app.config``."""

    return {
        "MAX_CONTENT_LENGTH": _positive_int("FIDO_SERVER_MAX_REQUEST_BYTES", DEFAULT_MAX_REQUEST_BYTES),
        METADATA_UPLOAD_LIMIT_KEY: _positive_int(
            "FIDO_SERVER_MAX_METADATA_UPLOAD_BYTES", DEFAULT_MAX_METADATA_UPLOAD_BYTES
        ),
    }
