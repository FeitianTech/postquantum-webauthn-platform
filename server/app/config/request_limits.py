"""How large a request body the app reads (``MAX_CONTENT_LENGTH``, and the metadata upload's, the codec's and a registration's own), and how much one visitor's namespace keeps.

A body over the limit is answered 413 before any route reads it
(``routes/errors.py`` answers it as JSON). Without one, only Cloud Run's 32 MiB
cap bounded a body, and the decoder read whatever it was sent.

The sizes the limits are chosen from (measured):

- an advanced registration with an ML-DSA-87 attestation and its full chain
  (leaf, intermediate and root, about 7.5 KB each): about 41 KB, and the
  credential artifact the page uploads for it about 61 KB;
- the decoder given that attestation object as hex: about 60 KB;
- an authentication that sends every saved credential: about 3.7 KB each for
  ML-DSA-87, bounded by what the browser's local storage holds (about 5 MB);
- a result snapshot at the page's caps: under 1 MB;
- the metadata upload of the whole MDS metadata (fido-mds3.verified.json):
  about 7.4 MB;
- a Simple registration's complete, which is the credential's response alone:
  40,544 bytes for that ML-DSA-87 attestation and its chain, and under 11 KB
  from a browser, which the Simple tab asks for no attestation; an advanced
  complete sends the editor's request beside the response, 528 KB with 64 fake
  exclude IDs of 4,096 bytes, none of which the artifact keeps.

So 8 MiB for every route; 16 MiB for the metadata upload; 1 MiB for
``/api/codec``, whose inputs are at most about 60 KB and which reads each one
several times; and 256 KiB for a registration's credential response. The
stored record and the answer copy that response whole, and each certificate in
it again in several forms: a crafted one under 8 MiB was stored as 12 MB and
answered as 15 MB. The upload, the codec and the Simple registration's complete
set their own limit on the request before reading it; the advanced registration's
complete measures its ``__credential_response`` once its ceremony's state is
consumed, so that refusal carries the challenge's trace. Each can be set in the
environment.

``/api/codec`` also reads at most ``MAX_CODEC_ITEMS`` items for one request,
20,000 unless the environment says otherwise (``decoder/item_budget.py`` says
what counts, and why that many).

What one visitor's namespace keeps (docs/STORAGE.md, "Quotas"): a write past it
raises ``storage.common.StorageQuotaExceeded``, 409 for a count, 413 for bytes.
Measured: an advanced registration's artifact is about 10 KB for a classical
credential and 1 MB for that ML-DSA-87 attestation with its chain, about
1.3 MB with the page's snapshot; the e2e runs keep one artifact per namespace,
the goldens four; a heavy visitor's 200 registrations, 20 of them ML-DSA-87
with chains, about 35 MB. So 1,000 artifacts and 256 MiB of them. Uploaded
metadata is kept one file per entry: the whole MDS metadata, 518 entries, about
7 MB; the e2e runs keep one entry per namespace. So 2,000 entries and 64 MiB of
them. A Simple username's list: the goldens hold two credentials under one, the
e2e runs one, a tester with every authenticator they own perhaps five. So 100.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from ..decoder import item_budget
from ..storage.common import Quota

_MIB = 1024 * 1024
DEFAULT_MAX_REQUEST_BYTES = 8 * _MIB
DEFAULT_MAX_METADATA_UPLOAD_BYTES = 16 * _MIB
DEFAULT_MAX_CODEC_REQUEST_BYTES = _MIB
DEFAULT_MAX_REGISTRATION_RESPONSE_BYTES = 256 * 1024
DEFAULT_MAX_STORED_ARTIFACTS = 1000
DEFAULT_MAX_STORED_ARTIFACT_BYTES = 256 * _MIB
DEFAULT_MAX_STORED_METADATA_ENTRIES = 2000
DEFAULT_MAX_STORED_METADATA_BYTES = 64 * _MIB
DEFAULT_MAX_SIMPLE_CREDENTIALS_PER_USERNAME = 100

# The app.config key the metadata upload reads its limit from.
METADATA_UPLOAD_LIMIT_KEY = "MAX_METADATA_UPLOAD_LENGTH"
# The app.config keys /api/codec reads its own limit and its item budget from.
CODEC_REQUEST_LIMIT_KEY = "MAX_CODEC_REQUEST_LENGTH"
CODEC_ITEM_LIMIT_KEY = "MAX_CODEC_ITEMS"
# The app.config key a registration's complete reads the limit of its credential response from.
REGISTRATION_RESPONSE_LIMIT_KEY = "MAX_REGISTRATION_RESPONSE_LENGTH"
# The app.config keys of the namespace's quota of credential artifacts: how many, how many bytes.
STORED_ARTIFACTS_KEY = "MAX_STORED_ARTIFACTS"
STORED_ARTIFACT_BYTES_KEY = "MAX_STORED_ARTIFACT_BYTES"
# The app.config keys of the namespace's quota of uploaded metadata: how many entries, how many bytes.
STORED_METADATA_ENTRIES_KEY = "MAX_STORED_METADATA_ENTRIES"
STORED_METADATA_BYTES_KEY = "MAX_STORED_METADATA_BYTES"
# The app.config key of how many Simple credentials one username's list keeps.
SIMPLE_CREDENTIALS_PER_USERNAME_KEY = "MAX_SIMPLE_CREDENTIALS_PER_USERNAME"


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
    """The request limits ``create_app()`` puts into ``app.config``."""

    return {
        "MAX_CONTENT_LENGTH": _positive_int("FIDO_SERVER_MAX_REQUEST_BYTES", DEFAULT_MAX_REQUEST_BYTES),
        METADATA_UPLOAD_LIMIT_KEY: _positive_int(
            "FIDO_SERVER_MAX_METADATA_UPLOAD_BYTES", DEFAULT_MAX_METADATA_UPLOAD_BYTES
        ),
        CODEC_REQUEST_LIMIT_KEY: _positive_int("FIDO_SERVER_MAX_CODEC_REQUEST_BYTES", DEFAULT_MAX_CODEC_REQUEST_BYTES),
        CODEC_ITEM_LIMIT_KEY: _positive_int("FIDO_SERVER_MAX_CODEC_ITEMS", item_budget.DEFAULT_MAX_ITEMS),
        REGISTRATION_RESPONSE_LIMIT_KEY: _positive_int(
            "FIDO_SERVER_MAX_REGISTRATION_RESPONSE_BYTES", DEFAULT_MAX_REGISTRATION_RESPONSE_BYTES
        ),
        STORED_ARTIFACTS_KEY: _positive_int("FIDO_SERVER_MAX_STORED_ARTIFACTS", DEFAULT_MAX_STORED_ARTIFACTS),
        STORED_ARTIFACT_BYTES_KEY: _positive_int("FIDO_SERVER_MAX_STORED_ARTIFACT_BYTES", DEFAULT_MAX_STORED_ARTIFACT_BYTES),
        STORED_METADATA_ENTRIES_KEY: _positive_int(
            "FIDO_SERVER_MAX_STORED_METADATA_ENTRIES", DEFAULT_MAX_STORED_METADATA_ENTRIES
        ),
        STORED_METADATA_BYTES_KEY: _positive_int("FIDO_SERVER_MAX_STORED_METADATA_BYTES", DEFAULT_MAX_STORED_METADATA_BYTES),
        SIMPLE_CREDENTIALS_PER_USERNAME_KEY: _positive_int(
            "FIDO_SERVER_MAX_SIMPLE_CREDENTIALS_PER_USERNAME", DEFAULT_MAX_SIMPLE_CREDENTIALS_PER_USERNAME
        ),
    }


def artifacts_quota(config: Mapping[str, Any]) -> Quota:
    """The namespace's quota of credential artifacts, as ``config`` (``app.config``) holds it."""

    return Quota(config[STORED_ARTIFACTS_KEY], config[STORED_ARTIFACT_BYTES_KEY])


def metadata_quota(config: Mapping[str, Any]) -> Quota:
    """The namespace's quota of uploaded metadata entries, as ``config`` (``app.config``) holds it."""

    return Quota(config[STORED_METADATA_ENTRIES_KEY], config[STORED_METADATA_BYTES_KEY])
