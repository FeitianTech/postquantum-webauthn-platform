"""The FIDO MDS BLOB, checked against the pinned root: its signing chain, its signature, its payload.

The BLOB is a JWS whose ``x5c`` header carries the signing certificate and the
certificates above it. RFC 5280 path validation stops at the first trusted
root, and the BLOB can carry certificates past it: the GlobalSign R3 to R46
cross-certificate, for trust stores that only have R3. fido2's ``parse_blob``
checks ``x5c`` and the root as one straight chain, so with R46 pinned it would
refuse the real BLOB; this checks each shorter path first.

A Flask-free leaf like ``mds_trust``: ``tools/update_mds_snapshot.py`` uses it
without building the app, and it imports nothing from the app.
"""
from __future__ import annotations

import json
from base64 import b64decode
from collections.abc import Sequence
from typing import Any

from cryptography import x509
from fido2.attestation import InvalidSignature, verify_x509_chain
from fido2.cose import CoseKey
from fido2.mds3 import MetadataBlobPayload
from fido2.utils import websafe_decode

__all__ = ["verify_blob", "verify_chain_to_root"]


def verify_chain_to_root(chain: Sequence[bytes], trust_root: bytes) -> None:
    """Check that some leading part of ``chain`` leads to ``trust_root``.

    Tries the leaf alone, then the leaf and the next certificate, and so on, each
    ending in ``trust_root``: the first path that verifies ends the check.
    Raises fido2's ``InvalidSignature`` when none does.
    """

    if not chain:
        verify_x509_chain([trust_root])
        return
    last_error: InvalidSignature | None = None
    for end in range(1, len(chain) + 1):
        try:
            verify_x509_chain(list(chain[:end]) + [trust_root])
            return
        except InvalidSignature as exc:
            last_error = exc
    assert last_error is not None  # nosec - the loop ran at least once
    raise last_error


def verify_blob(blob: bytes, trust_root: bytes) -> dict[str, Any]:
    """The BLOB's payload, once its chain leads to ``trust_root`` and its signature verifies.

    The payload is returned as the BLOB has it, JSON, not fido2's dataclasses,
    which drop every field they do not model; it must still read as a
    ``MetadataBlobPayload``, or this raises.
    """

    message, signature_segment = blob.rsplit(b".", 1)
    header_segment, payload_segment = message.split(b".")
    header = json.loads(websafe_decode(header_segment.decode("ascii")))

    chain = [b64decode(certificate) for certificate in header.get("x5c", [])]
    verify_chain_to_root(chain, trust_root)

    signer = x509.load_der_x509_certificate(chain[0] if chain else trust_root)
    try:
        public_key = signer.public_key()
    except ValueError:
        raise ValueError("Metadata signing certificate does not expose a supported public key") from None
    signature = websafe_decode(signature_segment.decode("ascii"))
    CoseKey.for_name(header["alg"]).from_cryptography_key(public_key).verify(message, signature)

    payload = json.loads(websafe_decode(payload_segment.decode("ascii")))
    MetadataBlobPayload.from_dict(payload)
    return payload
