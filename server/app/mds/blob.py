"""The FIDO MDS BLOB, checked against the pinned root: its signing chain, its signature, its payload.

The BLOB is a JWS whose ``x5c`` header carries the signing certificate and the
certificates above it. RFC 5280 path validation stops at the first trusted
root, and the BLOB can carry certificates past it: the GlobalSign R3 to R46
cross-certificate, for trust stores that only have R3. fido2's ``parse_blob``
checks ``x5c`` and the root as one straight chain, so with R46 pinned it would
refuse the real BLOB; this builds the path cryptography's verifier finds.

A Flask-free leaf like ``mds.trust``: ``tools/update_mds_snapshot.py`` uses it
without building the app, and its only import from the app is ``encoding``. The
JWS's segments are read as the unpadded base64url RFC 7515 writes, and ``x5c``'s
certificates as standard base64, strictly: nothing else is decoded.
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.x509.verification import (
    Criticality,
    ExtensionPolicy,
    PolicyBuilder,
    Store,
    VerificationError,
)
from fido2.attestation import InvalidSignature
from fido2.cose import CoseKey

from .. import encoding

__all__ = ["verify_blob", "verify_chain_to_root"]


def verify_chain_to_root(chain: Sequence[bytes], trust_root: bytes, *, now: datetime | None = None) -> None:
    """Check that ``chain``'s first certificate leads to ``trust_root``, valid at ``now``.

    RFC 5280 path building (cryptography's ``x509.verification``) with
    ``trust_root`` the only anchor and the rest of ``chain`` the intermediates it
    may use: a certificate past the root (the R3 cross-certificate) is simply not
    on the path. Every CA on the path must carry Basic Constraints. Raises fido2's
    ``InvalidSignature`` when there is no such path.
    """

    if not chain:
        return
    certificates = [x509.load_der_x509_certificate(bytes(der)) for der in chain]
    ca_policy = ExtensionPolicy.permit_all().require_present(x509.BasicConstraints, Criticality.AGNOSTIC, None)
    verifier = (
        PolicyBuilder()
        .store(Store([x509.load_der_x509_certificate(bytes(trust_root))]))
        .time(now or datetime.now(timezone.utc))
        .extension_policies(ca_policy=ca_policy, ee_policy=ExtensionPolicy.permit_all())
        .build_client_verifier()
    )
    try:
        verifier.verify(certificates[0], certificates[1:])
    except VerificationError as exc:
        raise InvalidSignature(f"No path to the pinned root: {exc}") from None


def _segment(segment: bytes) -> bytes:
    """A JWS segment's bytes: unpadded base64url, nothing else."""

    text = segment.decode("ascii")
    if "=" in text:
        raise encoding.EncodingError("a JWS segment is unpadded base64url")
    return encoding.decode_base64url(text, ignore_whitespace=False)


def verify_blob(blob: bytes, trust_root: bytes, *, now: datetime | None = None) -> dict[str, Any]:
    """The BLOB's payload, once its chain leads to ``trust_root``, valid at ``now``, and its signature verifies.

    ``now`` defaults to the present; an instance checks a BLOB it took from Cloud
    Storage at the time it was fetched. The payload is returned as the BLOB has
    it, JSON, not fido2's dataclasses (which drop every field they do not model),
    and is not parsed into them: the updater checks it reads as a
    ``MetadataBlobPayload``.
    """

    message, signature_segment = blob.rsplit(b".", 1)
    header_segment, payload_segment = message.split(b".")
    header = json.loads(_segment(header_segment))

    chain = [encoding.decode_base64(certificate, ignore_whitespace=False) for certificate in header.get("x5c", [])]
    verify_chain_to_root(chain, trust_root, now=now)

    signer = x509.load_der_x509_certificate(chain[0] if chain else trust_root)
    try:
        public_key = signer.public_key()
    except ValueError:
        raise ValueError("Metadata signing certificate does not expose a supported public key") from None
    signature = _segment(signature_segment)
    CoseKey.for_name(header["alg"]).from_cryptography_key(public_key).verify(message, signature)

    payload = json.loads(_segment(payload_segment))
    if not isinstance(payload, dict):
        raise ValueError("The metadata BLOB's payload is not a JSON object")
    return payload
