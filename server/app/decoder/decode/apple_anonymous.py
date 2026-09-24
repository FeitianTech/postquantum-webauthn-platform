"""Read the nonce in an Apple anonymous attestation certificate.

WebAuthn L3 section 8.8: credCert, the first certificate in x5c, carries a
nonce in the extension with OID 1.2.840.113635.100.8.2, which a verifier
compares with SHA-256(authenticatorData || clientDataHash). The extension's
value is a SEQUENCE holding the nonce as an OCTET STRING under explicit tag
[1] -- the bytes the vendored fido2's apple.py slices at offset 6 -- and
``cryptography`` decodes it. The comparison is a verifier's; it is not made here.
"""
from __future__ import annotations

from typing import Annotated, Any

from cryptography import x509
from cryptography.hazmat import asn1

NONCE_OID = "1.2.840.113635.100.8.2"


@asn1.sequence
class _NonceExtension:
    nonce: Annotated[bytes, asn1.Explicit(1)]


def read_certificate(der: bytes) -> dict[str, Any]:
    try:
        certificate = x509.load_der_x509_certificate(der)
    except ValueError as exc:
        return {"error": f"credCert is not DER X.509: {exc}"}
    try:
        extension = certificate.extensions.get_extension_for_oid(x509.ObjectIdentifier(NONCE_OID))
    except x509.ExtensionNotFound:
        return {"note": f"credCert has no {NONCE_OID} extension"}
    raw = extension.value.value if isinstance(extension.value, x509.UnrecognizedExtension) else b""
    try:
        nonce = asn1.decode_der(_NonceExtension, raw).nonce
    except ValueError as exc:
        return {"extension": NONCE_OID, "hex": raw.hex(), "error": f"not SEQUENCE {{[1] EXPLICIT OCTET STRING}}: {exc}"}
    return {
        "extension": NONCE_OID,
        "nonce": nonce.hex(),
        "length": len(nonce),
        "note": "WebAuthn L3 section 8.8: SHA-256(authenticatorData || clientDataHash); not compared",
    }
