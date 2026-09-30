"""A certificate given whole: PEM text holding one or more, or the DER bytes of one."""
from __future__ import annotations

import re
from typing import Any

from cryptography import x509

from ...encoding import try_decode_base64
from ...webauthn.attestation import certificates as attestation_certificates
from .. import values

_PEM_CERT_PATTERN = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*(?P<body>.*?)\s*-----END CERTIFICATE-----",
    re.IGNORECASE | re.DOTALL,
)


def looks_like_pem(value: str) -> bool:
    return "-----BEGIN CERTIFICATE-----" in value.upper()


def decode_pem_certificates(text: str) -> dict[str, Any]:
    certificates = []
    for match in _PEM_CERT_PATTERN.finditer(text):
        cert_bytes = try_decode_base64(match.group("body"))
        if cert_bytes is None:
            continue
        certificates.append(cert_bytes)

    if not certificates:
        raise ValueError("No PEM certificate data found.")

    decoded_details = [
        attestation_certificates.serialize_attestation_certificate(cert_bytes) for cert_bytes in certificates
    ]

    payload: dict[str, Any]
    if len(decoded_details) == 1:
        payload = decoded_details[0]
    else:
        payload = {"certificates": decoded_details}

    payload.setdefault("rawPem", text.strip())

    return {
        "format": "X.509 certificate (PEM)",
        "inputEncoding": "pem",
        "decoded": payload,
    }


def try_decode_der_certificate(data: bytes, encoding: str) -> dict[str, Any] | None:
    try:
        x509.load_der_x509_certificate(data)
    except Exception:
        return None

    return {
        "format": "X.509 certificate (DER)",
        "inputEncoding": encoding,
        "decoded": attestation_certificates.serialize_attestation_certificate(data),
        "binary": values.binary_summary(data, encoding),
    }
