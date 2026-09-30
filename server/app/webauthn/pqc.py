"""The ML-DSA algorithms in the server's WebAuthn: their names, and whether this build verifies them.

Signing and verification are provided by ``cryptography``, which has native
ML-DSA support; whether this build can verify it is fido2's to say
(``CoseKey.supported_algorithms``).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# COSE algorithm identifiers mapped to their FIPS 204 parameter set names.
PQC_ALGORITHM_ID_TO_NAME: dict[int, str] = {
    -50: "ML-DSA-87",
    -49: "ML-DSA-65",
    -48: "ML-DSA-44",
}

_PQC_ALGORITHM_NAME_TO_ID: dict[str, int] = {
    name: alg_id for alg_id, name in PQC_ALGORITHM_ID_TO_NAME.items()
}


def is_pqc_algorithm(alg_id: int) -> bool:
    """Return ``True`` if the COSE algorithm corresponds to an ML-DSA option."""

    return alg_id in PQC_ALGORITHM_ID_TO_NAME


def describe_algorithm(alg_id: int | None) -> str:
    """Return a friendly label for the given COSE algorithm identifier."""

    if alg_id is None:
        return "Unknown"
    name = PQC_ALGORITHM_ID_TO_NAME.get(alg_id)
    if name:
        return f"{name} (PQC)"
    if alg_id == -8:
        return "EdDSA"
    if alg_id == -19:
        return "Ed25519"
    if alg_id == -53:
        return "Ed448"
    if alg_id == -7:
        return "ES256 (ECDSA)"
    if alg_id == -9:
        return "ESP256 (ECDSA)"
    if alg_id == -47:
        return "ES256K (ECDSA)"
    if alg_id == -35:
        return "ES384 (ECDSA)"
    if alg_id == -36:
        return "ES512 (ECDSA)"
    if alg_id == -51:
        return "ESP384 (ECDSA)"
    if alg_id == -52:
        return "ESP512 (ECDSA)"
    if alg_id == -37:
        return "PS256 (RSA-PSS)"
    if alg_id == -38:
        return "PS384 (RSA-PSS)"
    if alg_id == -39:
        return "PS512 (RSA-PSS)"
    if alg_id == -257:
        return "RS256 (RSA)"
    if alg_id == -258:
        return "RS384 (RSA)"
    if alg_id == -259:
        return "RS512 (RSA)"
    if alg_id == -65535:
        return "RS1 (RSA)"
    return f"COSE alg {alg_id}"


def log_algorithm_selection(stage: str, alg_id: int | None) -> None:
    """Log the negotiated algorithm for the registration/authentication flow."""

    label = describe_algorithm(alg_id)
    if alg_id is None:
        logger.info("No signature algorithm associated with %s stage.", stage)
    elif is_pqc_algorithm(alg_id):
        logger.info(
            "Using post-quantum algorithm %s (COSE %d) during %s.",
            label,
            alg_id,
            stage,
        )
    else:
        logger.info(
            "Using classical algorithm %s (COSE %d) during %s.", label, alg_id, stage
        )


__all__ = [
    "describe_algorithm",
    "is_pqc_algorithm",
    "log_algorithm_selection",
    "PQC_ALGORITHM_ID_TO_NAME",
]
