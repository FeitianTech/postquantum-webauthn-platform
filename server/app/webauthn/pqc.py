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


# Every other COSE algorithm the views name, as they name it.
_ALGORITHM_LABELS: dict[int, str] = {
    -8: "EdDSA",
    -19: "Ed25519",
    -53: "Ed448",
    -7: "ES256 (ECDSA)",
    -9: "ESP256 (ECDSA)",
    -47: "ES256K (ECDSA)",
    -35: "ES384 (ECDSA)",
    -36: "ES512 (ECDSA)",
    -51: "ESP384 (ECDSA)",
    -52: "ESP512 (ECDSA)",
    -37: "PS256 (RSA-PSS)",
    -38: "PS384 (RSA-PSS)",
    -39: "PS512 (RSA-PSS)",
    -257: "RS256 (RSA)",
    -258: "RS384 (RSA)",
    -259: "RS512 (RSA)",
    -65535: "RS1 (RSA)",
}


def describe_algorithm(alg_id: int | None) -> str:
    """Return a friendly label for the given COSE algorithm identifier."""

    if alg_id is None:
        return "Unknown"
    name = PQC_ALGORITHM_ID_TO_NAME.get(alg_id)
    if name:
        return f"{name} (PQC)"
    return _ALGORITHM_LABELS.get(alg_id, f"COSE alg {alg_id}")


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
