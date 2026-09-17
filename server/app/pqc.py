"""Helpers for integrating ML-DSA algorithms into the demo server.

Signing and verification are provided by ``cryptography``, which has native
ML-DSA support.  liboqs is no longer required.
"""

from __future__ import annotations


from .config import app


# COSE algorithm identifiers mapped to their FIPS 204 parameter set names.
PQC_ALGORITHM_ID_TO_NAME: dict[int, str] = {
    -50: "ML-DSA-87",
    -49: "ML-DSA-65",
    -48: "ML-DSA-44",
}

_PQC_ALGORITHM_NAME_TO_ID: dict[str, int] = {
    name: alg_id for alg_id, name in PQC_ALGORITHM_ID_TO_NAME.items()
}


def _load_enabled_mechanisms() -> set[str]:
    """Return the ML-DSA parameter sets ``cryptography`` can verify."""

    from cryptography.hazmat.primitives.asymmetric import mldsa

    key_classes = {
        "ML-DSA-44": "MLDSA44PublicKey",
        "ML-DSA-65": "MLDSA65PublicKey",
        "ML-DSA-87": "MLDSA87PublicKey",
    }
    return {
        mechanism
        for mechanism, attribute in key_classes.items()
        if getattr(mldsa, attribute, None) is not None
    }


def detect_available_pqc_algorithms() -> tuple[set[int], str | None]:
    """Detect the ML-DSA algorithms this build can verify."""

    try:
        mechanism_names = _load_enabled_mechanisms()
    except ImportError:
        return set(), (
            "Post-quantum algorithms require a cryptography build with ML-DSA support. "
            "Install cryptography>=49."
        )
    except Exception as exc:  # pragma: no cover - defensive logging path
        app.logger.exception("Failed to enumerate ML-DSA mechanisms: %s", exc)
        return set(), "Unable to determine which post-quantum algorithms are available."

    available_ids = {
        alg_id
        for alg_id, mechanism in PQC_ALGORITHM_ID_TO_NAME.items()
        if mechanism in mechanism_names
    }

    if len(available_ids) == len(PQC_ALGORITHM_ID_TO_NAME):
        return available_ids, None

    missing = [
        PQC_ALGORITHM_ID_TO_NAME[alg_id]
        for alg_id in sorted(PQC_ALGORITHM_ID_TO_NAME)
        if alg_id not in available_ids
    ]
    return available_ids, (
        "The installed cryptography build does not support: "
        + ", ".join(missing)
        + ". Upgrade cryptography to a release providing all ML-DSA parameter sets."
    )


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
        app.logger.info("No signature algorithm associated with %s stage.", stage)
    elif is_pqc_algorithm(alg_id):
        app.logger.info(
            "Using post-quantum algorithm %s (COSE %d) during %s.",
            label,
            alg_id,
            stage,
        )
    else:
        app.logger.info(
            "Using classical algorithm %s (COSE %d) during %s.", label, alg_id, stage
        )


__all__ = [
    "describe_algorithm",
    "detect_available_pqc_algorithms",
    "is_pqc_algorithm",
    "log_algorithm_selection",
    "PQC_ALGORITHM_ID_TO_NAME",
]

