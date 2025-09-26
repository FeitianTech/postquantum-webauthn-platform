"""Helpers for integrating liboqs-backed ML-DSA algorithms into the demo server."""

from __future__ import annotations

from typing import Callable, Dict, Iterable, Optional, Sequence, Set, Tuple

from .config import app


# COSE algorithm identifiers mapped to their liboqs mechanism names.
PQC_ALGORITHM_ID_TO_NAME: Dict[int, str] = {
    -50: "ML-DSA-87",
    -49: "ML-DSA-65",
    -48: "ML-DSA-44",
}

_PQC_ALGORITHM_NAME_TO_ID: Dict[str, int] = {
    name: alg_id for alg_id, name in PQC_ALGORITHM_ID_TO_NAME.items()
}


def _load_enabled_mechanisms() -> Iterable[str]:
    """Query liboqs for the list of enabled signature mechanisms."""

    try:  # pragma: no cover - exercised in environments with oqs available
        import oqs  # type: ignore
    except ImportError:  # pragma: no cover - explicit messaging handled by caller
        raise

    enabled: Iterable[str]
    get_enabled: Optional[Callable[[], Sequence[str]]] = getattr(
        oqs, "get_enabled_sig_mechanisms", None
    )
    if callable(get_enabled):
        enabled = get_enabled()
    else:  # pragma: no cover - compatibility fallback for older oqs builds
        algorithms_attr = getattr(getattr(oqs, "Signature", None), "algorithms", None)
        if algorithms_attr is None:
            enabled = ()
        else:
            enabled = algorithms_attr
    return [str(name) for name in enabled]


def detect_available_pqc_algorithms() -> Tuple[Set[int], Optional[str]]:
    """Detect ML-DSA algorithms exposed by liboqs' Python bindings."""

    try:
        mechanism_names = set(_load_enabled_mechanisms())
    except ImportError:
        return set(), (
            "Post-quantum algorithms require the 'oqs' Python bindings (liboqs). "
            "Install the python-fido2-webauthn-test[pqc] extra and ensure liboqs is present."
        )
    except Exception as exc:  # pragma: no cover - defensive logging path
        app.logger.exception("Failed to enumerate oqs signature mechanisms: %%s", exc)
        return set(), "Unable to enumerate post-quantum algorithms from the oqs bindings."

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
        "The installed 'oqs' bindings do not include support for: "
        + ", ".join(missing)
        + ". Rebuild liboqs with ML-DSA enabled or install an updated wheel."
    )


def is_pqc_algorithm(alg_id: int) -> bool:
    """Return ``True`` if the COSE algorithm corresponds to an ML-DSA option."""

    return alg_id in PQC_ALGORITHM_ID_TO_NAME


def describe_algorithm(alg_id: Optional[int]) -> str:
    """Return a friendly label for the given COSE algorithm identifier."""

    if alg_id is None:
        return "Unknown"
    name = PQC_ALGORITHM_ID_TO_NAME.get(alg_id)
    if name:
        return f"{name} (PQC)"
    if alg_id == -8:
        return "EdDSA"
    if alg_id == -7:
        return "ES256 (ECDSA)"
    if alg_id == -47:
        return "ES256K (ECDSA)"
    if alg_id == -35:
        return "ES384 (ECDSA)"
    if alg_id == -36:
        return "ES512 (ECDSA)"
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


def log_algorithm_selection(stage: str, alg_id: Optional[int]) -> None:
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

