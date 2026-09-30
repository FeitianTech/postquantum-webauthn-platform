"""COSE algorithms: naming and coercing them, and which ones a ceremony offers."""
from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from typing import Any

from fido2.cose import CoseKey
from fido2.webauthn import (
    PublicKeyCredentialParameters,
    PublicKeyCredentialType,
)

from ...webauthn import cose_algorithms, pqc

logger = logging.getLogger(__name__)

# What a registration offers when its request names no algorithms.
_DEFAULT_REGISTRATION_ALGORITHMS = (-50, -48, -49, -7, -257)


def _verifiable_algorithms() -> set[int]:
    """The COSE algorithms fido2 verifies here: ML-DSA only where cryptography's backend has it."""

    return set(CoseKey.supported_algorithms())


def _derive_algorithms_from_credentials(
    credentials: Iterable[Any],
) -> list[PublicKeyCredentialParameters]:
    seen: dict[int, PublicKeyCredentialParameters] = {}
    for credential in credentials:
        alg_value = cose_algorithms.credential_algorithm(credential)
        if alg_value is None or alg_value in seen:
            continue
        seen[alg_value] = PublicKeyCredentialParameters(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            alg=alg_value,
        )

    return list(seen.values())


def _public_key_param(alg: int) -> PublicKeyCredentialParameters:
    return PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=alg)


def _requested_algorithm(param: Any) -> int | None:
    """The algorithm one ``pubKeyCredParams`` entry asks for; ``None`` skips the entry."""

    if not isinstance(param, Mapping):
        return cose_algorithms.coerce_cose_algorithm(param)

    raw_alg_value = param.get("alg")
    if raw_alg_value is None:
        raw_alg_value = param.get("id")
    if raw_alg_value is None:
        raw_alg_value = param.get("value")

    type_value = param.get("type")
    if isinstance(type_value, str):
        if type_value.strip().lower() != "public-key":
            return None
    elif type_value is not None:
        return None
    return cose_algorithms.coerce_cose_algorithm(raw_alg_value)


def configure_allowed_algorithms(
    public_key: Mapping[str, Any],
    temp_server: Any,
    warnings: list[str],
) -> str | None:
    """Set what a registration offers: the requested algorithms, else the defaults, less
    the ML-DSA ones fido2 cannot verify here. Gives the refusal when nothing is left."""

    pub_key_cred_params = public_key.get("pubKeyCredParams", [])
    if pub_key_cred_params:
        requested = [alg for alg in map(_requested_algorithm, pub_key_cred_params) if alg is not None]
        if requested:
            public_key["pubKeyCredParams"] = [{"type": "public-key", "alg": alg} for alg in requested]
            temp_server.allowed_algorithms = [_public_key_param(alg) for alg in requested]
    else:
        temp_server.allowed_algorithms = [_public_key_param(alg) for alg in _DEFAULT_REGISTRATION_ALGORITHMS]

    return _drop_unavailable_pqc(temp_server, warnings)


def _drop_unavailable_pqc(temp_server: Any, warnings: list[str]) -> str | None:
    allowed_algorithm_ids = [
        getattr(param, "alg", None)
        for param in getattr(temp_server, "allowed_algorithms", [])
    ]
    allowed_algorithm_ids = [alg for alg in allowed_algorithm_ids if isinstance(alg, int)]

    pqc_in_allowed = {alg for alg in allowed_algorithm_ids if pqc.is_pqc_algorithm(alg)}
    missing_pqc = pqc_in_allowed - _verifiable_algorithms()
    if not missing_pqc:
        return None

    missing_names = ", ".join(pqc.PQC_ALGORITHM_ID_TO_NAME[alg] for alg in sorted(missing_pqc))
    logger.warning("Post-quantum algorithms requested (%s) but not verifiable here.", missing_names)
    filtered_allowed = [
        param for param in temp_server.allowed_algorithms if getattr(param, "alg", None) not in missing_pqc
    ]
    if not filtered_allowed:
        return f"None of the requested algorithms can be verified by this server ({missing_names})."
    temp_server.allowed_algorithms = filtered_allowed
    warnings.append(f"Unsupported PQC algorithms were skipped ({missing_names}).")
    return None


def advertised_algorithm_params(temp_server: Any) -> list[dict[str, Any]]:
    """The ``pubKeyCredParams`` a registration advertises: the server's allowed algorithms."""

    return [
        {
            "type": (
                getattr(param.type, "value", param.type)
                if hasattr(param, "type")
                else "public-key"
            ),
            "alg": getattr(param, "alg", None),
        }
        for param in temp_server.allowed_algorithms
        if getattr(param, "alg", None) is not None
    ]
