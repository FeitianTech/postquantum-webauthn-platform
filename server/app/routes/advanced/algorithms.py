"""COSE algorithms: naming and coercing them, and which ones a ceremony offers."""
from __future__ import annotations

import logging
import math
import re
from collections.abc import Iterable, Mapping
from typing import Any

from fido2.webauthn import (
    PublicKeyCredentialParameters,
    PublicKeyCredentialType,
)

from ...webauthn import pqc
from . import constants

logger = logging.getLogger(__name__)

# What a registration offers when its request names no algorithms.
_DEFAULT_REGISTRATION_ALGORITHMS = (-50, -48, -49, -7, -257)
# What it falls back to when every requested algorithm is an unavailable PQC one.
_CLASSICAL_FALLBACK_ALGORITHMS = (-7, -8, -257)


def _normalize_algorithm_name_key(name: str) -> str:
    base = name.strip().split("(")[0]
    if not base:
        return ""
    sanitized = re.sub(r"[^A-Z0-9]", "", base.upper())
    if sanitized.startswith("FIDOALG"):
        sanitized = sanitized[len("FIDOALG"):]
    if sanitized.startswith("COSEALG"):
        sanitized = sanitized[len("COSEALG"):]
    return sanitized


def _lookup_named_cose_algorithm(
    name: str,
) -> int | None:
    normalized_name = _normalize_algorithm_name_key(name)
    if not normalized_name:
        return None

    direct_match = constants.COSE_ALGORITHM_NAME_LOOKUP.get(normalized_name)
    if direct_match is not None:
        return direct_match

    for alias_key, alg_value in constants.COSE_ALGORITHM_NAME_LOOKUP.items():
        if normalized_name.endswith(alias_key):
            return alg_value
    return None


def _coerce_cose_algorithm(
    value: Any,
) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if math.isfinite(value) and value.is_integer():
            return int(value)
        return None
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            return int(stripped, 10)
        except ValueError:
            normalized_alg = _lookup_named_cose_algorithm(stripped)
            if normalized_alg is not None:
                return normalized_alg
            matches = list(constants.COSE_ALGORITHM_NUMERIC_PATTERN.finditer(stripped))
            if matches:
                try:
                    return int(matches[-1].group(0), 10)
                except ValueError:
                    return None
            return None
    return None


def _extract_credential_algorithm(value: Any) -> int | None:
    if isinstance(value, Mapping):
        public_key_value = value.get("public_key") or value.get("publicKey")
    else:
        public_key_value = getattr(value, "public_key", None)

    if isinstance(public_key_value, Mapping):
        if 3 in public_key_value:
            raw_alg = public_key_value[3]
        else:
            raw_alg = public_key_value.get("alg")
    else:
        try:
            raw_alg = public_key_value[3]  # type: ignore[index]
        except Exception:
            raw_alg = getattr(public_key_value, "alg", None)

    return _coerce_cose_algorithm(raw_alg)


def _derive_algorithms_from_credentials(
    credentials: Iterable[Any],
) -> list[PublicKeyCredentialParameters]:
    seen: dict[int, PublicKeyCredentialParameters] = {}
    for credential in credentials:
        alg_value = _extract_credential_algorithm(credential)
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
        return _coerce_cose_algorithm(param)

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
    return _coerce_cose_algorithm(raw_alg_value)


def configure_allowed_algorithms(
    public_key: Mapping[str, Any],
    temp_server: Any,
    warnings: list[str],
) -> None:
    """Set what a registration offers: the requested algorithms, else the defaults, less unavailable PQC."""

    pub_key_cred_params = public_key.get("pubKeyCredParams", [])
    if pub_key_cred_params:
        requested = [alg for alg in map(_requested_algorithm, pub_key_cred_params) if alg is not None]
        if requested:
            public_key["pubKeyCredParams"] = [{"type": "public-key", "alg": alg} for alg in requested]
            temp_server.allowed_algorithms = [_public_key_param(alg) for alg in requested]
    else:
        temp_server.allowed_algorithms = [_public_key_param(alg) for alg in _DEFAULT_REGISTRATION_ALGORITHMS]

    _drop_unavailable_pqc(temp_server, warnings)


def _drop_unavailable_pqc(temp_server: Any, warnings: list[str]) -> None:
    allowed_algorithm_ids = [
        getattr(param, "alg", None)
        for param in getattr(temp_server, "allowed_algorithms", [])
    ]
    allowed_algorithm_ids = [alg for alg in allowed_algorithm_ids if isinstance(alg, int)]

    pqc_in_allowed = {alg for alg in allowed_algorithm_ids if pqc.is_pqc_algorithm(alg)}
    if not pqc_in_allowed:
        return

    pqc_available_ids, pqc_error_message = pqc.detect_available_pqc_algorithms()
    missing_pqc = pqc_in_allowed - pqc_available_ids
    if not missing_pqc:
        return

    missing_names = ", ".join(
        pqc.PQC_ALGORITHM_ID_TO_NAME[alg] for alg in sorted(missing_pqc)
    )
    if pqc_error_message:
        logger.warning("Post-quantum support unavailable: %s", pqc_error_message)
    else:
        logger.warning(
            "Post-quantum algorithms requested (%s) but not available in this environment.",
            missing_names,
        )

    filtered_allowed = [
        param for param in temp_server.allowed_algorithms if getattr(param, "alg", None) not in missing_pqc
    ]
    if filtered_allowed:
        temp_server.allowed_algorithms = filtered_allowed
        warnings.append(f"Unsupported PQC algorithms were skipped ({missing_names}).")
    else:
        temp_server.allowed_algorithms = [_public_key_param(alg) for alg in _CLASSICAL_FALLBACK_ALGORITHMS]
        warnings.append(
            f"Unsupported PQC algorithms were skipped ({missing_names}); falling back to classical algorithms."
        )


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
