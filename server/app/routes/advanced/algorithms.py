from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from typing import Any

from fido2.webauthn import (
    PublicKeyCredentialParameters,
    PublicKeyCredentialType,
)

from . import constants


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
