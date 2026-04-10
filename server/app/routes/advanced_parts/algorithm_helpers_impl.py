from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional

from fido2.webauthn import (
    PublicKeyCredentialParameters,
    PublicKeyCredentialType,
)


def _normalize_algorithm_name_key_impl(advanced_module: Any, name: str) -> str:
    base = name.strip().split("(")[0]
    if not base:
        return ""
    sanitized = advanced_module.re.sub(r"[^A-Z0-9]", "", base.upper())
    if sanitized.startswith("FIDOALG"):
        sanitized = sanitized[len("FIDOALG"):]
    if sanitized.startswith("COSEALG"):
        sanitized = sanitized[len("COSEALG"):]
    return sanitized


def _lookup_named_cose_algorithm_impl(
    advanced_module: Any,
    name: str,
) -> Optional[int]:
    normalized_name = advanced_module._normalize_algorithm_name_key(name)
    if not normalized_name:
        return None

    direct_match = advanced_module._COSE_ALGORITHM_NAME_LOOKUP.get(normalized_name)
    if direct_match is not None:
        return direct_match

    for alias_key, alg_value in advanced_module._COSE_ALGORITHM_NAME_LOOKUP.items():
        if normalized_name.endswith(alias_key):
            return alg_value
    return None


def _coerce_cose_algorithm_impl(
    advanced_module: Any,
    value: Any,
) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if advanced_module.math.isfinite(value) and value.is_integer():
            return int(value)
        return None
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            return int(stripped, 10)
        except ValueError:
            normalized_alg = advanced_module._lookup_named_cose_algorithm(stripped)
            if normalized_alg is not None:
                return normalized_alg
            matches = list(advanced_module._COSE_ALGORITHM_NUMERIC_PATTERN.finditer(stripped))
            if matches:
                try:
                    return int(matches[-1].group(0), 10)
                except ValueError:
                    return None
            return None
    return None


def _extract_credential_algorithm_impl(advanced_module: Any, value: Any) -> Optional[int]:
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

    return advanced_module._coerce_cose_algorithm(raw_alg)


def _derive_algorithms_from_credentials_impl(
    advanced_module: Any,
    credentials: Iterable[Any],
) -> List[PublicKeyCredentialParameters]:
    seen: Dict[int, PublicKeyCredentialParameters] = {}
    for credential in credentials:
        alg_value = advanced_module._extract_credential_algorithm(credential)
        if alg_value is None or alg_value in seen:
            continue
        seen[alg_value] = PublicKeyCredentialParameters(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            alg=alg_value,
        )

    return list(seen.values())


def _is_custom_cose_algorithm_impl(advanced_module: Any, alg_id: Optional[int]) -> bool:
    if alg_id is None:
        return False
    if alg_id in advanced_module._COSE_ALGORITHM_NAME_MAP.values():
        return False
    if alg_id in advanced_module.PQC_ALGORITHM_ID_TO_NAME:
        return False
    return True


def _extract_requested_assertion_algorithm_impl(
    advanced_module: Any,
    public_key: Mapping[str, Any],
    credential_id: Optional[bytes],
) -> Optional[int]:
    requested_alg = advanced_module._coerce_cose_algorithm(public_key.get("alg"))
    if isinstance(requested_alg, int):
        return requested_alg

    allow_credentials = public_key.get("allowCredentials")
    if not isinstance(allow_credentials, list):
        return None

    fallback_alg: Optional[int] = None
    for entry in allow_credentials:
        if not isinstance(entry, Mapping):
            continue

        entry_alg = advanced_module._coerce_cose_algorithm(entry.get("alg"))
        if entry_alg is None:
            continue

        entry_id = advanced_module._extract_binary_value(entry.get("id"))
        if isinstance(entry_id, str):
            try:
                entry_id = bytes.fromhex(entry_id)
            except ValueError:
                try:
                    entry_id = advanced_module._decode_base64url(entry_id)
                except (ValueError, TypeError):
                    entry_id = None

        if isinstance(entry_id, (bytes, bytearray, memoryview)):
            if credential_id is not None and bytes(entry_id) == credential_id:
                return entry_alg
            fallback_alg = entry_alg

    return fallback_alg
