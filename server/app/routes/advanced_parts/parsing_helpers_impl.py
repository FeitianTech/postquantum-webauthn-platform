from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from fido2 import cbor
from fido2.cose import CoseKey
from fido2.webauthn import AttestedCredentialData

from ...attachments import normalize_attachment
from ...encoding import encode_base64url
from . import algorithm_helpers_impl, binary_helpers_impl


def _extract_credential_id_impl(value: Any) -> bytes | None:
    credential_id = None
    if isinstance(value, Mapping):
        raw_id = value.get("credential_id")
        if isinstance(raw_id, (bytes, bytearray, memoryview)):
            credential_id = bytes(raw_id)
    else:
        raw_id = getattr(value, "credential_id", None)
        if isinstance(raw_id, (bytes, bytearray, memoryview)):
            credential_id = bytes(raw_id)
    return credential_id


def _coerce_optional_bool_impl(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    if isinstance(value, (int, float)):
        if isinstance(value, bool):  # pragma: no cover - defensive guard
            return bool(value)
        if value != value:  # NaN check
            return None
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    return None


def _extract_flag_from_mapping_impl(
    mapping: Mapping[str, Any],
    keys: Iterable[str],
) -> bool | None:
    for key in keys:
        if key in mapping:
            coerced = _coerce_optional_bool_impl(mapping.get(key))
            if coerced is not None:
                return coerced
    return None


def _select_first_impl(mapping: Mapping[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in mapping:
            value = mapping[key]
            if value is not None:
                return value
    return None


def _parse_client_supplied_credentials_impl(
    raw_credentials: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(raw_credentials, list):
        return [], []

    records: list[dict[str, Any]] = []
    serialized: list[dict[str, Any]] = []

    for entry in raw_credentials:
        if not isinstance(entry, Mapping):
            continue

        try:
            aaguid_raw = _select_first_impl(
                entry,
                ("aaguid", "aaguidBase64Url", "aaguidBase64", "aaguidHex"),
            )
            credential_id_raw = _select_first_impl(
                entry,
                ("credentialId", "credentialID", "credentialIdBase64Url", "id", "rawId"),
            )
            public_key_raw = _select_first_impl(
                entry,
                ("publicKey", "publicKeyBase64", "publicKeyBase64Url", "publicKeyBytes", "publicKeyCbor"),
            )
            if credential_id_raw is None or public_key_raw is None:
                continue

            aaguid_bytes = b"\x00" * 16 if aaguid_raw is None else binary_helpers_impl._decode_client_binary_impl(aaguid_raw)
            credential_id_bytes = binary_helpers_impl._decode_client_binary_impl(credential_id_raw)
            public_key_bytes = binary_helpers_impl._decode_client_binary_impl(public_key_raw)

            cose_key = CoseKey.parse(cbor.decode(public_key_bytes))
            attested = AttestedCredentialData.create(aaguid_bytes, credential_id_bytes, cose_key)

            attachment_value = normalize_attachment(
                _select_first_impl(entry, ("authenticatorAttachment", "attachment"))
                or (entry.get("properties") or {}).get("authenticatorAttachment")
                or (entry.get("properties") or {}).get("authenticator_attachment")
            )

            raw_alg_value = entry.get("algorithm") or entry.get("publicKeyAlgorithm")
            algorithm_value = algorithm_helpers_impl._coerce_cose_algorithm_impl(raw_alg_value)

            resident_flag = _extract_flag_from_mapping_impl(
                entry,
                ("resident", "residentKey", "discoverable"),
            )
            if resident_flag is None:
                properties = entry.get("properties")
                if isinstance(properties, Mapping):
                    resident_flag = _extract_flag_from_mapping_impl(
                        properties,
                        ("resident", "residentKey", "discoverable", "actualResidentKey"),
                    )

            if resident_flag is None:
                client_outputs = entry.get("clientExtensionOutputs")
                if isinstance(client_outputs, Mapping):
                    cred_props_value = client_outputs.get("credProps")
                    if isinstance(cred_props_value, Mapping):
                        resident_flag = _coerce_optional_bool_impl(cred_props_value.get("rk"))
                    elif isinstance(cred_props_value, bool):
                        resident_flag = cred_props_value

            if resident_flag is None:
                resident_flag = False

            records.append(
                {
                    "data": attested,
                    "id": credential_id_bytes,
                    "attachment": attachment_value,
                    "algorithm": algorithm_value,
                    "resident": bool(resident_flag),
                    "signCount": int(entry.get("signCount"))
                    if isinstance(entry.get("signCount"), int) and not isinstance(entry.get("signCount"), bool)
                    else 0,
                }
            )

            serialized_entry: dict[str, Any] = {
                "credentialId": encode_base64url(credential_id_bytes),
                "publicKey": encode_base64url(public_key_bytes),
                "signCount": int(entry.get("signCount")) if isinstance(entry.get("signCount"), int) else 0,
                "resident": bool(resident_flag),
            }
            if aaguid_bytes:
                serialized_entry["aaguid"] = encode_base64url(aaguid_bytes)
            if attachment_value:
                serialized_entry["authenticatorAttachment"] = attachment_value
            if algorithm_value is not None:
                serialized_entry["algorithm"] = algorithm_value

            serialized.append(serialized_entry)
        except Exception:
            continue

    return records, serialized
