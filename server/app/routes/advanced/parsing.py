from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from ...encoding import encode_base64url
from ...webauthn import client_credentials, cose_algorithms
from ...webauthn.attachments import normalize_attachment


def _coerce_optional_bool(value: Any) -> bool | None:
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


def _extract_flag_from_mapping(
    mapping: Mapping[str, Any],
    keys: Iterable[str],
) -> bool | None:
    for key in keys:
        if key in mapping:
            coerced = _coerce_optional_bool(mapping.get(key))
            if coerced is not None:
                return coerced
    return None


_FIELDS = client_credentials.CredentialFields(
    aaguid=("aaguid", "aaguidBase64Url", "aaguidBase64", "aaguidHex"),
    credential_id=("credentialId", "credentialID", "credentialIdBase64Url", "id", "rawId"),
    public_key=("publicKey", "publicKeyBase64", "publicKeyBase64Url", "publicKeyBytes", "publicKeyCbor"),
    default_aaguid=b"\x00" * 16,
    wrappers=True,
)


def _parse_client_supplied_credentials(
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
            material = client_credentials.read_key_material(entry, _FIELDS)
            if material is None:
                continue

            attachment_value = normalize_attachment(
                client_credentials.select_first(entry, ("authenticatorAttachment", "attachment"))
                or (entry.get("properties") or {}).get("authenticatorAttachment")
                or (entry.get("properties") or {}).get("authenticator_attachment")
            )

            raw_alg_value = entry.get("algorithm") or entry.get("publicKeyAlgorithm")
            algorithm_value = cose_algorithms.coerce_cose_algorithm(raw_alg_value)

            resident_flag = _resident_flag(entry)

            records.append(
                {
                    "data": material.attested,
                    "id": material.credential_id,
                    "attachment": attachment_value,
                    "algorithm": algorithm_value,
                    "resident": bool(resident_flag),
                    "signCount": int(entry.get("signCount"))
                    if isinstance(entry.get("signCount"), int) and not isinstance(entry.get("signCount"), bool)
                    else 0,
                }
            )
            serialized.append(_serialized_entry(entry, material, attachment_value, algorithm_value, resident_flag))
        except Exception:
            continue

    return records, serialized


def _resident_flag(entry: Mapping[str, Any]) -> bool:
    """Whether the entry says its credential is discoverable: its own flags, its properties, or credProps."""

    resident_flag = _extract_flag_from_mapping(
        entry,
        ("resident", "residentKey", "discoverable"),
    )
    if resident_flag is None:
        properties = entry.get("properties")
        if isinstance(properties, Mapping):
            resident_flag = _extract_flag_from_mapping(
                properties,
                ("resident", "residentKey", "discoverable", "actualResidentKey"),
            )

    if resident_flag is None:
        client_outputs = entry.get("clientExtensionOutputs")
        if isinstance(client_outputs, Mapping):
            cred_props_value = client_outputs.get("credProps")
            if isinstance(cred_props_value, Mapping):
                resident_flag = _coerce_optional_bool(cred_props_value.get("rk"))
            elif isinstance(cred_props_value, bool):
                resident_flag = cred_props_value

    if resident_flag is None:
        resident_flag = False
    return resident_flag


def _serialized_entry(
    entry: Mapping[str, Any],
    material: client_credentials.KeyMaterial,
    attachment_value: Any,
    algorithm_value: Any,
    resident_flag: bool,
) -> dict[str, Any]:
    serialized_entry: dict[str, Any] = {
        "credentialId": encode_base64url(material.credential_id),
        "publicKey": encode_base64url(material.public_key),
        "signCount": int(entry.get("signCount")) if isinstance(entry.get("signCount"), int) else 0,
        "resident": bool(resident_flag),
    }
    if material.aaguid:
        serialized_entry["aaguid"] = encode_base64url(material.aaguid)
    if attachment_value:
        serialized_entry["authenticatorAttachment"] = attachment_value
    if algorithm_value is not None:
        serialized_entry["algorithm"] = algorithm_value
    return serialized_entry
