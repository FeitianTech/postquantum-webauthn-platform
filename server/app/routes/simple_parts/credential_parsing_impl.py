from __future__ import annotations

from typing import Any, Dict, List, Mapping, Tuple


_AAGUID_SESSION_FIELD_PRECEDENCE = (
    "aaguid",
    "aaguidBase64",
    "aaguidBase64Url",
)

_AAGUID_PARSE_FIELD_PRECEDENCE = (
    "aaguid",
    "aaguidBase64",
    "aaguidBase64Url",
    "aaguidHex",
)

_CREDENTIAL_ID_SESSION_FIELD_PRECEDENCE = (
    "credentialIdBase64Url",
    "credentialId",
    "credentialID",
    "id",
    "rawId",
)

_CREDENTIAL_ID_PARSE_FIELD_PRECEDENCE = (
    "credentialId",
    "credentialIdBase64Url",
    "credentialID",
    "id",
    "rawId",
)

_PUBLIC_KEY_FIELD_PRECEDENCE = (
    "publicKey",
    "publicKeyBase64",
    "publicKeyBase64Url",
    "publicKeyCbor",
)


def _serialize_credential_for_session_impl(simple_module: Any, entry: Mapping[str, Any]) -> Dict[str, Any]:
    serialized: Dict[str, Any] = {}
    for source_key, dest_key in (
        ("email", "email"),
        ("userName", "userName"),
        ("displayName", "displayName"),
        ("signCount", "signCount"),
        ("algorithm", "algorithm"),
        ("publicKeyAlgorithm", "publicKeyAlgorithm"),
        ("type", "type"),
    ):
        if source_key in entry:
            serialized[dest_key] = entry[source_key]

    aaguid_value = simple_module._select_first(entry, _AAGUID_SESSION_FIELD_PRECEDENCE)
    if aaguid_value is None and "aaguidHex" in entry:
        aaguid_value = entry["aaguidHex"]

    credential_id_value = simple_module._select_first(
        entry,
        _CREDENTIAL_ID_SESSION_FIELD_PRECEDENCE,
    )

    public_key_value = simple_module._select_first(
        entry,
        _PUBLIC_KEY_FIELD_PRECEDENCE,
    )

    if aaguid_value is not None:
        aaguid_bytes = simple_module._decode_binary_value(aaguid_value)
        serialized["aaguid"] = simple_module.base64.urlsafe_b64encode(aaguid_bytes).decode("ascii").rstrip("=")

    if credential_id_value is not None:
        credential_id_bytes = simple_module._decode_binary_value(credential_id_value)
        serialized["credentialId"] = (
            simple_module.base64.urlsafe_b64encode(credential_id_bytes).decode("ascii").rstrip("=")
        )

    if public_key_value is not None:
        public_key_bytes = simple_module._decode_binary_value(public_key_value)
        serialized["publicKey"] = simple_module.base64.urlsafe_b64encode(public_key_bytes).decode("ascii").rstrip("=")

    return serialized


def _parse_client_credentials_impl(
    simple_module: Any, raw_credentials: Any
) -> Tuple[List[Any], List[Dict[str, Any]]]:
    if not isinstance(raw_credentials, list):
        return [], []

    attested_credentials: List[Any] = []
    serialized_entries: List[Dict[str, Any]] = []

    for entry in raw_credentials:
        if not isinstance(entry, Mapping):
            continue

        try:
            aaguid_raw = simple_module._select_first(
                entry,
                _AAGUID_PARSE_FIELD_PRECEDENCE,
            )
            credential_id_raw = simple_module._select_first(
                entry,
                _CREDENTIAL_ID_PARSE_FIELD_PRECEDENCE,
            )
            public_key_raw = simple_module._select_first(
                entry,
                _PUBLIC_KEY_FIELD_PRECEDENCE,
            )

            if aaguid_raw is None or credential_id_raw is None or public_key_raw is None:
                continue

            aaguid_bytes = simple_module._decode_binary_value(aaguid_raw)
            credential_id_bytes = simple_module._decode_binary_value(credential_id_raw)
            public_key_bytes = simple_module._decode_binary_value(public_key_raw)

            cose_key = simple_module.CoseKey.parse(simple_module.cbor.decode(public_key_bytes))

            attested = simple_module.AttestedCredentialData.create(
                aaguid_bytes,
                credential_id_bytes,
                cose_key,
            )

            attested_credentials.append(attested)

            serialized_entry = simple_module._serialize_credential_for_session(entry)
            serialized_entry.setdefault(
                "credentialId",
                simple_module.base64.urlsafe_b64encode(credential_id_bytes).decode("ascii").rstrip("="),
            )
            serialized_entry.setdefault(
                "aaguid",
                simple_module.base64.urlsafe_b64encode(aaguid_bytes).decode("ascii").rstrip("="),
            )
            serialized_entry.setdefault(
                "publicKey",
                simple_module.base64.urlsafe_b64encode(public_key_bytes).decode("ascii").rstrip("="),
            )
            if "signCount" not in serialized_entry and isinstance(entry.get("signCount"), int):
                serialized_entry["signCount"] = entry["signCount"]
            algorithm_value = entry.get("algorithm") or entry.get("publicKeyAlgorithm")
            if isinstance(algorithm_value, int):
                serialized_entry["algorithm"] = algorithm_value

            serialized_entries.append(serialized_entry)
        except Exception:
            continue

    return attested_credentials, serialized_entries
