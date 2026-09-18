from __future__ import annotations

import base64
from collections.abc import Mapping
from typing import Any

from fido2 import cbor
from fido2.cose import CoseKey
from fido2.webauthn import AttestedCredentialData

from . import binary_helpers_impl

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


def _serialize_credential_for_session_impl(entry: Mapping[str, Any]) -> dict[str, Any]:
    serialized: dict[str, Any] = {}
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

    aaguid_value = binary_helpers_impl._select_first_impl(entry, _AAGUID_SESSION_FIELD_PRECEDENCE)
    if aaguid_value is None and "aaguidHex" in entry:
        aaguid_value = entry["aaguidHex"]

    credential_id_value = binary_helpers_impl._select_first_impl(
        entry,
        _CREDENTIAL_ID_SESSION_FIELD_PRECEDENCE,
    )

    public_key_value = binary_helpers_impl._select_first_impl(
        entry,
        _PUBLIC_KEY_FIELD_PRECEDENCE,
    )

    if aaguid_value is not None:
        aaguid_bytes = binary_helpers_impl._decode_binary_value_impl(aaguid_value)
        serialized["aaguid"] = base64.urlsafe_b64encode(aaguid_bytes).decode("ascii").rstrip("=")

    if credential_id_value is not None:
        credential_id_bytes = binary_helpers_impl._decode_binary_value_impl(credential_id_value)
        serialized["credentialId"] = (
            base64.urlsafe_b64encode(credential_id_bytes).decode("ascii").rstrip("=")
        )

    if public_key_value is not None:
        public_key_bytes = binary_helpers_impl._decode_binary_value_impl(public_key_value)
        serialized["publicKey"] = base64.urlsafe_b64encode(public_key_bytes).decode("ascii").rstrip("=")

    return serialized


def _parse_client_credentials_impl(
    raw_credentials: Any
) -> tuple[list[Any], list[dict[str, Any]]]:
    if not isinstance(raw_credentials, list):
        return [], []

    attested_credentials: list[Any] = []
    serialized_entries: list[dict[str, Any]] = []

    for entry in raw_credentials:
        if not isinstance(entry, Mapping):
            continue

        try:
            aaguid_raw = binary_helpers_impl._select_first_impl(
                entry,
                _AAGUID_PARSE_FIELD_PRECEDENCE,
            )
            credential_id_raw = binary_helpers_impl._select_first_impl(
                entry,
                _CREDENTIAL_ID_PARSE_FIELD_PRECEDENCE,
            )
            public_key_raw = binary_helpers_impl._select_first_impl(
                entry,
                _PUBLIC_KEY_FIELD_PRECEDENCE,
            )

            if aaguid_raw is None or credential_id_raw is None or public_key_raw is None:
                continue

            aaguid_bytes = binary_helpers_impl._decode_binary_value_impl(aaguid_raw)
            credential_id_bytes = binary_helpers_impl._decode_binary_value_impl(credential_id_raw)
            public_key_bytes = binary_helpers_impl._decode_binary_value_impl(public_key_raw)

            cose_key = CoseKey.parse(cbor.decode(public_key_bytes))

            attested = AttestedCredentialData.create(
                aaguid_bytes,
                credential_id_bytes,
                cose_key,
            )

            attested_credentials.append(attested)

            serialized_entry = _serialize_credential_for_session_impl(entry)
            serialized_entry.setdefault(
                "credentialId",
                base64.urlsafe_b64encode(credential_id_bytes).decode("ascii").rstrip("="),
            )
            serialized_entry.setdefault(
                "aaguid",
                base64.urlsafe_b64encode(aaguid_bytes).decode("ascii").rstrip("="),
            )
            serialized_entry.setdefault(
                "publicKey",
                base64.urlsafe_b64encode(public_key_bytes).decode("ascii").rstrip("="),
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
