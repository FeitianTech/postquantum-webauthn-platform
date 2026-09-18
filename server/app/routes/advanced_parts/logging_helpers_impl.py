from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from ... import attestation, config, pqc
from . import binary_helpers_impl


def _log_authenticator_attestation_response_impl(
    advanced_module: Any,
    attestation_format: str | None,
    auth_data: Any,
    attestation_statement: Any,
    raw_attestation_object: Any,
) -> None:
    if auth_data is None:
        return

    payload: dict[str, Any] = {}
    if attestation_format:
        payload["fmt"] = attestation_format

    auth_data_payload: dict[str, Any] = {}
    rp_id_hash = getattr(auth_data, "rp_id_hash", None)
    if isinstance(rp_id_hash, (bytes, bytearray, memoryview)):
        auth_data_payload["rpIdHash"] = bytes(rp_id_hash).hex()

    flags_value = getattr(auth_data, "flags", None)
    if isinstance(flags_value, int):
        auth_data_payload["flags"] = {"value": flags_value, "hex": f"0x{flags_value:02x}"}
        flag_breakdown: dict[str, bool] = {}
        flag_names = ("UP", "UV", "BE", "BS", "AT", "ED")
        flag_enum = getattr(auth_data, "FLAG", None)
        for name in flag_names:
            bit_value = getattr(flag_enum, name, None) if flag_enum is not None else None
            if isinstance(bit_value, int):
                flag_breakdown[name] = bool(flags_value & bit_value)
        if flag_breakdown:
            auth_data_payload["flagsDecoded"] = flag_breakdown

    counter_value = getattr(auth_data, "counter", None)
    if isinstance(counter_value, int):
        auth_data_payload["counter"] = counter_value

    try:
        auth_data_payload["rawHex"] = bytes(auth_data).hex()
    except Exception:  # pragma: no cover - defensive guard
        pass

    credential_data = getattr(auth_data, "credential_data", None)
    if credential_data is not None:
        credential_payload: dict[str, Any] = {}

        aaguid_value = getattr(credential_data, "aaguid", None)
        if isinstance(aaguid_value, (bytes, bytearray, memoryview)):
            credential_payload["aaguid"] = bytes(aaguid_value).hex()

        credential_id_value = getattr(credential_data, "credential_id", None)
        if isinstance(credential_id_value, (bytes, bytearray, memoryview)):
            credential_id_bytes = bytes(credential_id_value)
            credential_payload["credentialId"] = binary_helpers_impl._encode_base64url_impl(credential_id_bytes)
            credential_payload["credentialIdLength"] = len(credential_id_bytes)

        public_key_value = getattr(credential_data, "public_key", None)
        if isinstance(public_key_value, Mapping):
            public_key_dict = dict(public_key_value)
            credential_payload["credentialPublicKey"] = attestation.make_json_safe(public_key_dict)

            algorithm_value: int | None = None
            if 3 in public_key_dict:
                algorithm_value = advanced_module._coerce_cose_algorithm(public_key_dict[3])
            elif "alg" in public_key_dict:
                algorithm_value = advanced_module._coerce_cose_algorithm(public_key_dict["alg"])

            if algorithm_value is not None:
                credential_payload["credentialPublicKeyAlgorithm"] = {
                    "id": algorithm_value,
                    "label": pqc.describe_algorithm(algorithm_value),
                }

        if credential_payload:
            auth_data_payload["attestedCredentialData"] = credential_payload

    extensions_value = getattr(auth_data, "extensions", None)
    if isinstance(extensions_value, Mapping):
        auth_data_payload["extensions"] = attestation.make_json_safe(dict(extensions_value))

    payload["authData"] = auth_data_payload

    if attestation_statement:
        payload["attStmt"] = attestation.make_json_safe(attestation_statement)

    if isinstance(raw_attestation_object, (bytes, bytearray, memoryview)):
        payload["rawAttestationObject"] = binary_helpers_impl._encode_base64url_impl(bytes(raw_attestation_object))
    elif isinstance(raw_attestation_object, str):
        payload["rawAttestationObject"] = raw_attestation_object

    try:
        message = json.dumps(payload, indent=2, sort_keys=True)
    except TypeError:
        message = str(payload)

    config.app.logger.info("Authenticator attestation response:\n%s", message)


def datetime_from_timestamp_impl(advanced_module: Any, timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
