"""Routes for the advanced JSON editor flows."""
from __future__ import annotations

import base64
import binascii
import json
import math
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional

from flask import jsonify, request, session
from fido2 import cbor
from fido2.cose import CoseKey
from fido2.webauthn import (
    AttestationConveyancePreference,
    AttestedCredentialData,
    AuthenticatorAttachment,
    AuthenticatorData,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from ..attachments import (
    normalize_attachment,
    normalize_attachment_list,
    resolve_effective_attachments,
)
from ..attestation import (
    augment_aaguid_fields,
    extract_attestation_details,
    extract_min_pin_length,
    make_json_safe,
    perform_attestation_checks,
    summarize_authenticator_extensions,
)
from ..config import (
    app,
    build_rp_entity,
    create_fido_server,
    determine_rp_id,
)
from ..pqc import (
    PQC_ALGORITHM_ID_TO_NAME,
    describe_algorithm,
    detect_available_pqc_algorithms,
    is_pqc_algorithm,
    log_algorithm_selection,
)
from ..storage import add_public_key_material, convert_bytes_for_json, readkey


_COSE_ALGORITHM_NAME_MAP: Dict[str, int] = {
    "ML-DSA-87": -50,
    "ML-DSA-65": -49,
    "ML-DSA-44": -48,
    "EDDSA": -8,
    "ED25519": -19,
    "ED448": -53,
    "ES256": -7,
    "ECDSA256": -7,
    "ECDSA-256": -7,
    "ES256K": -47,
    "ESP256": -9,
    "ESP-256": -9,
    "ES384": -35,
    "ES512": -36,
    "ESP384": -51,
    "ESP-384": -51,
    "ESP512": -52,
    "ESP-512": -52,
    "RS256": -257,
    "RSA256": -257,
    "RS384": -258,
    "RSA384": -258,
    "RS512": -259,
    "RSA512": -259,
    "RS1": -65535,
    "RSASSA-PKCS1-V1_5-SHA1": -65535,
    "PS256": -37,
    "PS384": -38,
    "PS512": -39,
}


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


_COSE_ALGORITHM_NAME_LOOKUP: Dict[str, int] = {}
for raw_name, alg_id in _COSE_ALGORITHM_NAME_MAP.items():
    normalized_key = _normalize_algorithm_name_key(raw_name)
    if normalized_key:
        _COSE_ALGORITHM_NAME_LOOKUP[normalized_key] = alg_id


_COSE_ALGORITHM_NUMERIC_PATTERN = re.compile(r"-?\d+")


def _extract_credential_id(value: Any) -> Optional[bytes]:
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


def _extract_credential_algorithm(value: Any) -> Optional[int]:
    None
    if isinstance(value, Mapping):
        public_key_value = value.get("public_key") or value.get("publicKey")
    else:
        public_key_value = getattr(value, "public_key", None)

    None
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




def _coerce_optional_bool(value: Any) -> Optional[bool]:
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


def _extract_flag_from_mapping(mapping: Mapping[str, Any], keys: Iterable[str]) -> Optional[bool]:
    for key in keys:
        if key in mapping:
            coerced = _coerce_optional_bool(mapping.get(key))
            if coerced is not None:
                return coerced
    return None


def _select_first(mapping: Mapping[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in mapping:
            value = mapping[key]
            if value is not None:
                return value
    return None


def _decode_client_binary(value: Any) -> bytes:
    if value is None:
        raise ValueError("missing binary value")

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)

    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            raise ValueError("empty binary value")

        for decoder in (
            lambda candidate: base64.urlsafe_b64decode(candidate + "=" * ((4 - len(candidate) % 4) % 4)),
            lambda candidate: base64.b64decode(candidate + "=" * ((4 - len(candidate) % 4) % 4)),
        ):
            try:
                return decoder(stripped)
            except (ValueError, TypeError, binascii.Error):
                continue

        try:
            return bytes.fromhex(stripped)
        except ValueError as exc:
            raise ValueError("invalid binary value") from exc

    if isinstance(value, Mapping):
        for key in ("$base64url", "base64url", "$base64", "base64", "$hex", "hex"):
            if key in value and value[key] is not None:
                return _decode_client_binary(value[key])

    raise ValueError("unsupported binary value type")


def _parse_client_supplied_credentials(raw_credentials: Any) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    if not isinstance(raw_credentials, list):
        return [], []

    records: List[Dict[str, Any]] = []
    serialized: List[Dict[str, Any]] = []

    for entry in raw_credentials:
        if not isinstance(entry, Mapping):
            continue

        try:
            aaguid_raw = _select_first(
                entry,
                (
                    "aaguid",
                    "aaguidBase64Url",
                    "aaguidBase64",
                    "aaguidHex",
                ),
            )
            credential_id_raw = _select_first(
                entry,
                (
                    "credentialId",
                    "credentialID",
                    "credentialIdBase64Url",
                    "id",
                    "rawId",
                ),
            )
            public_key_raw = _select_first(
                entry,
                (
                    "publicKey",
                    "publicKeyBase64",
                    "publicKeyBase64Url",
                    "publicKeyBytes",
                    "publicKeyCbor",
                ),
            )

            if credential_id_raw is None or public_key_raw is None:
                continue

            if aaguid_raw is None:
                aaguid_bytes = b"\x00" * 16
            else:
                aaguid_bytes = _decode_client_binary(aaguid_raw)
            credential_id_bytes = _decode_client_binary(credential_id_raw)
            public_key_bytes = _decode_client_binary(public_key_raw)

            cose_key = CoseKey.parse(cbor.decode(public_key_bytes))

            attested = AttestedCredentialData.create(
                aaguid_bytes,
                credential_id_bytes,
                cose_key,
            )

            attachment_value = normalize_attachment(
                _select_first(
                    entry,
                    ("authenticatorAttachment", "attachment"),
                )
                or (entry.get("properties") or {}).get("authenticatorAttachment")
                or (entry.get("properties") or {}).get("authenticator_attachment")
            )

            raw_alg_value = entry.get("algorithm") or entry.get("publicKeyAlgorithm")
            algorithm_value = _coerce_cose_algorithm(raw_alg_value)

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

            record = {
                "data": attested,
                "id": credential_id_bytes,
                "attachment": attachment_value,
                "algorithm": algorithm_value,
                "resident": bool(resident_flag),
            }

            records.append(record)

            serialized_entry: Dict[str, Any] = {
                "credentialId": base64.urlsafe_b64encode(credential_id_bytes).decode("ascii").rstrip("="),
                "publicKey": base64.urlsafe_b64encode(public_key_bytes).decode("ascii").rstrip("="),
                "signCount": int(entry.get("signCount")) if isinstance(entry.get("signCount"), int) else 0,
            }

            if aaguid_bytes:
                serialized_entry["aaguid"] = base64.urlsafe_b64encode(aaguid_bytes).decode("ascii").rstrip("=")
            if attachment_value:
                serialized_entry["authenticatorAttachment"] = attachment_value
            if algorithm_value is not None:
                serialized_entry["algorithm"] = algorithm_value
            serialized_entry["resident"] = bool(resident_flag)

            serialized.append(serialized_entry)
        except Exception:
            continue

    return records, serialized

def _derive_algorithms_from_credentials(credentials: Iterable[Any]) -> List[PublicKeyCredentialParameters]:
    """Produce a list of allowed algorithms based on stored credential data."""

    seen: Dict[int, PublicKeyCredentialParameters] = {}
    for credential in credentials:
        alg_value = _extract_credential_algorithm(credential)
        if alg_value is None or alg_value in seen:
            continue

        seen[alg_value] = PublicKeyCredentialParameters(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            alg=alg_value,
        )

    return list(seen.values())

def _lookup_named_cose_algorithm(name: str) -> Optional[int]:
    normalized_name = _normalize_algorithm_name_key(name)
    if not normalized_name:
        return None
    direct_match = _COSE_ALGORITHM_NAME_LOOKUP.get(normalized_name)
    if direct_match is not None:
        return direct_match
    for alias_key, alg_value in _COSE_ALGORITHM_NAME_LOOKUP.items():
        if normalized_name.endswith(alias_key):
            return alg_value
    return None


def _coerce_cose_algorithm(value: Any) -> Optional[int]:
    """Attempt to coerce a COSE algorithm identifier into an ``int``."""

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
            matches = list(_COSE_ALGORITHM_NUMERIC_PATTERN.finditer(stripped))
            if matches:
                try:
                    return int(matches[-1].group(0), 10)
                except ValueError:
                    return None
            return None
    return None


def _is_custom_cose_algorithm(alg_id: Optional[int]) -> bool:
    """Return ``True`` if the COSE algorithm is not recognised by the demo server."""

    if alg_id is None:
        return False

    if alg_id in _COSE_ALGORITHM_NAME_MAP.values():
        return False

    if alg_id in PQC_ALGORITHM_ID_TO_NAME:
        return False

    return True


def _decode_base64url(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _extract_assertion_credential_id(response: Mapping[str, Any]) -> Optional[bytes]:
    raw_id: Any = None
    if isinstance(response, Mapping):
        raw_id = response.get("rawId") or response.get("id")

    if isinstance(raw_id, (bytes, bytearray, memoryview)):
        return bytes(raw_id)

    if isinstance(raw_id, str):
        try:
            return _decode_base64url(raw_id)
        except (ValueError, TypeError):
            return None

    return None


def _extract_requested_assertion_algorithm(
    public_key: Mapping[str, Any],
    credential_id: Optional[bytes],
) -> Optional[int]:
    """Attempt to determine the requested algorithm for the assertion."""

    requested_alg = _coerce_cose_algorithm(public_key.get("alg"))
    if isinstance(requested_alg, int):
        return requested_alg

    allow_credentials = public_key.get("allowCredentials")
    if not isinstance(allow_credentials, list):
        return None

    fallback_alg: Optional[int] = None
    for entry in allow_credentials:
        if not isinstance(entry, Mapping):
            continue

        entry_alg = _coerce_cose_algorithm(entry.get("alg"))
        if entry_alg is None:
            continue

        entry_id = _extract_binary_value(entry.get("id"))
        if isinstance(entry_id, str):
            try:
                entry_id = bytes.fromhex(entry_id)
            except ValueError:
                try:
                    entry_id = _decode_base64url(entry_id)
                except (ValueError, TypeError):
                    entry_id = None

        if isinstance(entry_id, (bytes, bytearray, memoryview)):
            if credential_id is not None and bytes(entry_id) == credential_id:
                return entry_alg
            fallback_alg = entry_alg

    return fallback_alg


def _extract_binary_value(value: Any) -> Any:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if "$hex" in value:
            return bytes.fromhex(value["$hex"])
        if "$base64" in value:
            return base64.urlsafe_b64decode(value["$base64"] + "==")
        if "$base64url" in value:
            return base64.urlsafe_b64decode(value["$base64url"] + "==")
    return value


def _encode_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _log_authenticator_attestation_response(
    attestation_format: Optional[str],
    auth_data: Any,
    attestation_statement: Any,
    raw_attestation_object: Any,
) -> None:
    """Emit a structured log describing the authenticator's attestation payload."""

    if auth_data is None:
        return

    payload: Dict[str, Any] = {}
    if attestation_format:
        payload["fmt"] = attestation_format

    auth_data_payload: Dict[str, Any] = {}

    rp_id_hash = getattr(auth_data, "rp_id_hash", None)
    if isinstance(rp_id_hash, (bytes, bytearray, memoryview)):
        auth_data_payload["rpIdHash"] = bytes(rp_id_hash).hex()

    flags_value = getattr(auth_data, "flags", None)
    if isinstance(flags_value, int):
        auth_data_payload["flags"] = {"value": flags_value, "hex": f"0x{flags_value:02x}"}
        flag_breakdown: Dict[str, bool] = {}
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
        credential_payload: Dict[str, Any] = {}

        aaguid_value = getattr(credential_data, "aaguid", None)
        if isinstance(aaguid_value, (bytes, bytearray, memoryview)):
            credential_payload["aaguid"] = bytes(aaguid_value).hex()

        credential_id_value = getattr(credential_data, "credential_id", None)
        if isinstance(credential_id_value, (bytes, bytearray, memoryview)):
            credential_id_bytes = bytes(credential_id_value)
            credential_payload["credentialId"] = _encode_base64url(credential_id_bytes)
            credential_payload["credentialIdLength"] = len(credential_id_bytes)

        public_key_value = getattr(credential_data, "public_key", None)
        if isinstance(public_key_value, Mapping):
            public_key_dict = dict(public_key_value)
            credential_payload["credentialPublicKey"] = make_json_safe(public_key_dict)

            algorithm_value: Optional[int] = None
            if 3 in public_key_dict:
                algorithm_value = _coerce_cose_algorithm(public_key_dict[3])
            elif "alg" in public_key_dict:
                algorithm_value = _coerce_cose_algorithm(public_key_dict["alg"])

            if algorithm_value is not None:
                credential_payload["credentialPublicKeyAlgorithm"] = {
                    "id": algorithm_value,
                    "label": describe_algorithm(algorithm_value),
                }

        if credential_payload:
            auth_data_payload["attestedCredentialData"] = credential_payload

    extensions_value = getattr(auth_data, "extensions", None)
    if isinstance(extensions_value, Mapping):
        auth_data_payload["extensions"] = make_json_safe(dict(extensions_value))

    payload["authData"] = auth_data_payload

    if attestation_statement:
        payload["attStmt"] = make_json_safe(attestation_statement)

    if isinstance(raw_attestation_object, (bytes, bytearray, memoryview)):
        payload["rawAttestationObject"] = _encode_base64url(bytes(raw_attestation_object))
    elif isinstance(raw_attestation_object, str):
        payload["rawAttestationObject"] = raw_attestation_object

    try:
        message = json.dumps(payload, indent=2, sort_keys=True)
    except TypeError:
        message = str(payload)

    app.logger.info("Authenticator attestation response:\n%s", message)


@app.route("/api/advanced/register/begin", methods=["POST"])
def advanced_register_begin():
    data = request.get_json(silent=True)

    if not data or not data.get("publicKey"):
        return jsonify({"error": "Invalid request: Missing publicKey in CredentialCreationOptions"}), 400

    public_key = data["publicKey"]

    warnings: List[str] = []

    if not public_key.get("rp"):
        return jsonify({"error": "Missing required field: rp"}), 400
    if not public_key.get("user"):
        return jsonify({"error": "Missing required field: user"}), 400
    if not public_key.get("challenge"):
        return jsonify({"error": "Missing required field: challenge"}), 400

    user_info = public_key["user"]
    username = user_info.get("name", "")
    display_name = user_info.get("displayName", username)

    if not username:
        return jsonify({"error": "Username is required in user.name"}), 400

    user_id_value = user_info.get("id", "")
    if user_id_value:
        try:
            user_id_bytes = _extract_binary_value(user_id_value)
            if isinstance(user_id_bytes, str):
                user_id_bytes = bytes.fromhex(user_id_bytes)
        except (ValueError, TypeError) as exc:
            return jsonify({"error": f"Invalid user ID format: {exc}"}), 400
    else:
        user_id_bytes = username.encode('utf-8')

    challenge_value = public_key.get("challenge", "")
    challenge_bytes = None
    if challenge_value:
        try:
            challenge_bytes = _extract_binary_value(challenge_value)
            if isinstance(challenge_bytes, str):
                challenge_bytes = bytes.fromhex(challenge_bytes)
        except (ValueError, TypeError) as exc:
            return jsonify({"error": f"Invalid challenge format: {exc}"}), 400

    rp_input = public_key.get("rp") if isinstance(public_key, Mapping) else None
    rp_entity = build_rp_entity(rp_input)
    sanitized_rp = {"id": rp_entity.id, "name": rp_entity.name}
    if isinstance(rp_input, Mapping):
        sanitized_rp.update(
            {k: v for k, v in rp_input.items() if k not in {"id", "name"}}
        )
    if isinstance(public_key, MutableMapping):
        public_key["rp"] = sanitized_rp

    temp_server = create_fido_server(rp_data=sanitized_rp)

    timeout = public_key.get("timeout", 90000)
    temp_server.timeout = timeout / 1000.0 if timeout else None

    attestation = public_key.get("attestation", "none")
    if attestation == "direct":
        temp_server.attestation = AttestationConveyancePreference.DIRECT
    elif attestation == "indirect":
        temp_server.attestation = AttestationConveyancePreference.INDIRECT
    elif attestation == "enterprise":
        temp_server.attestation = AttestationConveyancePreference.ENTERPRISE
    else:
        temp_server.attestation = AttestationConveyancePreference.NONE

    pub_key_cred_params = public_key.get("pubKeyCredParams", [])
    requested_algorithm_ids: List[int] = []
    if pub_key_cred_params:
        allowed_algorithms: List[PublicKeyCredentialParameters] = []
        normalized_params: List[Dict[str, Any]] = []
        for param in pub_key_cred_params:
            raw_alg_value: Any
            normalized_param: Dict[str, Any]

            if isinstance(param, Mapping):
                raw_alg_value = param.get("alg")
                if raw_alg_value is None:
                    raw_alg_value = param.get("id")
                if raw_alg_value is None:
                    raw_alg_value = param.get("value")

                type_value = param.get("type")
                if isinstance(type_value, str):
                    if type_value.strip().lower() != "public-key":
                        continue
                elif type_value is not None:
                    continue

                alg_value = _coerce_cose_algorithm(raw_alg_value)
                if alg_value is None:
                    continue

                requested_algorithm_ids.append(alg_value)
                normalized_param = {"type": "public-key", "alg": alg_value}
                normalized_params.append(normalized_param)
            else:
                alg_value = _coerce_cose_algorithm(param)
                if alg_value is None:
                    continue

                requested_algorithm_ids.append(alg_value)
                normalized_param = {"type": "public-key", "alg": alg_value}
                normalized_params.append(normalized_param)

            allowed_algorithms.append(
                PublicKeyCredentialParameters(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    alg=alg_value
                )
            )
        if normalized_params:
            public_key["pubKeyCredParams"] = normalized_params
        if allowed_algorithms:
            temp_server.allowed_algorithms = allowed_algorithms
    else:
        temp_server.allowed_algorithms = [
            PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-50),
            PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-48),
            PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-49),
            PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-7),
            PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-257),
        ]

    allowed_algorithm_ids = [
        getattr(param, "alg", None) for param in getattr(temp_server, "allowed_algorithms", [])
    ]
    allowed_algorithm_ids = [alg for alg in allowed_algorithm_ids if isinstance(alg, int)]

    pqc_in_allowed = {alg for alg in allowed_algorithm_ids if is_pqc_algorithm(alg)}
    if pqc_in_allowed:
        pqc_available_ids, pqc_error_message = detect_available_pqc_algorithms()
        missing_pqc = pqc_in_allowed - pqc_available_ids
        if missing_pqc:
            missing_names = ", ".join(
                PQC_ALGORITHM_ID_TO_NAME[alg] for alg in sorted(missing_pqc)
            )
            if pqc_error_message:
                app.logger.warning("Post-quantum support unavailable: %s", pqc_error_message)
            else:
                app.logger.warning(
                    "Post-quantum algorithms requested (%s) but not available in this environment.",
                    missing_names,
                )

            filtered_allowed = [
                param
                for param in temp_server.allowed_algorithms
                if getattr(param, "alg", None) not in missing_pqc
            ]

            fallback_applied = False
            if not filtered_allowed:
                fallback_algorithms = [
                    PublicKeyCredentialParameters(
                        type=PublicKeyCredentialType.PUBLIC_KEY,
                        alg=alg_value,
                    )
                    for alg_value in (-7, -8, -257)
                ]
                temp_server.allowed_algorithms = fallback_algorithms
                fallback_applied = True
            else:
                temp_server.allowed_algorithms = filtered_allowed

            if pqc_available_ids:
                if fallback_applied:
                    warning_message = (
                        f"Unsupported PQC algorithms were skipped ({missing_names}); "
                        "falling back to classical algorithms."
                    )
                else:
                    warning_message = (
                        f"Unsupported PQC algorithms were skipped ({missing_names})."
                    )

            warnings.append(warning_message)

            allowed_algorithm_ids = [
                getattr(param, "alg", None) for param in temp_server.allowed_algorithms
            ]
            [alg for alg in allowed_algorithm_ids if isinstance(alg, int)]

    public_key["pubKeyCredParams"] = [
        {
            "type": getattr(param.type, "value", param.type) if hasattr(param, "type") else "public-key",
            "alg": getattr(param, "alg", None),
        }
        for param in temp_server.allowed_algorithms
        if getattr(param, "alg", None) is not None
    ]

    app.logger.info(
        "Advanced registration request will advertise algorithms: %s",
        [entry.get("alg") for entry in public_key["pubKeyCredParams"]],
    )

    auth_selection = public_key.get("authenticatorSelection", {})
    if not isinstance(auth_selection, dict):
        auth_selection = {}
        public_key["authenticatorSelection"] = auth_selection

    raw_hints = public_key.get("hints")
    hints_list: List[str] = []
    if isinstance(raw_hints, list):
        hints_list = [item for item in raw_hints if isinstance(item, str)]

    requested_attachment = normalize_attachment(auth_selection.get("authenticatorAttachment"))

    allowed_attachment_values = resolve_effective_attachments(hints_list, requested_attachment)
    session["advanced_register_allowed_attachments"] = list(allowed_attachment_values)

    uv_req = UserVerificationRequirement.PREFERRED
    user_verification = auth_selection.get("userVerification", "preferred")
    if user_verification == "required":
        uv_req = UserVerificationRequirement.REQUIRED
    elif user_verification == "discouraged":
        uv_req = UserVerificationRequirement.DISCOURAGED

    auth_attachment = None
    attachment_source = requested_attachment
    if not attachment_source and len(allowed_attachment_values) == 1:
        attachment_source = allowed_attachment_values[0]
    if attachment_source == "platform":
        auth_attachment = AuthenticatorAttachment.PLATFORM
    elif attachment_source == "cross-platform":
        auth_attachment = AuthenticatorAttachment.CROSS_PLATFORM

    rk_req = ResidentKeyRequirement.PREFERRED
    resident_key = auth_selection.get("residentKey", "preferred")
    if auth_selection.get("requireResidentKey") is True:
        rk_req = ResidentKeyRequirement.REQUIRED
    elif resident_key == "required":
        rk_req = ResidentKeyRequirement.REQUIRED
    elif resident_key == "discouraged":
        rk_req = ResidentKeyRequirement.DISCOURAGED

    user_entity = PublicKeyCredentialUserEntity(
        id=user_id_bytes,
        name=username,
        display_name=display_name,
    )

    exclude_list = []
    exclude_credentials = public_key.get("excludeCredentials") if "excludeCredentials" in public_key else None
    if isinstance(exclude_credentials, list):
        for exclude_cred in exclude_credentials:
            if isinstance(exclude_cred, dict) and exclude_cred.get("type") == "public-key":
                cred_id = _extract_binary_value(exclude_cred.get("id", ""))
                if isinstance(cred_id, str):
                    cred_id = bytes.fromhex(cred_id)
                if cred_id:
                    exclude_list.append(PublicKeyCredentialDescriptor(
                        type=PublicKeyCredentialType.PUBLIC_KEY,
                        id=cred_id
                    ))

    extensions = public_key.get("extensions", {})
    processed_extensions = {}

    for ext_name, ext_value in extensions.items():
        if ext_name == "credProps":
            processed_extensions["credProps"] = bool(ext_value)
        elif ext_name == "minPinLength":
            processed_extensions["minPinLength"] = bool(ext_value)
        elif ext_name in ("credProtect", "credentialProtectionPolicy"):
            if isinstance(ext_value, int):
                protect_map = {
                    1: "userVerificationOptional",
                    2: "userVerificationOptionalWithCredentialIDList",
                    3: "userVerificationRequired",
                }
                processed_extensions["credentialProtectionPolicy"] = protect_map.get(ext_value, ext_value)
            elif isinstance(ext_value, str):
                alias_map = {
                    "userVerificationOptional": "userVerificationOptional",
                    "userVerificationOptionalWithCredentialIDList": "userVerificationOptionalWithCredentialIDList",
                    "userVerificationOptionalWithCredentialIdList": "userVerificationOptionalWithCredentialIDList",
                    "userVerificationRequired": "userVerificationRequired",
                }
                processed_extensions["credentialProtectionPolicy"] = alias_map.get(ext_value, ext_value)
            else:
                processed_extensions["credentialProtectionPolicy"] = ext_value
        elif ext_name in ("enforceCredProtect", "enforceCredentialProtectionPolicy"):
            processed_extensions["enforceCredentialProtectionPolicy"] = bool(ext_value)
        elif ext_name == "largeBlob":
            if isinstance(ext_value, str):
                processed_extensions["largeBlob"] = {"support": ext_value}
            else:
                processed_extensions["largeBlob"] = ext_value
        elif ext_name == "prf":
            if isinstance(ext_value, dict) and "eval" in ext_value:
                prf_eval = ext_value["eval"]
                processed_eval = {}
                if isinstance(prf_eval, dict):
                    if "first" in prf_eval:
                        first_value = _extract_binary_value(prf_eval["first"])
                        if isinstance(first_value, str):
                            first_value = bytes.fromhex(first_value)
                        processed_eval["first"] = first_value
                    if "second" in prf_eval:
                        second_value = _extract_binary_value(prf_eval["second"])
                        if isinstance(second_value, str):
                            second_value = bytes.fromhex(second_value)
                        processed_eval["second"] = second_value
                if processed_eval:
                    processed_extensions["prf"] = {"eval": processed_eval}
                else:
                    processed_extensions["prf"] = ext_value
            else:
                processed_extensions["prf"] = ext_value
        else:
            processed_extensions[ext_name] = ext_value

    options, state = temp_server.register_begin(
        user_entity,
        exclude_list,
        user_verification=uv_req,
        authenticator_attachment=auth_attachment,
        resident_key_requirement=rk_req,
        challenge=challenge_bytes,
        extensions=processed_extensions if processed_extensions else None,
    )

    if "largeBlob" in processed_extensions:
        print(f"[DEBUG] largeBlob extension sent to Fido2Server: {processed_extensions['largeBlob']}")
        options_dict = dict(options)
        if 'extensions' in options_dict.get('publicKey', {}):
            print(
                f"[DEBUG] largeBlob extension in server response: "
                f"{options_dict['publicKey'].get('extensions', {}).get('largeBlob')}"
            )
        else:
            print(f"[DEBUG] No extensions in server response")

    session["advanced_state"] = state
    session["advanced_rp"] = {"id": rp_entity.id, "name": rp_entity.name}
    session["advanced_original_request"] = data

    response_payload = dict(options)
    if warnings:
        response_payload["warnings"] = warnings

    return jsonify(make_json_safe(response_payload))


@app.route("/api/advanced/register/complete", methods=["POST"])
def advanced_register_complete():
    data = request.get_json(silent=True) or {}

    response = data.get("__credential_response")
    if not response:
        return jsonify({"error": "Credential response is required"}), 400

    credential_response = response.get('response', {}) if isinstance(response, dict) else {}

    original_request = {key: value for key, value in data.items() if not key.startswith("__")}

    original_public_key = original_request.get("publicKey") if isinstance(original_request, Mapping) else None
    original_hints: List[str] = []
    if isinstance(original_public_key, Mapping):
        raw_hints = original_public_key.get("hints")
        if isinstance(raw_hints, list):
            original_hints = [item for item in raw_hints if isinstance(item, str)]

    requested_attachment = None
    if isinstance(original_public_key, Mapping):
        selection = original_public_key.get("authenticatorSelection")
        if isinstance(selection, Mapping):
            requested_attachment = normalize_attachment(selection.get("authenticatorAttachment"))

    request_allowed_attachments = resolve_effective_attachments(original_hints, requested_attachment)

    session_allowed_marker = session.pop("advanced_register_allowed_attachments", None)
    if session_allowed_marker is None:
        allowed_attachments = request_allowed_attachments
    else:
        allowed_attachments = normalize_attachment_list(session_allowed_marker)

    if not allowed_attachments:
        allowed_attachments = request_allowed_attachments

    response_attachment = normalize_attachment(
        response.get('authenticatorAttachment') if isinstance(response, Mapping) else None
    )
    if allowed_attachments:
        if response_attachment is None:
            return jsonify({
                "error": "Authenticator attachment could not be determined to enforce selected hints.",
            }), 400
        if response_attachment not in allowed_attachments:
            return jsonify({
                "error": "Authenticator attachment is not permitted by the selected hints.",
            }), 400

    if not original_request.get("publicKey"):
        return jsonify({"error": "Invalid request: Missing publicKey in JSON editor content"}), 400

    public_key = original_request["publicKey"]
    user_info = public_key.get("user", {})
    username = user_info.get("name", "")
    display_name = user_info.get("displayName", username)

    if not username:
        return jsonify({"error": "Username is required in user.name"}), 400

    credentials = readkey(username)

    warnings: List[str] = []

    auth_selection = public_key.get('authenticatorSelection', {})
    if isinstance(auth_selection, Mapping):
        auth_selection = dict(auth_selection)
        if isinstance(public_key, MutableMapping):
            public_key['authenticatorSelection'] = auth_selection
    elif isinstance(public_key, MutableMapping):
        public_key['authenticatorSelection'] = {}
        auth_selection = public_key['authenticatorSelection']
    resident_key_requested = auth_selection.get('residentKey')
    resident_key_required = auth_selection.get('requireResidentKey')
    if resident_key_required is None:
        resident_key_required = resident_key_requested == 'required'

    (
        attestation_format,
        attestation_statement,
        parsed_attestation_object,
        parsed_client_data_json,
        parsed_extension_results,
        attestation_certificate_details,
        attestation_certificates_details,
    ) = extract_attestation_details(response)

    raw_attestation_object = credential_response.get('attestationObject')
    client_data_json = credential_response.get('clientDataJSON')

    if parsed_attestation_object:
        raw_attestation_object = parsed_attestation_object
    if parsed_client_data_json:
        client_data_json = parsed_client_data_json

    client_extension_results = (
        parsed_extension_results
        if parsed_extension_results
        else (response.get('clientExtensionResults', {}) if isinstance(response, dict) else {})
    )

    min_pin_length_value = extract_min_pin_length(client_extension_results)

    authenticator_attachment_response = normalize_attachment(
        response.get('authenticatorAttachment') if isinstance(response, Mapping) else None
    )

    try:
        state = session.pop("advanced_state", None)
        stored_original_request = session.pop("advanced_original_request", None)
        if state is None:
            return (
                jsonify(
                    {
                        "error": "Registration state not found or has expired. "
                        "Please restart the registration process.",
                    }
                ),
                400,
            )

        stored_rp = session.get("advanced_rp")
        stored_rp_id = None
        stored_rp_name = None
        if isinstance(stored_rp, Mapping):
            stored_rp_id = stored_rp.get("id")
            stored_rp_name = stored_rp.get("name")

        resolved_rp_id = determine_rp_id(stored_rp_id)
        register_server = create_fido_server(
            rp_id=resolved_rp_id,
            rp_name=stored_rp_name,
        )

        auth_data = register_server.register_complete(state, response)

        _log_authenticator_attestation_response(
            attestation_format,
            auth_data,
            attestation_statement,
            raw_attestation_object,
        )

        stored_public_key: Optional[Mapping[str, Any]] = None
        if isinstance(stored_original_request, Mapping):
            stored_public_key = stored_original_request.get("publicKey")
            if not isinstance(stored_public_key, Mapping):
                stored_public_key = None

        public_key_for_checks: Optional[Mapping[str, Any]] = None
        if isinstance(stored_public_key, Mapping):
            public_key_for_checks = stored_public_key
        elif isinstance(public_key, Mapping):
            public_key_for_checks = public_key

        expected_origin = request.headers.get("Origin") or request.host_url.rstrip("/")
        attestation_checks = perform_attestation_checks(
            response if isinstance(response, Mapping) else {},
            state if isinstance(state, Mapping) else None,
            public_key_for_checks,
            auth_data,
            expected_origin,
            resolved_rp_id,
        )

        attestation_signature_valid = attestation_checks.get("signature_valid")
        attestation_root_valid = attestation_checks.get("root_valid")
        attestation_rp_id_hash_valid = attestation_checks.get("rp_id_hash_valid")
        attestation_aaguid_match = attestation_checks.get("aaguid_match")
        attestation_checks_safe = make_json_safe(attestation_checks)
        attestation_warnings = attestation_checks.get("warnings")
        if isinstance(attestation_warnings, list):
            for message in attestation_warnings:
                if isinstance(message, str):
                    stripped = message.strip()
                    if stripped:
                        warnings.append(stripped)
        attestation_summary = {
            "signatureValid": attestation_signature_valid,
            "rootValid": attestation_root_valid,
            "rpIdHashValid": attestation_rp_id_hash_valid,
            "aaguidMatch": attestation_aaguid_match,
        }
        metadata_summary = attestation_checks_safe.get("metadata")
        if isinstance(metadata_summary, Mapping):
            attestation_summary["metadata"] = metadata_summary
        warnings_summary = attestation_checks_safe.get("warnings")
        if isinstance(warnings_summary, list) and warnings_summary:
            attestation_summary["warnings"] = warnings_summary

        authenticator_extensions_summary: Dict[str, Any] = {}
        if hasattr(auth_data, 'extensions'):
            authenticator_extensions = getattr(auth_data, 'extensions')
            if isinstance(authenticator_extensions, Mapping):
                authenticator_extensions_summary = summarize_authenticator_extensions(
                    authenticator_extensions
                )

        if 'largeBlob' in client_extension_results:
            print(f"[DEBUG] largeBlob client extension results: {client_extension_results['largeBlob']}")

        user_id_value = user_info.get("id", "")
        if user_id_value:
            try:
                user_handle = _extract_binary_value(user_id_value)
                if isinstance(user_handle, str):
                    user_handle = bytes.fromhex(user_handle)
            except (ValueError, TypeError):
                user_handle = username.encode('utf-8')
        else:
            user_handle = username.encode('utf-8')

        credential_info = {
            'credential_data': auth_data.credential_data,
            'auth_data': auth_data,
            'user_info': {
                'name': username,
                'display_name': display_name,
                'user_handle': user_handle
            },
            'registration_time': time.time(),
            'client_data_json': client_data_json or '',
            'attestation_object': raw_attestation_object or '',
            'attestation_format': attestation_format,
            'attestation_statement': attestation_statement,
            'attestation_certificates': attestation_certificates_details,
            'client_extension_outputs': client_extension_results,
            'authenticator_attachment': authenticator_attachment_response,
            'original_webauthn_request': original_request,
            'properties': {
                'excludeCredentialsSentCount': len(public_key.get('excludeCredentials', [])),
                'excludeCredentialsUsed': False,
                'credentialIdLength': len(auth_data.credential_data.credential_id),
                'fakeCredentialIdLengthRequested': None,
                'hintsSent': public_key.get('hints', []),
                'resolvedAuthenticatorAttachments': allowed_attachments,
                'authenticatorAttachment': authenticator_attachment_response,
                'largeBlobRequested': public_key.get('extensions', {}).get('largeBlob', {}),
                'largeBlobClientOutput': client_extension_results.get('largeBlob', {}),
                'residentKeyRequested': resident_key_requested,
                'residentKeyRequired': bool(resident_key_required),
                'attestationSignatureValid': attestation_signature_valid,
                'attestationRootValid': attestation_root_valid,
                'attestationRpIdHashValid': attestation_rp_id_hash_valid,
                'attestationAaguidMatch': attestation_aaguid_match,
                'attestationChecks': attestation_checks_safe,
                'attestationSummary': attestation_summary,
            }
        }

        if min_pin_length_value is not None:
            credential_info['properties']['minPinLength'] = min_pin_length_value

        if attestation_certificates_details:
            credential_info['attestationCertificates'] = attestation_certificates_details
            credential_info['properties']['attestationCertificates'] = attestation_certificates_details

        add_public_key_material(
            credential_info,
            getattr(auth_data.credential_data, 'public_key', {})
        )
        augment_aaguid_fields(credential_info)

        if authenticator_extensions_summary:
            credential_info['authenticator_extensions'] = authenticator_extensions_summary

        if attestation_certificate_details is not None:
            credential_info['attestation_certificate'] = attestation_certificate_details

        if isinstance(response, Mapping):
            credential_info['registration_response'] = make_json_safe(response)

        credential_public_key_value = getattr(auth_data.credential_data, "public_key", None)
        raw_alg_value: Any = None
        if isinstance(credential_public_key_value, Mapping):
            if 3 in credential_public_key_value:
                raw_alg_value = credential_public_key_value[3]
            elif "alg" in credential_public_key_value:
                raw_alg_value = credential_public_key_value["alg"]
        else:
            try:
                raw_alg_value = credential_public_key_value[3]  # type: ignore[index]
            except Exception:
                raw_alg_value = None

        algo = _coerce_cose_algorithm(raw_alg_value)
        algoname = describe_algorithm(algo)
        log_algorithm_selection("registration", algo)

        pub_key_params = public_key.get("pubKeyCredParams", [])
        algorithms_used = [param.get("alg") for param in pub_key_params if isinstance(param, dict) and "alg" in param]

        debug_info = {
            "attestationFormat": attestation_format,
            "algorithmsUsed": algorithms_used or ([algo] if algo is not None else []),
            "excludeCredentialsUsed": bool(public_key.get("excludeCredentials")),
            "hintsUsed": public_key.get("hints", []),
            "actualResidentKey": bool(auth_data.flags & 0x04) if hasattr(auth_data, 'flags') else False,
            "attestationSignatureValid": attestation_signature_valid,
            "attestationRootValid": attestation_root_valid,
            "attestationRpIdHashValid": attestation_rp_id_hash_valid,
            "attestationAaguidMatch": attestation_aaguid_match,
            "attestationChecks": attestation_checks_safe,
            "attestationSummary": attestation_summary,
        }

        extensions_requested = public_key.get("extensions", {})
        if not isinstance(extensions_requested, dict):
            extensions_requested = {}

        cred_protect_requested = extensions_requested.get("credentialProtectionPolicy")
        if cred_protect_requested is None:
            cred_protect_requested = extensions_requested.get("credProtect")

        cred_protect_mapping = {
            1: "userVerificationOptional",
            2: "userVerificationOptionalWithCredentialIDList",
            3: "userVerificationRequired",
        }

        if isinstance(cred_protect_requested, int):
            cred_protect_display = cred_protect_mapping.get(cred_protect_requested, cred_protect_requested)
        elif cred_protect_requested:
            cred_protect_display = cred_protect_requested
        else:
            cred_protect_display = "none"

        debug_info["credProtectUsed"] = cred_protect_display

        enforce_requested = extensions_requested.get("enforceCredentialProtectionPolicy")
        if enforce_requested is None:
            enforce_requested = extensions_requested.get("enforceCredProtect")
        debug_info["enforceCredProtectUsed"] = bool(enforce_requested)

        credential_data = auth_data.credential_data
        credential_id_bytes = getattr(credential_data, 'credential_id', b'') or b''
        credential_id_hex = credential_id_bytes.hex() if credential_id_bytes else None
        credential_id_b64 = (
            base64.b64encode(credential_id_bytes).decode('ascii') if credential_id_bytes else None
        )
        credential_id_b64url = (
            base64.urlsafe_b64encode(credential_id_bytes).rstrip(b'=').decode('ascii')
            if credential_id_bytes else None
        )

        aaguid_hex = None
        aaguid_guid = None
        aaguid_bytes: Optional[bytes] = None
        aaguid_value = getattr(credential_data, 'aaguid', None)
        if aaguid_value is not None:
            try:
                aaguid_bytes = bytes(aaguid_value)
            except Exception:
                aaguid_bytes = None
            if aaguid_bytes is not None and len(aaguid_bytes) == 16:
                aaguid_hex = aaguid_bytes.hex()
                try:
                    aaguid_guid = str(uuid.UUID(bytes=aaguid_bytes))
                except ValueError:
                    aaguid_guid = None

        if aaguid_hex:
            credential_info['properties']['aaguid'] = aaguid_hex
            credential_info['properties']['aaguidHex'] = aaguid_hex
        if aaguid_guid:
            credential_info['properties']['aaguidGuid'] = aaguid_guid

        flags_dict = {
            "AT": bool(auth_data.flags & auth_data.FLAG.AT),
            "BE": bool(auth_data.flags & auth_data.FLAG.BE),
            "BS": bool(auth_data.flags & auth_data.FLAG.BS),
            "ED": bool(auth_data.flags & auth_data.FLAG.ED),
            "UP": bool(auth_data.flags & auth_data.FLAG.UP),
            "UV": bool(auth_data.flags & auth_data.FLAG.UV),
        }

        authenticator_data_hex = bytes(auth_data).hex()
        registration_timestamp = datetime_from_timestamp(credential_info['registration_time'])

        None
        cred_props = (
            client_extension_results.get('credProps')
            if isinstance(client_extension_results, dict)
            else None
        )
        if isinstance(cred_props, dict) and 'rk' in cred_props:
            resident_key_result = bool(cred_props.get('rk'))
        elif isinstance(cred_props, bool):
            resident_key_result = bool(cred_props)
        else:
            resident_key_result = bool(auth_data.flags & auth_data.FLAG.BE) or bool(resident_key_required)

        credential_info['properties']['residentKey'] = bool(resident_key_result)
        credential_info['resident_key'] = bool(resident_key_result)

        large_blob_result = False
        if isinstance(client_extension_results, dict) and 'largeBlob' in client_extension_results:
            large_blob_value = client_extension_results.get('largeBlob')
            if isinstance(large_blob_value, dict):
                large_blob_result = bool(
                    large_blob_value.get('supported')
                    or large_blob_value.get('written')
                    or large_blob_value.get('blob')
                    or large_blob_value.get('result')
                )
            else:
                large_blob_result = bool(large_blob_value)

        rp_info = {
            "aaguid": {
                "raw": aaguid_hex,
                "guid": aaguid_guid,
            },
            "attestationFmt": attestation_format,
            "attestationObject": credential_info.get('attestation_object'),
            "createdAt": registration_timestamp,
            "credentialId": credential_id_hex,
            "credentialIdBase64": credential_id_b64,
            "credentialIdBase64Url": credential_id_b64url,
            "device": {
                "name": "Unknown device",
                "type": "unknown",
            },
            "largeBlob": large_blob_result,
            "publicKeyAlgorithm": algo,
            "registrationData": {
                "authenticatorData": authenticator_data_hex,
                "clientExtensionResults": client_extension_results,
                "flags": flags_dict,
                "signatureCounter": auth_data.counter,
                "attestationChecks": attestation_checks_safe,
                "attestationSummary": attestation_summary,
            },
            "residentKey": resident_key_result,
            "userHandle": {
                "base64": base64.b64encode(user_handle).decode('ascii'),
                "base64url": base64.urlsafe_b64encode(user_handle).rstrip(b'=').decode('ascii'),
                "hex": user_handle.hex(),
            },
        }

        if authenticator_extensions_summary:
            rp_info["registrationData"]["authenticatorExtensions"] = make_json_safe(
                authenticator_extensions_summary
            )

        if attestation_certificate_details:
            rp_info["attestationCertificate"] = attestation_certificate_details

        if attestation_certificates_details:
            rp_info["attestationCertificates"] = attestation_certificates_details

        credential_info['relying_party'] = make_json_safe(rp_info)

        user_handle_b64url = base64.urlsafe_b64encode(user_handle).rstrip(b'=').decode('ascii')
        user_handle_b64 = base64.b64encode(user_handle).decode('ascii')

        stored_properties = convert_bytes_for_json(credential_info.get('properties', {}))
        stored_extensions = convert_bytes_for_json(client_extension_results)

        public_key_b64 = None
        public_key_b64url = None
        credential_public_key = getattr(auth_data.credential_data, 'public_key', None)
        if isinstance(credential_public_key, Mapping):
            try:
                public_key_cbor_bytes = cbor.encode(dict(credential_public_key))
            except Exception:
                public_key_cbor_bytes = None
            if public_key_cbor_bytes:
                public_key_b64 = base64.b64encode(public_key_cbor_bytes).decode('ascii')
                public_key_b64url = base64.urlsafe_b64encode(public_key_cbor_bytes).rstrip(b'=').decode('ascii')

        stored_credential: Dict[str, Any] = {
            "type": "advanced",
            "userName": username,
            "displayName": display_name,
            "residentKey": bool(resident_key_result),
            "largeBlob": bool(large_blob_result),
            "authenticatorAttachment": authenticator_attachment_response,
            "credentialId": credential_id_b64,
            "credentialIdBase64Url": credential_id_b64url,
            "credentialIdHex": credential_id_hex,
            "aaguid": base64.urlsafe_b64encode(aaguid_bytes).rstrip(b'=').decode('ascii') if aaguid_bytes else None,
            "aaguidHex": aaguid_hex,
            "aaguidGuid": aaguid_guid,
            "publicKeyAlgorithm": algo,
            "publicKey": public_key_b64,
            "publicKeyBase64": public_key_b64,
            "publicKeyBase64Url": public_key_b64url,
            "publicKeyBytes": credential_info.get('publicKeyBytes'),
            "publicKeyCose": credential_info.get('publicKeyCose'),
            "publicKeyType": credential_info.get('publicKeyType'),
            "signCount": getattr(auth_data, 'counter', 0),
            "createdAt": credential_info['registration_time'],
            "clientExtensionOutputs": stored_extensions,
            "attestationFormat": attestation_format,
            "attestationStatement": convert_bytes_for_json(attestation_statement),
            "attestationObject": convert_bytes_for_json(credential_info.get('attestation_object')),
            "authenticatorData": authenticator_data_hex,
            "clientDataJSON": convert_bytes_for_json(credential_info.get('client_data_json')),
            "relyingParty": make_json_safe(rp_info),
            "properties": stored_properties,
            "registrationResponse": credential_info.get('registration_response'),
            "userHandle": user_handle_b64,
            "userHandleBase64": user_handle_b64,
            "userHandleBase64Url": user_handle_b64url,
            "userHandleHex": user_handle.hex(),
        }

        stored_credential = convert_bytes_for_json({k: v for k, v in stored_credential.items() if v is not None})

        response_payload: Dict[str, Any] = {
            "status": "OK",
            "algo": algoname,
            **debug_info,
            "relyingParty": rp_info,
        }
        if warnings:
            response_payload["warnings"] = warnings

        response_payload["storedCredential"] = stored_credential

        return jsonify(response_payload)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


def datetime_from_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


@app.route("/api/advanced/authenticate/begin", methods=["POST"])
def advanced_authenticate_begin():
    data = request.get_json(silent=True)

    if not data or not data.get("publicKey"):
        return jsonify({"error": "Invalid request: Missing publicKey in CredentialRequestOptions"}), 400

    public_key = data["publicKey"]

    if not public_key.get("challenge"):
        return jsonify({"error": "Missing required field: challenge"}), 400

    raw_hints = public_key.get("hints")
    hints_list: List[str] = []
    if isinstance(raw_hints, list):
        hints_list = [item for item in raw_hints if isinstance(item, str)]

    allowed_attachment_values = resolve_effective_attachments(hints_list, None)

    session["advanced_authenticate_allowed_attachments"] = list(allowed_attachment_values)

    challenge_value = public_key.get("challenge", "")
    challenge_bytes = None
    if challenge_value:
        try:
            challenge_bytes = _extract_binary_value(challenge_value)
            if isinstance(challenge_bytes, str):
                challenge_bytes = bytes.fromhex(challenge_bytes)
        except (ValueError, TypeError) as exc:
            return jsonify({"error": f"Invalid challenge format: {exc}"}), 400

    stored_rp = session.get("advanced_rp")
    stored_rp_id = None
    stored_rp_name = None
    if isinstance(stored_rp, Mapping):
        stored_rp_id = stored_rp.get("id")
        stored_rp_name = stored_rp.get("name")

    resolved_rp_id = determine_rp_id(stored_rp_id)
    temp_server = create_fido_server(rp_id=resolved_rp_id, rp_name=stored_rp_name)

    timeout = public_key.get("timeout", 90000)
    temp_server.timeout = timeout / 1000.0 if timeout else None

    user_verification = public_key.get("userVerification", "preferred")
    uv_req = UserVerificationRequirement.PREFERRED
    if user_verification == "required":
        uv_req = UserVerificationRequirement.REQUIRED
    elif user_verification == "discouraged":
        uv_req = UserVerificationRequirement.DISCOURAGED

    raw_credentials_input: List[Any] = []
    for field in ("__storedCredentials", "storedCredentials", "credentials"):
        candidate = data.get(field)
        if isinstance(candidate, list):
            raw_credentials_input = candidate
            break

    stored_records, serialized_credentials = _parse_client_supplied_credentials(raw_credentials_input)

    if not stored_records:
        return jsonify({"error": "No credentials detected. Please register a credential first."}), 404

    credential_lookup: Dict[bytes, Dict[str, Any]] = {
        bytes(record["id"]): record
        for record in stored_records
        if isinstance(record.get("id"), (bytes, bytearray, memoryview))
    }

    raw_allow_credentials = public_key.get("allowCredentials")
    allow_credentials: List[Any] = (
        list(raw_allow_credentials)
        if isinstance(raw_allow_credentials, list)
        else []
    )
    allow_credentials_present = bool(allow_credentials)
    resident_key_only = not allow_credentials_present
    credentials_for_begin: List[Any] = []
    resident_records: List[Dict[str, Any]] = []

    if allow_credentials_present:
        seen_ids: set[bytes] = set()
        for allow_cred in allow_credentials:
            if not isinstance(allow_cred, dict) or allow_cred.get("type") != "public-key":
                continue

            cred_id = _extract_binary_value(allow_cred.get("id", ""))
            if isinstance(cred_id, str):
                try:
                    cred_id = bytes.fromhex(cred_id)
                except ValueError:
                    continue

            if not isinstance(cred_id, (bytes, bytearray, memoryview)):
                continue

            cred_id_bytes = bytes(cred_id)
            if cred_id_bytes in seen_ids:
                continue

            record = credential_lookup.get(cred_id_bytes)
            if record is None:
                continue

            attachment_value = record.get("attachment")
            if allowed_attachment_values and attachment_value not in allowed_attachment_values:
                continue

            credentials_for_begin.append(record["data"])
            seen_ids.add(cred_id_bytes)
        if not credentials_for_begin:
            seen_ids.clear()
            for record in stored_records:
                cred_id = record.get("id")
                if not isinstance(cred_id, (bytes, bytearray, memoryview)):
                    continue
                cred_id_bytes = bytes(cred_id)
                if cred_id_bytes in seen_ids:
                    continue
                attachment_value = record.get("attachment")
                if allowed_attachment_values and attachment_value not in allowed_attachment_values:
                    continue
                credentials_for_begin.append(record["data"])
                seen_ids.add(cred_id_bytes)

    else:
        resident_records = [record for record in stored_records if record.get("resident")]
        seen_ids: set[bytes] = set()
        candidate_records = (
            resident_records if resident_key_only and resident_records else stored_records
        )
        for record in candidate_records:
            cred_id = record.get("id")
            if not isinstance(cred_id, (bytes, bytearray, memoryview)):
                continue
            cred_id_bytes = bytes(cred_id)
            if cred_id_bytes in seen_ids:
                continue
            attachment_value = record.get("attachment")
            if allowed_attachment_values and attachment_value not in allowed_attachment_values:
                continue
            credentials_for_begin.append(record["data"])
            seen_ids.add(cred_id_bytes)

    if not credentials_for_begin and not resident_key_only:
        if allowed_attachment_values:
            return jsonify({
                "error": "No credentials matched the selected hints. Please adjust your hints or select different credentials."
            }), 404
        return jsonify({"error": "No matching credentials found. Please register first."}), 404

    if resident_key_only and resident_records and not credentials_for_begin:
        if allowed_attachment_values:
            return jsonify({
                "error": "No resident key credentials matched the selected hints. Please adjust your hints or register a discoverable credential."
            }), 404
        return jsonify({
            "error": "No resident key credentials are available. Please register a discoverable credential first."
        }), 404

    algorithm_source: Iterable[Any]
    if credentials_for_begin:
        algorithm_source = credentials_for_begin
    else:
        algorithm_source = [
            record["data"]
            for record in stored_records
            if record.get("data") is not None
        ]

    derived_algorithms = _derive_algorithms_from_credentials(algorithm_source)
    if derived_algorithms:
        temp_server.allowed_algorithms = derived_algorithms

    extensions = public_key.get("extensions", {})
    processed_extensions = {}

    for ext_name, ext_value in extensions.items():
        if ext_name == "largeBlob":
            if isinstance(ext_value, dict):
                if ext_value.get("read"):
                    processed_extensions["largeBlob"] = {"read": True}
                elif ext_value.get("write"):
                    write_value = _extract_binary_value(ext_value["write"])
                    if isinstance(write_value, str):
                        write_value = bytes.fromhex(write_value)
                    processed_extensions["largeBlob"] = {"write": write_value}
                else:
                    processed_extensions["largeBlob"] = ext_value
            else:
                processed_extensions["largeBlob"] = ext_value
        elif ext_name == "prf":
            if isinstance(ext_value, dict) and "eval" in ext_value:
                prf_eval = ext_value["eval"]
                processed_eval = {}
                if "first" in prf_eval:
                    first_value = _extract_binary_value(prf_eval["first"])
                    if isinstance(first_value, str):
                        first_value = bytes.fromhex(first_value)
                    processed_eval["first"] = first_value
                if "second" in prf_eval:
                    second_value = _extract_binary_value(prf_eval["second"])
                    if isinstance(second_value, str):
                        second_value = bytes.fromhex(second_value)
                    processed_eval["second"] = second_value
                if processed_eval:
                    processed_extensions["prf"] = {"eval": processed_eval}
            else:
                processed_extensions["prf"] = ext_value
        else:
            processed_extensions[ext_name] = ext_value

    credentials_argument: Optional[List[Any]]
    credentials_argument = credentials_for_begin if credentials_for_begin else None

    options, state = temp_server.authenticate_begin(
        credentials_argument,
        user_verification=uv_req,
        challenge=challenge_bytes,
        extensions=processed_extensions if processed_extensions else None,
    )

    session["advanced_auth_state"] = state
    session["advanced_auth_rp"] = {"id": resolved_rp_id, "name": stored_rp_name}
    session["advanced_original_auth_request"] = data
    session["advanced_auth_credentials"] = serialized_credentials

    options_payload = dict(options)
    public_key_dict = options_payload.get("publicKey")
    if isinstance(public_key_dict, Mapping):
        allow_list = public_key_dict.get("allowCredentials")
        if resident_key_only or allow_list is None:
            public_key_dict.pop("allowCredentials", None)

    return jsonify(make_json_safe(options_payload))


@app.route("/api/advanced/authenticate/complete", methods=["POST"])
def advanced_authenticate_complete():
    data = request.get_json(silent=True) or {}

    response = data.get("__assertion_response")
    if not response:
        return jsonify({"error": "Assertion response is required"}), 400

    original_request = {key: value for key, value in data.items() if not key.startswith("__")}

    public_key_raw = original_request.get("publicKey")
    if not isinstance(public_key_raw, Mapping):
        return jsonify({"error": "Invalid request: Missing publicKey in JSON editor content"}), 400

    public_key = public_key_raw

    raw_allow_credentials = public_key.get("allowCredentials")
    allow_credentials_list = (
        list(raw_allow_credentials)
        if isinstance(raw_allow_credentials, list)
        else []
    )
    resident_key_only = not allow_credentials_list

    raw_hints = public_key.get("hints")
    hints_list: List[str] = []
    if isinstance(raw_hints, list):
        hints_list = [item for item in raw_hints if isinstance(item, str)]

    request_allowed_attachments = resolve_effective_attachments(hints_list, None)

    session_allowed_marker = session.pop("advanced_authenticate_allowed_attachments", None)
    if session_allowed_marker is None:
        allowed_attachments = request_allowed_attachments
    else:
        allowed_attachments = normalize_attachment_list(session_allowed_marker)

    if not allowed_attachments:
        allowed_attachments = request_allowed_attachments

    if allowed_attachments:
        response_attachment = normalize_attachment(
            response.get('authenticatorAttachment') if isinstance(response, Mapping) else None
        )
        if response_attachment is None:
            return jsonify({
                "error": "Authenticator attachment could not be determined to enforce selected hints."
            }), 400
        if response_attachment not in allowed_attachments:
            return jsonify({
                "error": "Authenticator attachment is not permitted by the selected hints."
            }), 400

    serialized_credentials = session.pop("advanced_auth_credentials", [])
    stored_records, _ = _parse_client_supplied_credentials(serialized_credentials)

    if not stored_records:
        return jsonify({"error": "No credentials found"}), 404

    credential_lookup: Dict[bytes, Dict[str, Any]] = {
        bytes(record["id"]): record
        for record in stored_records
        if isinstance(record.get("id"), (bytes, bytearray, memoryview))
    }

    all_credentials = [
        record["data"]
        for record in stored_records
        if record.get("data") is not None
    ]

    response_mapping: Mapping[str, Any]
    response_mapping = response if isinstance(response, Mapping) else {}
    credential_id_bytes = _extract_assertion_credential_id(response_mapping)
    selected_record = credential_lookup.get(credential_id_bytes) if credential_id_bytes else None

    if resident_key_only and selected_record is not None and not selected_record.get("resident"):
        return jsonify({
            "error": "The credential used is not discoverable. Please register a resident key credential to authenticate without allowCredentials."
        }), 400

    try:
        stored_rp = session.pop("advanced_auth_rp", None)
        stored_rp_id = None
        stored_rp_name = None
        if isinstance(stored_rp, Mapping):
            stored_rp_id = stored_rp.get("id")
            stored_rp_name = stored_rp.get("name")
        elif isinstance(session.get("advanced_rp"), Mapping):
            fallback_rp = session.get("advanced_rp")
            stored_rp_id = fallback_rp.get("id")
            stored_rp_name = fallback_rp.get("name")

        resolved_rp_id = determine_rp_id(stored_rp_id)
        auth_server = create_fido_server(rp_id=resolved_rp_id, rp_name=stored_rp_name)

        derived_algorithms = _derive_algorithms_from_credentials(all_credentials)
        if derived_algorithms:
            auth_server.allowed_algorithms = derived_algorithms

        fallback_used = False
        None
        None

        try:
            auth_result = auth_server.authenticate_complete(
                session.pop("advanced_auth_state"),
                all_credentials,
                response,
            )
        except Exception as exc:
            response_mapping: Mapping[str, Any]
            response_mapping = response if isinstance(response, Mapping) else {}
            credential_id = _extract_assertion_credential_id(response_mapping)
            record = credential_lookup.get(credential_id) if credential_id else None
            stored_alg_value: Optional[int] = None
            if isinstance(record, Mapping):
                stored_alg = record.get("algorithm")
                if isinstance(stored_alg, int):
                    stored_alg_value = stored_alg

            requested_alg = _extract_requested_assertion_algorithm(public_key, credential_id)
            error_message = str(exc).lower()
            signature_related = (
                not error_message
                or any(
                    keyword in error_message
                    for keyword in ("signature", "algorithm", "unsupported", "verify")
                )
            )

            if (
                stored_alg_value is not None
                and _is_custom_cose_algorithm(stored_alg_value)
                and (requested_alg is None or requested_alg == stored_alg_value)
                and signature_related
            ):
                fallback_used = True
                auth_alg = stored_alg_value
                app.logger.warning(
                    "Accepting assertion using custom COSE algorithm %d without signature verification.",
                    stored_alg_value,
                )
            else:
                raise
        else:
            try:
                result_public_key = getattr(auth_result, "public_key", None)
                if isinstance(result_public_key, Mapping):
                    auth_alg = result_public_key.get(3)
                else:
                    auth_alg = getattr(result_public_key, "get", lambda *_: None)(3)
            except Exception:  # pragma: no cover - defensive path for unexpected objects
                auth_alg = None

        log_algorithm_selection("authentication", auth_alg)

        hints_used = public_key.get("hints", [])

        debug_info: Dict[str, Any] = {
            "hintsUsed": hints_used,
        }

        authenticated_id = None
        if credential_id_bytes:
            authenticated_id = base64.urlsafe_b64encode(credential_id_bytes).decode('ascii').rstrip('=')

        sign_count_value = None
        credential_response = response.get('response', {}) if isinstance(response, Mapping) else {}
        if isinstance(credential_response, Mapping):
            auth_data_b64 = credential_response.get('authenticatorData')
            if isinstance(auth_data_b64, str):
                try:
                    auth_data_bytes = _decode_base64url(auth_data_b64)
                    sign_count_value = AuthenticatorData(auth_data_bytes).counter
                except Exception:
                    sign_count_value = None

        if auth_alg is not None:
            debug_info["algorithm"] = auth_alg
            debug_info["algorithmDescription"] = describe_algorithm(auth_alg)

        if fallback_used:
            debug_info["customAlgorithmBypass"] = True

        response_payload: Dict[str, Any] = {
            "status": "OK",
            **debug_info,
        }
        if authenticated_id is not None:
            response_payload["authenticatedCredentialId"] = authenticated_id
        if sign_count_value is not None:
            response_payload["signCount"] = sign_count_value

        return jsonify(response_payload)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
