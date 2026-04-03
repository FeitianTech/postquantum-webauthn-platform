"""Routes for the basic registration and authentication flows."""
from __future__ import annotations

import base64
import hashlib
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from flask import abort, jsonify, request, session

from fido2 import cbor
from fido2.cose import CoseKey
from fido2.webauthn import AttestedCredentialData, AuthenticatorData, PublicKeyCredentialUserEntity
from ..attachments import normalize_attachment
from ..attestation import (
    augment_aaguid_fields,
    coerce_aaguid_hex,
    extract_attestation_details,
    extract_min_pin_length,
    make_json_safe,
    perform_attestation_checks,
)
from ..config import app, create_fido_server, determine_rp_id
from ..device_logs import RegistrationEvent, record_registration_event
from ..metadata import ensure_metadata_session_id
from ..storage import (
    add_public_key_material,
    convert_bytes_for_json,
    delkey,
    iter_credentials,
    list_credentials as storage_list_credentials,
    readkey,
    savekey,
)

_SIMPLE_ALLOWED_ALGORITHMS: Tuple[int, ...] = tuple(
    alg
    for alg in (-50, -49, -48, -8, -7, -257, -35)
    if alg in set(CoseKey.supported_algorithms())
)


def _add_base64_padding(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def _decode_base64url_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return b""
        padding = "=" * (-len(candidate) % 4)
        try:
            return base64.urlsafe_b64decode(candidate + padding)
        except Exception:
            return b""
    return b""


def _extract_assertion_credential_id(response: Mapping[str, Any]) -> Optional[bytes]:
    raw_id: Any = None
    if isinstance(response, Mapping):
        raw_id = response.get("rawId") or response.get("id")

    if isinstance(raw_id, (bytes, bytearray, memoryview)):
        return bytes(raw_id)

    if isinstance(raw_id, str):
        return _decode_base64url_bytes(raw_id) or None

    return None


def _decode_binary_value(value: Any) -> bytes:
    if value is None:
        raise ValueError("missing binary value")

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)

    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            raise ValueError("empty string")

        try:
            return base64.urlsafe_b64decode(_add_base64_padding(candidate))
        except Exception:
            pass

        try:
            return base64.b64decode(_add_base64_padding(candidate))
        except Exception:
            pass

        try:
            return bytes.fromhex(candidate)
        except Exception as exc:  # pragma: no cover - defensive
            raise ValueError("invalid binary value") from exc

    if isinstance(value, Iterable):
        try:
            return bytes(value)
        except Exception as exc:  # pragma: no cover - defensive
            raise ValueError("invalid iterable value") from exc

    raise ValueError("unsupported binary value type")


def _select_first(mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _serialize_credential_for_session(entry: Mapping[str, Any]) -> Dict[str, Any]:
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

    aaguid_value = _select_first(entry, ("aaguid", "aaguidBase64", "aaguidBase64Url"))
    if aaguid_value is None and "aaguidHex" in entry:
        aaguid_value = entry["aaguidHex"]

    credential_id_value = _select_first(
        entry,
        (
            "credentialIdBase64Url",
            "credentialId",
            "credentialID",
            "id",
            "rawId",
        ),
    )

    public_key_value = _select_first(
        entry,
        (
            "publicKey",
            "publicKeyBase64",
            "publicKeyBase64Url",
            "publicKeyCbor",
        ),
    )

    if aaguid_value is not None:
        aaguid_bytes = _decode_binary_value(aaguid_value)
        serialized["aaguid"] = base64.urlsafe_b64encode(aaguid_bytes).decode("ascii").rstrip("=")

    if credential_id_value is not None:
        credential_id_bytes = _decode_binary_value(credential_id_value)
        serialized["credentialId"] = base64.urlsafe_b64encode(credential_id_bytes).decode("ascii").rstrip("=")

    if public_key_value is not None:
        public_key_bytes = _decode_binary_value(public_key_value)
        serialized["publicKey"] = base64.urlsafe_b64encode(public_key_bytes).decode("ascii").rstrip("=")

    return serialized


def _parse_client_credentials(raw_credentials: Any) -> Tuple[List[AttestedCredentialData], List[Dict[str, Any]]]:
    if not isinstance(raw_credentials, list):
        return [], []

    attested_credentials: List[AttestedCredentialData] = []
    serialized_entries: List[Dict[str, Any]] = []

    for entry in raw_credentials:
        if not isinstance(entry, Mapping):
            continue

        try:
            aaguid_raw = _select_first(
                entry,
                (
                    "aaguid",
                    "aaguidBase64",
                    "aaguidBase64Url",
                    "aaguidHex",
                ),
            )
            credential_id_raw = _select_first(
                entry,
                (
                    "credentialId",
                    "credentialIdBase64Url",
                    "credentialID",
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
                    "publicKeyCbor",
                ),
            )

            if aaguid_raw is None or credential_id_raw is None or public_key_raw is None:
                continue

            aaguid_bytes = _decode_binary_value(aaguid_raw)
            credential_id_bytes = _decode_binary_value(credential_id_raw)
            public_key_bytes = _decode_binary_value(public_key_raw)

            cose_key = CoseKey.parse(cbor.decode(public_key_bytes))

            attested = AttestedCredentialData.create(
                aaguid_bytes,
                credential_id_bytes,
                cose_key,
            )

            attested_credentials.append(attested)

            serialized_entry = _serialize_credential_for_session(entry)
            serialized_entry.setdefault(
                "credentialId", base64.urlsafe_b64encode(credential_id_bytes).decode("ascii").rstrip("=")
            )
            serialized_entry.setdefault(
                "aaguid", base64.urlsafe_b64encode(aaguid_bytes).decode("ascii").rstrip("=")
            )
            serialized_entry.setdefault(
                "publicKey", base64.urlsafe_b64encode(public_key_bytes).decode("ascii").rstrip("=")
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


@app.route("/api/register/begin", methods=["POST"])
def register_begin():
    uname = request.args.get("email")
    payload = request.get_json(silent=True) or {}

    existing_credentials_raw: List[Any] = []
    if isinstance(payload, Mapping):
        raw_candidates = payload.get("credentials") or payload.get("existingCredentials")
        if isinstance(raw_candidates, list):
            existing_credentials_raw = raw_candidates

    credentials, serialized = _parse_client_credentials(existing_credentials_raw)
    if serialized:
        session["simple_credentials"] = serialized
    else:
        session.pop("simple_credentials", None)

    rp_id = determine_rp_id()
    server = create_fido_server(rp_id=rp_id)

    options, state = server.register_begin(
        PublicKeyCredentialUserEntity(
            id=b"user_id",
            name="a_user",
            display_name="A. User",
        ),
        credentials,
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )

    session["state"] = state
    session["register_rp_id"] = rp_id

    options_dict = dict(options)
    options_dict["__session_state"] = make_json_safe(state)
    public_key_options = options_dict.get("publicKey")
    if isinstance(public_key_options, MutableMapping):
        session["simple_register_public_key"] = make_json_safe(public_key_options)
    else:
        session.pop("simple_register_public_key", None)
    if _SIMPLE_ALLOWED_ALGORITHMS:
        public_key_options = options_dict.get("publicKey")
        if isinstance(public_key_options, MutableMapping):
            params = public_key_options.get("pubKeyCredParams")
            allowed_params: List[Dict[str, Any]] = []
            existing_param_map: Dict[int, Dict[str, Any]] = {}
            if isinstance(params, list):
                for param in params:
                    if isinstance(param, MutableMapping):
                        alg_value = param.get("alg")
                        if isinstance(alg_value, int) and alg_value in _SIMPLE_ALLOWED_ALGORITHMS:
                            cloned = dict(param)
                            cloned["type"] = "public-key"
                            existing_param_map[alg_value] = cloned
            for alg in _SIMPLE_ALLOWED_ALGORITHMS:
                if alg in existing_param_map:
                    allowed_params.append(existing_param_map[alg])
                else:
                    allowed_params.append({"type": "public-key", "alg": alg})
            public_key_options["pubKeyCredParams"] = allowed_params

    return jsonify(make_json_safe(options_dict))


@app.route("/api/register/complete", methods=["POST"])
def register_complete():
    uname = request.args.get("email")
    response = request.get_json(silent=True) or {}
    credential_response = response.get('response', {}) if isinstance(response, dict) else {}

    (
        attestation_format,
        attestation_statement,
        parsed_attestation_object,
        parsed_client_data_json,
        parsed_extension_results,
        attestation_certificate_details,
        attestation_certificates_details,
    ) = extract_attestation_details(response)

    client_data_json_b64 = credential_response.get('clientDataJSON')
    client_data_json = client_data_json_b64
    if parsed_client_data_json:
        client_data_json = parsed_client_data_json

    client_extension_results = (
        parsed_extension_results
        if parsed_extension_results
        else (response.get('clientExtensionResults', {}) if isinstance(response, dict) else {})
    )

    min_pin_length_value = extract_min_pin_length(client_extension_results)

    if isinstance(response, dict):
        state_from_request = response.pop("__session_state", None)
    else:
        state_from_request = None

    rp_id = session.get("register_rp_id")
    state = session.get("state")
    if state is None and isinstance(state_from_request, Mapping):
        state = state_from_request
    if state is None:
        return (
            jsonify(
                {
                    "error": "Registration state not found or has expired. Please restart the registration process."
                }
            ),
            400,
        )

    public_key_options_for_checks = session.pop("simple_register_public_key", None)
    resolved_rp_id = rp_id or determine_rp_id()
    server = create_fido_server(rp_id=resolved_rp_id)

    auth_data = server.register_complete(state, response)
    session.pop("state", None)

    authenticator_attachment_response = normalize_attachment(
        response.get('authenticatorAttachment') if isinstance(response, Mapping) else None
    )

    raw_attestation_object_b64 = credential_response.get('attestationObject')
    raw_attestation_object = raw_attestation_object_b64

    expected_origin = request.headers.get("Origin") or request.host_url.rstrip("/")

    attestation_checks = perform_attestation_checks(
        response if isinstance(response, Mapping) else {},
        state if isinstance(state, Mapping) else None,
        public_key_options_for_checks if isinstance(public_key_options_for_checks, Mapping) else None,
        auth_data,
        expected_origin,
        resolved_rp_id,
    )

    attestation_signature_valid = attestation_checks.get("signature_valid")
    attestation_root_valid = attestation_checks.get("root_valid")
    attestation_rp_id_hash_valid = attestation_checks.get("rp_id_hash_valid")
    attestation_aaguid_match = attestation_checks.get("aaguid_match")
    attestation_checks_safe = make_json_safe(attestation_checks)

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
    warnings: List[str] = []
    if isinstance(warnings_summary, list):
        filtered_warnings: List[Any] = []
        for message in warnings_summary:
            if isinstance(message, str):
                stripped = message.strip()
                if stripped:
                    warnings.append(stripped)
                    filtered_warnings.append(stripped)
            elif message:
                filtered_warnings.append(message)
        if filtered_warnings:
            attestation_summary["warnings"] = filtered_warnings

    credential_info: Dict[str, Any] = {
        'credential_data': auth_data.credential_data,
        'auth_data': auth_data,
        'user_info': {
            'name': uname,
            'display_name': uname,
            'user_handle': uname.encode('utf-8')
        },
        'registration_time': time.time(),
        'client_data_json': client_data_json or '',
        'attestation_object': raw_attestation_object or '',
        'attestation_object_raw': raw_attestation_object or '',
        'attestation_format': attestation_format,
        'attestation_statement': attestation_statement,
        'attestation_certificate': attestation_certificate_details,
        'attestation_certificates': attestation_certificates_details,
        'client_extension_outputs': client_extension_results,
        'authenticator_attachment': authenticator_attachment_response,
        'request_params': {
            'user_verification': 'discouraged',
            'authenticator_attachment': 'cross-platform',
            'attestation': 'none',
            'resident_key': None,
            'extensions': {},
            'timeout': 90000
        },
        'properties': {
            'excludeCredentialsSentCount': 0,
            'excludeCredentialsUsed': False,
            'credentialIdLength': len(auth_data.credential_data.credential_id),
            'fakeCredentialIdLengthRequested': None,
            'hintsSent': [],
            'resolvedAuthenticatorAttachments': [],
            'authenticatorAttachment': authenticator_attachment_response,
            'largeBlobRequested': {},
            'largeBlobClientOutput': client_extension_results.get('largeBlob', {}),
            'residentKeyRequested': None,
            'residentKeyRequired': False
        }
    }

    credential_properties = credential_info['properties']
    credential_properties['attestationSignatureValid'] = attestation_signature_valid
    credential_properties['attestationRootValid'] = attestation_root_valid
    credential_properties['attestationRpIdHashValid'] = attestation_rp_id_hash_valid
    credential_properties['attestationAaguidMatch'] = attestation_aaguid_match
    credential_properties['attestationChecks'] = attestation_checks_safe
    credential_properties['attestationSummary'] = attestation_summary
    if warnings:
        credential_properties['attestationWarnings'] = warnings

    if min_pin_length_value is not None:
        credential_properties['minPinLength'] = min_pin_length_value

    add_public_key_material(
        credential_info,
        getattr(auth_data.credential_data, 'public_key', {})
    )

    if parsed_attestation_object:
        credential_info['attestation_object_decoded'] = make_json_safe(parsed_attestation_object)

    if attestation_certificates_details:
        credential_info['attestationCertificates'] = attestation_certificates_details
        credential_properties['attestationCertificates'] = attestation_certificates_details

    if isinstance(response, Mapping):
        credential_info['registration_response'] = make_json_safe(response)

    credential_data = auth_data.credential_data
    aaguid_value = getattr(credential_data, 'aaguid', None)
    if aaguid_value is not None:
        try:
            aaguid_bytes = bytes(aaguid_value)
        except Exception:
            aaguid_bytes = None
        if aaguid_bytes is not None and len(aaguid_bytes) == 16:
            aaguid_hex = aaguid_bytes.hex()
            credential_properties['aaguid'] = aaguid_hex
            credential_properties['aaguidHex'] = aaguid_hex
            try:
                credential_properties['aaguidGuid'] = str(uuid.UUID(bytes=aaguid_bytes))
            except ValueError:
                pass

    try:
        auth_data_bytes = bytes(auth_data)
    except Exception:
        auth_data_bytes = b''

    authenticator_data_raw = ''
    authenticator_data_hex = ''
    authenticator_data_hash = ''
    if auth_data_bytes:
        authenticator_data_raw = base64.urlsafe_b64encode(auth_data_bytes).decode('utf-8').rstrip('=')
        authenticator_data_hex = auth_data_bytes.hex()
        authenticator_data_hash = hashlib.sha256(auth_data_bytes).hexdigest()
        credential_info['authenticator_data_raw'] = authenticator_data_raw
        credential_info['authenticator_data_hex'] = authenticator_data_hex
        credential_info['authenticator_data_hash'] = authenticator_data_hash
        credential_properties['authenticatorDataHash'] = authenticator_data_hash

    algo = auth_data.credential_data.public_key[3]
    if algo == -50:
        algoname = "ML-DSA-87 (PQC)"
    elif algo == -49:
        algoname = "ML-DSA-65 (PQC)"
    elif algo == -48:
        algoname = "ML-DSA-44 (PQC)"
    elif algo == -7:
        algoname = "ES256 (ECDSA)"
    elif algo == -257:
        algoname = "RS256 (RSA)"
    else:
        algoname = "Other (Classical)"

    flags_value = getattr(auth_data, 'flags', 0)
    flags_dict = {
        "UP": bool(flags_value & getattr(auth_data.FLAG, 'UP', 0)),
        "UV": bool(flags_value & getattr(auth_data.FLAG, 'UV', 0)),
        "BE": bool(flags_value & getattr(auth_data.FLAG, 'BE', 0)),
        "BS": bool(flags_value & getattr(auth_data.FLAG, 'BS', 0)),
        "AT": bool(flags_value & getattr(auth_data.FLAG, 'AT', 0)),
        "ED": bool(flags_value & getattr(auth_data.FLAG, 'ED', 0)),
    }

    rp_id_hash_bytes = getattr(auth_data, 'rp_id_hash', b'')
    if isinstance(rp_id_hash_bytes, (bytearray, memoryview)):
        rp_id_hash_bytes = bytes(rp_id_hash_bytes)
    elif not isinstance(rp_id_hash_bytes, bytes):
        rp_id_hash_bytes = b''

    rp_id_hash_hex = rp_id_hash_bytes.hex() if rp_id_hash_bytes else ''
    rp_id_hash_b64 = base64.urlsafe_b64encode(rp_id_hash_bytes).decode('ascii').rstrip('=') if rp_id_hash_bytes else ''

    expected_rp_hash_bytes = hashlib.sha256((resolved_rp_id or '').encode('utf-8')).digest()
    expected_rp_hash_hex = expected_rp_hash_bytes.hex()
    expected_rp_hash_b64 = base64.urlsafe_b64encode(expected_rp_hash_bytes).decode('ascii').rstrip('=')

    if attestation_rp_id_hash_valid is None:
        attestation_rp_id_hash_valid = rp_id_hash_bytes == expected_rp_hash_bytes

    if rp_id_hash_hex:
        credential_properties['rpIdHash'] = rp_id_hash_hex
    if rp_id_hash_b64:
        credential_properties['rpIdHashBase64'] = rp_id_hash_b64
    credential_properties['rpIdHashExpected'] = expected_rp_hash_hex
    credential_properties['rpIdHashExpectedBase64'] = expected_rp_hash_b64

    registration_timestamp = datetime.fromtimestamp(credential_info['registration_time'], timezone.utc).isoformat()

    large_blob_result = False
    if isinstance(client_extension_results, Mapping) and 'largeBlob' in client_extension_results:
        large_blob_value = client_extension_results.get('largeBlob')
        if isinstance(large_blob_value, Mapping):
            large_blob_result = bool(
                large_blob_value.get('supported')
                or large_blob_value.get('written')
                or large_blob_value.get('blob')
                or large_blob_value.get('result')
            )
        else:
            large_blob_result = bool(large_blob_value)

    credential_id_bytes = auth_data.credential_data.credential_id
    credential_id_hex = credential_id_bytes.hex()
    credential_id_b64 = base64.b64encode(credential_id_bytes).decode('ascii')
    credential_id_b64u = base64.urlsafe_b64encode(credential_id_bytes).decode('ascii').rstrip('=')

    try:
        aaguid_bytes = bytes(auth_data.credential_data.aaguid)
    except Exception:
        aaguid_bytes = b""

    cose_public_key = dict(getattr(auth_data.credential_data, 'public_key', {}))
    public_key_bytes = cbor.encode(cose_public_key)

    user_handle_value = credential_info['user_info'].get('user_handle')
    if isinstance(user_handle_value, (bytes, bytearray, memoryview)):
        user_handle_bytes = bytes(user_handle_value)
    else:
        user_handle_bytes = str(user_handle_value or '').encode('utf-8')
    user_handle_b64 = base64.b64encode(user_handle_bytes).decode('ascii')
    user_handle_b64u = base64.urlsafe_b64encode(user_handle_bytes).decode('ascii').rstrip('=')
    user_handle_hex = user_handle_bytes.hex()

    rp_registration_data = {
        "authenticatorData": authenticator_data_hex,
        "authenticatorDataHash": authenticator_data_hash,
        "clientExtensionResults": convert_bytes_for_json(client_extension_results),
        "flags": flags_dict,
        "signatureCounter": getattr(auth_data, 'counter', 0),
        "attestationChecks": attestation_checks_safe,
        "attestationSummary": attestation_summary,
    }
    if warnings:
        rp_registration_data['warnings'] = warnings

    rp_info = {
        "attestationFmt": attestation_format,
        "createdAt": registration_timestamp,
        "credentialId": credential_id_hex,
        "credentialIdBase64": credential_id_b64,
        "credentialIdBase64Url": credential_id_b64u,
        "rpIdHash": rp_id_hash_hex,
        "rpIdHashBase64": rp_id_hash_b64,
        "rpIdHashExpected": expected_rp_hash_hex,
        "rpIdHashExpectedBase64": expected_rp_hash_b64,
        "rpIdHashMatch": bool(attestation_rp_id_hash_valid),
        "authenticatorDataHash": authenticator_data_hash,
        "largeBlob": large_blob_result,
        "publicKeyAlgorithm": algo,
        "registrationData": rp_registration_data,
        "userHandle": {
            "base64": user_handle_b64,
            "base64url": user_handle_b64u,
            "hex": user_handle_hex,
        },
    }

    if aaguid_bytes:
        rp_info["aaguid"] = {
            "raw": aaguid_bytes.hex(),
            "guid": str(uuid.UUID(bytes=aaguid_bytes)) if len(aaguid_bytes) == 16 else None,
        }

    credential_info['relying_party'] = make_json_safe(rp_info)

    debug_info = {
        "attestationFormat": attestation_format,
        "algorithmsUsed": [algo],
        "excludeCredentialsUsed": False,
        "hintsUsed": [],
        "credProtectUsed": "none",
        "enforceCredProtectUsed": False,
        "actualResidentKey": bool(flags_value & getattr(auth_data.FLAG, 'BE', 0)),
        "attestationSummary": attestation_summary,
        "rpIdHashValid": attestation_rp_id_hash_valid,
        "rpIdHash": rp_id_hash_hex,
        "rpIdHashExpected": expected_rp_hash_hex,
    }

    session.pop("register_rp_id", None)

    stored_credential: Dict[str, Any] = {
        "type": "simple",
        "email": uname,
        "userName": credential_info['user_info'].get('name', uname),
        "displayName": credential_info['user_info'].get('display_name', uname),
        "credentialId": credential_id_b64,
        "credentialIdBase64Url": credential_id_b64u,
        "credentialIdHex": credential_id_hex,
        "aaguid": base64.urlsafe_b64encode(aaguid_bytes).decode('ascii').rstrip('=') if aaguid_bytes else None,
        "aaguidHex": aaguid_bytes.hex() if aaguid_bytes else None,
        "publicKey": base64.b64encode(public_key_bytes).decode('ascii'),
        "publicKeyBase64Url": base64.urlsafe_b64encode(public_key_bytes).decode('ascii').rstrip('='),
        "publicKeyAlgorithm": credential_info.get('publicKeyAlgorithm') or algo,
        "signCount": getattr(auth_data, 'counter', 0),
        "createdAt": credential_info['registration_time'],
        "clientExtensionOutputs": convert_bytes_for_json(client_extension_results),
        "attestationFormat": attestation_format,
        "attestationStatement": convert_bytes_for_json(attestation_statement),
        "properties": convert_bytes_for_json(credential_properties),
        "publicKeyCose": convert_bytes_for_json(cose_public_key),
        "publicKeyBytes": base64.b64encode(public_key_bytes).decode('ascii'),
        "authenticatorAttachment": authenticator_attachment_response,
        "clientDataJSON": credential_info.get('client_data_json'),
        "attestationObject": credential_info.get('attestation_object'),
        "authenticatorData": authenticator_data_raw,
        "authenticatorDataHex": authenticator_data_hex,
        "authenticatorDataHash": authenticator_data_hash or None,
        "relyingParty": make_json_safe(rp_info),
        "registrationResponse": credential_info.get('registration_response'),
    }

    stored_credential['userHandle'] = user_handle_b64u

    # Persist credential to storage (GCS or local filesystem)
    # Store complete credential info including attestation data
    metadata_session_id = ensure_metadata_session_id()
    existing_credentials = readkey(uname, session_id=metadata_session_id)
    
    # Create the credential entry with both credential_data and full info
    credential_entry = {
        'credential_data': auth_data.credential_data,
        'auth_data': auth_data,
        'user_info': credential_info['user_info'],
        'registration_time': credential_info['registration_time'],
        'client_data_json': credential_info.get('client_data_json', ''),
        'attestation_object': credential_info.get('attestation_object', ''),
        'attestation_object_raw': credential_info.get('attestation_object_raw', ''),
        'attestation_format': attestation_format,
        'attestation_statement': attestation_statement,
        'attestation_certificate': attestation_certificate_details,
        'attestation_certificates': attestation_certificates_details,
        'client_extension_outputs': client_extension_results,
        'authenticator_attachment': authenticator_attachment_response,
        'request_params': credential_info.get('request_params', {}),
        'properties': credential_properties,
        'relying_party': credential_info.get('relying_party'),
        'registration_response': credential_info.get('registration_response'),
    }
    
    # Add attestation object decoded if available
    if parsed_attestation_object:
        credential_entry['attestation_object_decoded'] = make_json_safe(parsed_attestation_object)
    
    # Append to existing credentials list or create new list
    if isinstance(existing_credentials, list):
        existing_credentials.append(credential_entry)
    else:
        existing_credentials = [credential_entry]
    
    # Save to persistent storage
    savekey(uname, existing_credentials, session_id=metadata_session_id)

    session_simple_credentials = session.get('simple_credentials')
    if isinstance(session_simple_credentials, list):
        new_entry = {
            "credentialId": stored_credential["credentialIdBase64Url"],
            "aaguid": stored_credential.get("aaguid"),
            "publicKey": stored_credential["publicKeyBase64Url"],
            "algorithm": stored_credential.get("publicKeyAlgorithm"),
            "signCount": stored_credential.get("signCount", 0),
            "email": stored_credential.get("email"),
            "type": "simple",
        }
        session_simple_credentials = [entry for entry in session_simple_credentials if isinstance(entry, Mapping)]
        session_simple_credentials.append(new_entry)
        session['simple_credentials'] = session_simple_credentials

    metadata_description: Optional[str] = None
    if isinstance(metadata_summary, Mapping):
        raw_description = metadata_summary.get("description")
        if isinstance(raw_description, str):
            metadata_description = raw_description

    transports_field = response.get('transports') if isinstance(response, Mapping) else None
    transports: Optional[List[str]] = None
    if isinstance(transports_field, list):
        transports = [str(item) for item in transports_field if isinstance(item, str)]

    event = RegistrationEvent(
        timestamp=datetime.now(timezone.utc),
        rp_id=resolved_rp_id,
        user_id=user_handle_bytes,
        user_name=str(uname or ""),
        user_display_name=str(credential_info['user_info'].get('display_name') or uname or ""),
        credential_id=credential_id_bytes,
        public_key_cose=cose_public_key,
        sign_count=int(getattr(auth_data, 'counter', 0)),
        transports=transports,
        aaguid=aaguid_bytes or None,
        device_name_mds=metadata_description,
        attestation_format=str(attestation_format or ""),
        attestation_object=_decode_base64url_bytes(raw_attestation_object_b64),
        client_data_json=_decode_base64url_bytes(client_data_json_b64),
        signature_valid=attestation_signature_valid,
        root_valid=attestation_root_valid,
        rp_id_hash_valid=attestation_rp_id_hash_valid,
        aaguid_match=attestation_aaguid_match,
    )

    record_registration_event(event)

    response_payload: Dict[str, Any] = {
        "status": "OK",
        "algo": algoname,
        **debug_info,
        "storedCredential": convert_bytes_for_json(stored_credential),
        "relyingParty": rp_info,
    }
    if warnings:
        response_payload["warnings"] = warnings

    return jsonify(response_payload)


@app.route("/api/authenticate/begin", methods=["POST"])
def authenticate_begin():
    uname = request.args.get("email")
    payload = request.get_json(silent=True) or {}

    raw_credentials: List[Any] = []
    if isinstance(payload, Mapping):
        candidate_credentials = payload.get("credentials") or payload.get("storedCredentials")
        if isinstance(candidate_credentials, list):
            raw_credentials = candidate_credentials

    credential_data_list, serialized = _parse_client_credentials(raw_credentials)

    if not credential_data_list:
        abort(404)

    session['simple_credentials'] = serialized
    session['simple_credentials_email'] = uname

    rp_id = determine_rp_id()
    server = create_fido_server(rp_id=rp_id)

    options, state = server.authenticate_begin(
        credential_data_list,
        user_verification="discouraged"
    )
    session["state"] = state
    session["authenticate_rp_id"] = rp_id

    options_payload = dict(options)
    options_payload["__session_state"] = make_json_safe(state)

    return jsonify(make_json_safe(options_payload))


@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    uname = request.args.get("email")
    response = request.get_json(silent=True)
    session_credentials = session.pop('simple_credentials', [])
    credential_data_list, _ = _parse_client_credentials(session_credentials)
    if not credential_data_list:
        abort(400)

    state = session.pop("state", None)
    state_from_request = None
    if isinstance(response, Mapping):
        state_from_request = response.pop("__session_state", None)
    if state is None and isinstance(state_from_request, Mapping):
        state = state_from_request
    if state is None:
        session.pop("authenticate_rp_id", None)
        return jsonify({"error": "Authentication state not found or has expired. Please restart the authentication flow."}), 400

    rp_id = session.pop("authenticate_rp_id", None)
    server = create_fido_server(rp_id=rp_id)

    response_mapping: Mapping[str, Any]
    response_mapping = response if isinstance(response, Mapping) else {}

    try:
        matched_credential = server.authenticate_complete(
            state,
            credential_data_list,
            response,
        )
    except Exception as exc:
        failed_credential_id = None
        credential_id_bytes = _extract_assertion_credential_id(response_mapping)
        if credential_id_bytes:
            failed_credential_id = base64.urlsafe_b64encode(credential_id_bytes).decode("ascii").rstrip("=")

        response_payload: Dict[str, Any] = {"error": str(exc)}
        if failed_credential_id is not None:
            response_payload["failedCredentialId"] = failed_credential_id

        session.pop('simple_credentials_email', None)
        return jsonify(response_payload), 400

    credential_response = response_mapping.get('response', {}) if isinstance(response_mapping, Mapping) else {}
    auth_data_b64 = credential_response.get('authenticatorData') if isinstance(credential_response, Mapping) else None
    sign_count = None
    if isinstance(auth_data_b64, str):
        try:
            auth_data_bytes = base64.b64decode(_add_base64_padding(auth_data_b64))
            sign_count = AuthenticatorData(auth_data_bytes).counter
        except Exception:
            sign_count = None

    authenticated_id = None
    try:
        credential_id_bytes = bytes(getattr(matched_credential, 'credential_id', b''))
        if credential_id_bytes:
            authenticated_id = base64.urlsafe_b64encode(credential_id_bytes).decode('ascii').rstrip('=')
    except Exception:
        authenticated_id = None

    debug_info = {
        "hintsUsed": [],
    }

    response_payload: Dict[str, Any] = {
        "status": "OK",
        **debug_info,
    }
    if authenticated_id is not None:
        response_payload["authenticatedCredentialId"] = authenticated_id
    if sign_count is not None:
        response_payload["signCount"] = sign_count

    session.pop('simple_credentials_email', None)

    return jsonify(response_payload)


@app.route("/api/credentials", methods=["GET", "DELETE"])
def list_credentials():
    metadata_session_id = ensure_metadata_session_id()
    if request.method == "DELETE":
        removed = 0
        try:
            for username in list(storage_list_credentials(session_id=metadata_session_id).keys()):
                delkey(username, session_id=metadata_session_id)
                removed += 1
        except Exception:
            pass

        return jsonify({"status": "OK", "removed": removed})

    credentials: List[Dict[str, Any]] = []

    def add_registration_metadata(target: Dict[str, Any], source: Mapping[str, Any]) -> None:
        registration_response = source.get('registration_response')
        if registration_response is None:
            registration_response = source.get('registrationResponse')
        if registration_response is not None:
            if isinstance(registration_response, Mapping):
                target['registrationResponse'] = make_json_safe(registration_response)
            else:
                target['registrationResponse'] = registration_response

        registration_rp = source.get('relying_party')
        if registration_rp is None:
            registration_rp = source.get('relyingParty')
        if registration_rp is not None:
            if isinstance(registration_rp, Mapping):
                target['relyingParty'] = make_json_safe(registration_rp)
            else:
                target['relyingParty'] = registration_rp

        client_data_value = source.get('client_data_json')
        if client_data_value is None:
            client_data_value = source.get('clientDataJSON')
        if isinstance(client_data_value, Mapping):
            target['clientDataJSON'] = make_json_safe(client_data_value)
        elif isinstance(client_data_value, str) and client_data_value:
            target['clientDataJSON'] = client_data_value

    try:
        for email, user_creds in iter_credentials(session_id=metadata_session_id):
            try:
                for cred in user_creds:
                    try:
                        if isinstance(cred, dict) and 'credential_data' in cred:
                            if isinstance(cred['credential_data'], dict):
                                cred_data = cred['credential_data']
                                auth_data = cred['auth_data']
                                user_info = cred['user_info']

                                properties_source = cred.get('properties')
                                properties_copy = properties_source.copy() if isinstance(properties_source, dict) else {}
                                attachment_value = normalize_attachment(
                                    cred.get('authenticator_attachment')
                                    or cred.get('authenticatorAttachment')
                                    or properties_copy.get('authenticatorAttachment')
                                    or properties_copy.get('authenticator_attachment')
                                )

                                aaguid_hex = coerce_aaguid_hex(cred_data.get('aaguid'))

                                credential_info = {
                                    'email': email,
                                    'credentialId': base64.b64encode(cred_data['credential_id']).decode('utf-8'),
                                    'userName': user_info.get('name', email),
                                    'displayName': user_info.get('display_name', email),
                                    'userHandle': base64.b64encode(user_info.get('user_handle', cred_data['credential_id'])).decode('utf-8') if user_info.get('user_handle') else None,
                                    'algorithm': cred_data.get('public_key', {}).get(3, 'Unknown'),
                                    'type': 'WebAuthn',
                                    'createdAt': cred.get('registration_time'),
                                    'signCount': auth_data.get('counter', 0),
                                    'aaguid': aaguid_hex,
                                    'flags': auth_data.get('flags', {}),
                                    'clientExtensionOutputs': cred.get('client_extension_outputs', {}),
                                    'attestationFormat': cred.get('attestation_format', 'none'),
                                    'attestationStatement': convert_bytes_for_json(cred.get('attestation_statement', {})),
                                    'publicKeyAlgorithm': cred_data.get('public_key', {}).get(3),
                                    'authenticatorAttachment': attachment_value,
                                    'residentKey': auth_data.get('flags', {}).get('be', False),
                                    'largeBlob': cred.get('client_extension_outputs', {}).get('largeBlob', {}).get('supported', False),
                                    'properties': properties_copy,
                                }

                                if attachment_value is not None:
                                    properties_copy['authenticatorAttachment'] = attachment_value

                                certificate_details = cred.get('attestation_certificate')
                                if certificate_details is not None:
                                    credential_info['attestationCertificate'] = certificate_details

                                certificates_list = cred.get('attestation_certificates') or cred.get('attestationCertificates')
                                if certificates_list:
                                    credential_info['attestationCertificates'] = certificates_list
                                    credential_info['attestation_certificates'] = certificates_list

                                add_registration_metadata(credential_info, cred)

                                add_public_key_material(credential_info, cred_data.get('public_key', {}))
                                if credential_info.get('publicKeyAlgorithm') is not None:
                                    credential_info['algorithm'] = credential_info['publicKeyAlgorithm']

                                augment_aaguid_fields(credential_info)
                                if isinstance(properties_copy, MutableMapping):
                                    if credential_info.get('aaguidHex'):
                                        properties_copy.setdefault('aaguid', credential_info['aaguidHex'])
                                        properties_copy.setdefault('aaguidHex', credential_info['aaguidHex'])
                                        properties_copy.setdefault('aaguidRaw', credential_info['aaguidHex'])
                                    if credential_info.get('aaguidGuid'):
                                        properties_copy.setdefault('aaguidGuid', credential_info['aaguidGuid'])

                                raw_attestation_value = (
                                    cred.get('attestation_object_raw')
                                    or cred.get('attestationObjectRaw')
                                )
                                if not raw_attestation_value:
                                    stored_att_obj = cred.get('attestation_object')
                                    if isinstance(stored_att_obj, str):
                                        raw_attestation_value = stored_att_obj

                                decoded_attestation_value = (
                                    cred.get('attestation_object_decoded')
                                    or cred.get('attestationObjectDecoded')
                                )
                                if decoded_attestation_value is None:
                                    stored_att_obj = cred.get('attestation_object')
                                    if isinstance(stored_att_obj, Mapping):
                                        decoded_attestation_value = stored_att_obj

                                if raw_attestation_value:
                                    credential_info['attestationObjectRaw'] = raw_attestation_value
                                if decoded_attestation_value is not None:
                                    credential_info['attestationObjectDecoded'] = make_json_safe(decoded_attestation_value)

                                raw_authenticator_value = (
                                    cred.get('authenticator_data_raw')
                                    or cred.get('authenticatorDataRaw')
                                )
                                authenticator_hex_value = (
                                    cred.get('authenticator_data_hex')
                                    or cred.get('authenticatorDataHex')
                                )

                                try:
                                    auth_data_bytes = bytes(auth_data)
                                except Exception:
                                    auth_data_bytes = b''

                                if auth_data_bytes:
                                    if not raw_authenticator_value:
                                        raw_authenticator_value = base64.urlsafe_b64encode(auth_data_bytes).decode('utf-8').rstrip('=')
                                    if not authenticator_hex_value:
                                        authenticator_hex_value = auth_data_bytes.hex()

                                if raw_authenticator_value:
                                    credential_info['authenticatorDataRaw'] = raw_authenticator_value
                                if authenticator_hex_value:
                                    credential_info['authenticatorDataHex'] = authenticator_hex_value
                            else:
                                cred_data = cred['credential_data']
                                auth_data = cred['auth_data']
                                user_info = cred['user_info']

                                properties_source = cred.get('properties')
                                properties_copy = properties_source.copy() if isinstance(properties_source, dict) else {}
                                attachment_value = normalize_attachment(
                                    cred.get('authenticator_attachment')
                                    or cred.get('authenticatorAttachment')
                                    or properties_copy.get('authenticatorAttachment')
                                    or properties_copy.get('authenticator_attachment')
                                )

                                rk_from_credprops = cred.get('client_extension_outputs', {}).get('credProps', {}).get('rk', None)
                                rk_from_request = cred.get('request_params', {}).get('resident_key') == 'required'
                                resident_key_status = rk_from_credprops if rk_from_credprops is not None else rk_from_request

                                aaguid_hex = coerce_aaguid_hex(getattr(cred_data, 'aaguid', None))

                                credential_info = {
                                    'email': email,
                                    'credentialId': base64.b64encode(cred_data.credential_id).decode('utf-8'),
                                    'userName': user_info.get('name', email),
                                    'displayName': user_info.get('display_name', email),
                                    'userHandle': base64.b64encode(user_info.get('user_handle')).decode('utf-8') if user_info.get('user_handle') else None,
                                    'algorithm': cred_data.public_key[3] if hasattr(cred_data, 'public_key') and len(cred_data.public_key) > 3 else 'Unknown',
                                    'type': 'WebAuthn',
                                    'createdAt': cred.get('registration_time'),
                                    'signCount': auth_data.counter if hasattr(auth_data, 'counter') else 0,
                                    'aaguid': aaguid_hex,
                                    'flags': {
                                        'up': bool(auth_data.flags & auth_data.FLAG.UP) if hasattr(auth_data, 'flags') else True,
                                        'uv': bool(auth_data.flags & auth_data.FLAG.UV) if hasattr(auth_data, 'flags') else True,
                                        'at': bool(auth_data.flags & auth_data.FLAG.AT) if hasattr(auth_data, 'flags') else True,
                                        'ed': bool(auth_data.flags & auth_data.FLAG.ED) if hasattr(auth_data, 'flags') else False,
                                        'be': bool(auth_data.flags & auth_data.FLAG.BE) if hasattr(auth_data, 'flags') else False,
                                        'bs': bool(auth_data.flags & auth_data.FLAG.BS) if hasattr(auth_data, 'flags') else False,
                                    },
                                    'clientExtensionOutputs': cred.get('client_extension_outputs', {}),
                                    'attestationFormat': cred.get('attestation_format', 'none'),
                                    'attestationStatement': convert_bytes_for_json(cred.get('attestation_statement', {})),
                                    'publicKeyAlgorithm': cred_data.public_key[3] if hasattr(cred_data, 'public_key') and len(cred_data.public_key) > 3 else None,
                                    'authenticatorAttachment': attachment_value,
                                    'residentKey': resident_key_status,
                                    'largeBlob': cred.get('client_extension_outputs', {}).get('largeBlob', {}).get('supported', False),
                                    'requestParams': cred.get('request_params', {}),
                                    'properties': properties_copy,
                                }

                                certificate_details = cred.get('attestation_certificate')
                                if certificate_details is not None:
                                    credential_info['attestationCertificate'] = certificate_details

                                if attachment_value is not None:
                                    properties_copy['authenticatorAttachment'] = attachment_value

                                add_registration_metadata(credential_info, cred)

                                add_public_key_material(credential_info, getattr(cred_data, 'public_key', {}))
                                if credential_info.get('publicKeyAlgorithm') is not None:
                                    credential_info['algorithm'] = credential_info['publicKeyAlgorithm']

                                augment_aaguid_fields(credential_info)
                                if isinstance(properties_copy, MutableMapping):
                                    if credential_info.get('aaguidHex'):
                                        properties_copy.setdefault('aaguid', credential_info['aaguidHex'])
                                        properties_copy.setdefault('aaguidHex', credential_info['aaguidHex'])
                                        properties_copy.setdefault('aaguidRaw', credential_info['aaguidHex'])
                                    if credential_info.get('aaguidGuid'):
                                        properties_copy.setdefault('aaguidGuid', credential_info['aaguidGuid'])
                        else:
                            aaguid_hex = coerce_aaguid_hex(getattr(cred, 'aaguid', None))

                            credential_info = {
                                'email': email,
                                'credentialId': base64.b64encode(cred.credential_id).decode('utf-8'),
                                'userName': email,
                                'displayName': email,
                                'userHandle': None,
                                'algorithm': cred.public_key[3] if hasattr(cred, 'public_key') and len(cred.public_key) > 3 else 'Unknown',
                                'type': 'WebAuthn',
                                'createdAt': None,
                                'signCount': 0,
                                'authenticatorAttachment': None,
                                'aaguid': aaguid_hex,
                                'flags': {
                                    'up': True,
                                    'uv': True,
                                    'at': True,
                                    'ed': False,
                                    'be': False,
                                    'bs': False,
                                },
                                'clientExtensionOutputs': {},
                                'attestationFormat': 'none',
                                'attestationStatement': {},
                                'publicKeyAlgorithm': cred.public_key[3] if hasattr(cred, 'public_key') and len(cred.public_key) > 3 else None,
                                'residentKey': False,
                                'largeBlob': False,
                                'properties': {},
                            }

                            add_public_key_material(credential_info, getattr(cred, 'public_key', {}))
                            if credential_info.get('publicKeyAlgorithm') is not None:
                                credential_info['algorithm'] = credential_info['publicKeyAlgorithm']

                            augment_aaguid_fields(credential_info)

                        credentials.append(credential_info)
                    except Exception:
                        continue
            except Exception:
                continue

    except Exception:
        pass

    return jsonify(credentials)
