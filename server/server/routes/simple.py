"""Routes for the basic registration and authentication flows."""
from __future__ import annotations

import base64
import os
import time
import uuid
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Sequence, Set, Tuple

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
)
from ..config import app, basepath, create_fido_server, determine_rp_id
from ..storage import (
    add_public_key_material,
    convert_bytes_for_json,
    delkey,
    extract_credential_data,
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


def _load_credentials_for_user(email: str) -> List[Tuple[AttestedCredentialData, Dict[str, Any]]]:
    if not email:
        return []

    stored_credentials = readkey(email)
    if not isinstance(stored_credentials, list):
        return []

    results: List[Tuple[AttestedCredentialData, Dict[str, Any]]] = []

    for stored_entry in stored_credentials:
        try:
            credential_data = extract_credential_data(stored_entry)
        except Exception:
            continue

        if not isinstance(credential_data, AttestedCredentialData):
            continue

        try:
            credential_id_bytes = bytes(credential_data.credential_id)
            aaguid_bytes = bytes(credential_data.aaguid)
            cose_public_key = dict(getattr(credential_data, "public_key", {}))
            public_key_bytes = cbor.encode(cose_public_key)
        except Exception:
            continue

        serialized_source: Dict[str, Any] = {
            "credentialId": credential_id_bytes,
            "aaguid": aaguid_bytes,
            "publicKey": public_key_bytes,
            "type": "simple",
            "email": email,
        }

        if isinstance(stored_entry, Mapping):
            user_info = stored_entry.get("user_info")
            if isinstance(user_info, Mapping):
                if "name" in user_info:
                    serialized_source["userName"] = user_info["name"]
                if "display_name" in user_info:
                    serialized_source["displayName"] = user_info["display_name"]

            if isinstance(stored_entry.get("signCount"), int):
                serialized_source["signCount"] = stored_entry["signCount"]

            algorithm_value = stored_entry.get("publicKeyAlgorithm") or stored_entry.get("algorithm")
            if isinstance(algorithm_value, int):
                serialized_source["algorithm"] = algorithm_value
        else:
            algorithm_value = None

        auth_data_value = None
        if isinstance(stored_entry, Mapping):
            auth_data_value = stored_entry.get("auth_data")
        elif hasattr(stored_entry, "auth_data"):
            auth_data_value = getattr(stored_entry, "auth_data")

        counter_value = None
        if isinstance(auth_data_value, Mapping):
            counter_candidate = auth_data_value.get("counter")
        else:
            counter_candidate = getattr(auth_data_value, "counter", None)
        if isinstance(counter_candidate, int):
            counter_value = counter_candidate

        if counter_value is not None:
            serialized_source["signCount"] = counter_value

        if "algorithm" not in serialized_source and isinstance(cose_public_key.get(3), int):
            serialized_source["algorithm"] = cose_public_key[3]

        serialized = _serialize_credential_for_session(serialized_source)
        if "credentialId" not in serialized:
            serialized["credentialId"] = base64.urlsafe_b64encode(credential_id_bytes).decode("ascii").rstrip("=")
        if "aaguid" not in serialized:
            serialized["aaguid"] = base64.urlsafe_b64encode(aaguid_bytes).decode("ascii").rstrip("=")
        if "publicKey" not in serialized:
            serialized["publicKey"] = base64.urlsafe_b64encode(public_key_bytes).decode("ascii").rstrip("=")

        results.append((credential_data, serialized))

    return results


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

    credential_response.get('attestationObject')
    client_data_json = credential_response.get('clientDataJSON')

    if parsed_attestation_object:
        parsed_attestation_object
    if parsed_client_data_json:
        client_data_json = parsed_client_data_json

    client_extension_results = (
        parsed_extension_results
        if parsed_extension_results
        else (response.get('clientExtensionResults', {}) if isinstance(response, dict) else {})
    )

    min_pin_length_value = extract_min_pin_length(client_extension_results)

    rp_id = session.get("register_rp_id")
    server = create_fido_server(rp_id=rp_id)

    auth_data = server.register_complete(session["state"], response)

    authenticator_attachment_response = normalize_attachment(
        response.get('authenticatorAttachment') if isinstance(response, Mapping) else None
    )

    raw_attestation_object = credential_response.get('attestationObject')

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

    if min_pin_length_value is not None:
        credential_info['properties']['minPinLength'] = min_pin_length_value

    add_public_key_material(
        credential_info,
        getattr(auth_data.credential_data, 'public_key', {})
    )

    if parsed_attestation_object:
        credential_info['attestation_object_decoded'] = make_json_safe(parsed_attestation_object)

    if attestation_certificates_details:
        credential_info['attestationCertificates'] = attestation_certificates_details
        credential_info['properties']['attestationCertificates'] = attestation_certificates_details

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
            credential_info['properties']['aaguid'] = aaguid_hex
            credential_info['properties']['aaguidHex'] = aaguid_hex
            try:
                credential_info['properties']['aaguidGuid'] = str(uuid.UUID(bytes=aaguid_bytes))
            except ValueError:
                pass

    try:
        auth_data_bytes = bytes(auth_data)
        credential_info['authenticator_data_raw'] = base64.urlsafe_b64encode(auth_data_bytes).decode('utf-8').rstrip('=')
        credential_info['authenticator_data_hex'] = auth_data_bytes.hex()
    except Exception:
        pass

    algo = auth_data.credential_data.public_key[3]
    ""
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

    debug_info = {
        "attestationFormat": attestation_format,
        "algorithmsUsed": [algo],
        "excludeCredentialsUsed": False,
        "hintsUsed": [],
        "credProtectUsed": "none",
        "enforceCredProtectUsed": False,
        "actualResidentKey": bool(auth_data.flags & 0x04) if hasattr(auth_data, 'flags') else False,
    }

    session.pop("register_rp_id", None)

    credential_id_bytes = auth_data.credential_data.credential_id
    try:
        aaguid_bytes = bytes(auth_data.credential_data.aaguid)
    except Exception:
        aaguid_bytes = b""

    cose_public_key = dict(getattr(auth_data.credential_data, 'public_key', {}))
    public_key_bytes = cbor.encode(cose_public_key)

    stored_credential: Dict[str, Any] = {
        "type": "simple",
        "email": uname,
        "userName": credential_info['user_info'].get('name', uname),
        "displayName": credential_info['user_info'].get('display_name', uname),
        "credentialId": base64.b64encode(credential_id_bytes).decode('ascii'),
        "credentialIdBase64Url": base64.urlsafe_b64encode(credential_id_bytes).decode('ascii').rstrip('='),
        "credentialIdHex": credential_id_bytes.hex(),
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
        "properties": convert_bytes_for_json(credential_info.get('properties', {})),
        "publicKeyCose": convert_bytes_for_json(cose_public_key),
        "publicKeyBytes": base64.b64encode(public_key_bytes).decode('ascii'),
        "authenticatorAttachment": authenticator_attachment_response,
        "clientDataJSON": credential_info.get('client_data_json'),
        "attestationObject": credential_info.get('attestation_object'),
        "authenticatorData": credential_info.get('authenticator_data_raw'),
    }

    user_handle_value = credential_info['user_info'].get('user_handle')
    if isinstance(user_handle_value, (bytes, bytearray, memoryview)):
        stored_credential['userHandle'] = base64.urlsafe_b64encode(bytes(user_handle_value)).decode('ascii').rstrip('=')

    if uname:
        existing_entries = readkey(uname)
        filtered_entries: List[Any] = []
        replaced = False
        credential_id_bytes = bytes(auth_data.credential_data.credential_id)
        seen_ids: Set[bytes] = set()
        if isinstance(existing_entries, list):
            for entry in existing_entries:
                try:
                    existing_data = extract_credential_data(entry)
                except Exception:
                    # Unable to parse this entry; keep it as-is
                    filtered_entries.append(entry)
                    continue

                if not isinstance(existing_data, AttestedCredentialData):
                    filtered_entries.append(entry)
                    continue

                try:
                    existing_id = bytes(existing_data.credential_id)
                except Exception:
                    filtered_entries.append(entry)
                    continue

                if existing_id in seen_ids:
                    # Skip duplicate stored credentials that share the same ID
                    continue
                seen_ids.add(existing_id)

                if existing_id == credential_id_bytes:
                    if not replaced:
                        filtered_entries.append(credential_info)
                        replaced = True
                    # Skip appending additional duplicates of the same credential
                    continue

                filtered_entries.append(entry)

        if not replaced:
            filtered_entries.append(credential_info)
        savekey(uname, filtered_entries)

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

        filtered_session_credentials: List[Dict[str, Any]] = []
        for entry in session_simple_credentials:
            if not isinstance(entry, Mapping):
                continue
            existing_id = entry.get("credentialId")
            if isinstance(existing_id, str) and existing_id == new_entry["credentialId"]:
                continue
            filtered_session_credentials.append(dict(entry))

        filtered_session_credentials.append(new_entry)
        session['simple_credentials'] = filtered_session_credentials

    return jsonify({
        "status": "OK",
        "algo": algoname,
        **debug_info,
        "storedCredential": convert_bytes_for_json(stored_credential),
    })


@app.route("/api/authenticate/begin", methods=["POST"])
def authenticate_begin():
    uname = request.args.get("email")
    payload = request.get_json(silent=True) or {}

    credential_candidates: List[Any] = []
    if isinstance(payload, Mapping):
        candidate_credentials = payload.get("credentials") or payload.get("storedCredentials")
        if isinstance(candidate_credentials, list):
            credential_candidates = candidate_credentials

    stored_credentials = _load_credentials_for_user(uname)

    candidate_ids: List[bytes] = []
    for entry in credential_candidates:
        if not isinstance(entry, Mapping):
            continue
        raw_identifier = _select_first(
            entry,
            (
                "credentialId",
                "credentialIdBase64Url",
                "credentialID",
                "id",
                "rawId",
            ),
        )
        if raw_identifier is None:
            continue
        try:
            candidate_ids.append(_decode_binary_value(raw_identifier))
        except Exception:
            continue

    if candidate_ids:
        candidate_id_set = {candidate for candidate in candidate_ids}
        filtered_credentials = [
            item
            for item in stored_credentials
            if bytes(item[0].credential_id) in candidate_id_set
        ]
    else:
        filtered_credentials = stored_credentials

    credential_data_list = [item[0] for item in filtered_credentials]
    serialized = [item[1] for item in filtered_credentials]

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

    return jsonify(make_json_safe(dict(options)))


@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    uname = request.args.get("email")
    response = request.get_json(silent=True)
    session_credentials = session.pop('simple_credentials', [])
    credential_data_list, _ = _parse_client_credentials(session_credentials)
    if not credential_data_list:
        abort(400)

    rp_id = session.pop("authenticate_rp_id", None)
    server = create_fido_server(rp_id=rp_id)

    matched_credential = server.authenticate_complete(
        session.pop("state"),
        credential_data_list,
        response,
    )

    credential_response = response.get('response', {}) if isinstance(response, Mapping) else {}
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
    if request.method == "DELETE":
        removed = 0
        try:
            for filename in os.listdir(basepath):
                if not filename.endswith('_credential_data.pkl'):
                    continue
                username = filename.replace('_credential_data.pkl', '')
                delkey(username)
                removed += 1
        except Exception:
            pass

        return jsonify({"status": "OK", "removed": removed})

    credentials: List[Dict[str, Any]] = []
    seen_credential_ids: Set[str] = set()

    def _append_credential(entry: Dict[str, Any]) -> None:
        credential_id_value = entry.get('credentialId')
        normalized_id: str | None = None

        if isinstance(credential_id_value, str):
            try:
                credential_id_bytes = _decode_binary_value(credential_id_value)
            except ValueError:
                normalized_id = credential_id_value
            else:
                normalized_id = (
                    base64.urlsafe_b64encode(credential_id_bytes).decode('ascii').rstrip('=')
                )
        elif isinstance(credential_id_value, (bytes, bytearray, memoryview)):
            credential_id_bytes = bytes(credential_id_value)
            normalized_id = base64.urlsafe_b64encode(credential_id_bytes).decode('ascii').rstrip('=')

        if normalized_id is None:
            normalized_id = str(credential_id_value)

        if normalized_id in seen_credential_ids:
            return

        seen_credential_ids.add(normalized_id)
        credentials.append(entry)

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
        pkl_files = [f for f in os.listdir(basepath) if f.endswith('_credential_data.pkl')]

        for pkl_file in pkl_files:
            email = pkl_file.replace('_credential_data.pkl', '')

            try:
                user_creds = readkey(email)
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

                                _append_credential(credential_info)
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

                        _append_credential(credential_info)
                    except Exception:
                        continue
            except Exception:
                continue

    except Exception:
        pass

    return jsonify(credentials)
