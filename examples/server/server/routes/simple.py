"""Routes for the basic registration and authentication flows."""
from __future__ import annotations

import base64
import os
import time
import uuid
from typing import Any, Dict, List, Mapping, MutableMapping

from flask import abort, jsonify, request, session
from fido2.webauthn import PublicKeyCredentialUserEntity

from ..attachments import normalize_attachment
from ..attestation import (
    augment_aaguid_fields,
    coerce_aaguid_hex,
    extract_attestation_details,
    extract_min_pin_length,
    make_json_safe,
)
from ..config import app, basepath, create_fido_server, determine_rp_id
from ..storage import add_public_key_material, convert_bytes_for_json, delkey, extract_credential_data, readkey, savekey


@app.route("/api/register/begin", methods=["POST"])
def register_begin():
    raw_request_payload = request.get_data(cache=True, as_text=True)
    parsed_payload = request.get_json(silent=True)
    print("[DEBUG] Raw registration begin request payload:", raw_request_payload or "<empty>")
    if parsed_payload is not None:
        print("[DEBUG] Parsed registration begin request:", parsed_payload)
    if request.args:
        print("[DEBUG] Registration begin query parameters:", request.args.to_dict(flat=False))

    uname = request.args.get("email")
    credentials = readkey(uname)
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

    options_payload = make_json_safe(dict(options))
    print("[DEBUG] Registration options generated:", options_payload)

    return jsonify(options_payload)


@app.route("/api/register/complete", methods=["POST"])
def register_complete():
    uname = request.args.get("email")
    credentials = readkey(uname)
    raw_request_payload = request.get_data(as_text=True)
    response = request.get_json(silent=True) or {}
    print("[DEBUG] Raw registration request payload:", raw_request_payload or "<empty>")
    print("[DEBUG] Parsed registration response:", response)
    credential_response = response.get('response', {}) if isinstance(response, dict) else {}
    if credential_response:
        print("[DEBUG] Parsed credential.response payload:", credential_response)

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

    credentials.append(credential_info)
    savekey(uname, credentials)

    algo = auth_data.credential_data.public_key[3]
    algoname = ""
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

    response_payload = {
        "status": "OK",
        "algo": algoname,
        **debug_info
    }
    print("[DEBUG] Registration completion response:", response_payload)

    return jsonify(response_payload)


@app.route("/api/authenticate/begin", methods=["POST"])
def authenticate_begin():
    uname = request.args.get("email")
    credentials = readkey(uname)
    if not credentials:
        abort(404)

    credential_data_list = [extract_credential_data(cred) for cred in credentials]

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
    credentials = readkey(uname)
    if not credentials:
        abort(404)

    credential_data_list = [extract_credential_data(cred) for cred in credentials]

    response = request.get_json(silent=True)
    rp_id = session.pop("authenticate_rp_id", None)
    server = create_fido_server(rp_id=rp_id)

    server.authenticate_complete(
        session.pop("state"),
        credential_data_list,
        response,
    )

    debug_info = {
        "hintsUsed": [],
    }

    return jsonify({
        "status": "OK",
        **debug_info
    })


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
