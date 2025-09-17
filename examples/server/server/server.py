# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Example demo server to use a supported web browser to call the WebAuthn APIs
to register and use a credential.

See the file README.adoc in this directory for details.

Navigate to http://localhost:5000 in a supported web browser.
"""
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
)
from fido2.server import Fido2Server
from fido2.utils import ByteBuffer
from flask import Flask, request, redirect, abort, jsonify, session, send_file

import os
import uuid
import fido2.features
import base64
import pickle
import time
import textwrap
from datetime import datetime, timezone

from typing import Any, Dict, Mapping, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ed448, ec, rsa

# Enable webauthn-json mapping if available (compatible across fido2 versions)
try:
    fido2.features.webauthn_json_mapping.enabled = True
except Exception:
    try:
        fido2.features.webauthn_json.enabled = True
    except Exception:
        pass

app = Flask(__name__, static_url_path="")
app.secret_key = os.urandom(32)  # Used for session.

rp = PublicKeyCredentialRpEntity(name="Demo server", id="localhost")
server = Fido2Server(rp)

# Save credentials next to this server.py file, regardless of CWD.
basepath = os.path.abspath(os.path.dirname(__file__))

def extract_credential_data(cred):
    """Extract AttestedCredentialData from either old or new format"""
    if isinstance(cred, dict):
        # New format - return the credential_data
        return cred['credential_data']
    else:
        # Old format - return as is (it's already AttestedCredentialData)
        return cred

def savekey(name, key):
    name = name + "_credential_data.pkl"
    with open(os.path.join(basepath, name), "wb") as f:
        f.write(pickle.dumps(key))

def readkey(name):
    name = name + "_credential_data.pkl"
    try:
        with open(os.path.join(basepath, name), "rb") as f:
            creds = pickle.loads(f.read())
            return creds
    except Exception:
        return []

def delkey(name):
    name = name + "_credential_data.pkl"
    try:
        os.remove(os.path.join(basepath, name))
    except Exception:
        pass


def _colon_hex(data: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in data)


def _encode_base64url(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_json_safe(value: Any) -> Any:
    """Recursively convert bytes-like WebAuthn option values into JSON-friendly data."""
    if isinstance(value, (bytes, bytearray, memoryview, ByteBuffer)):
        return _encode_base64url(bytes(value))
    if isinstance(value, Mapping):
        return {key: _make_json_safe(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_make_json_safe(item) for item in value]
    return value


def _extract_attestation_details(
    response: Any,
) -> Tuple[
    str,
    Dict[str, Any],
    Optional[str],
    Optional[str],
    Dict[str, Any],
    Optional[Dict[str, Any]],
]:
    """Parse attestation information from a registration response structure."""
    attestation_format = "none"
    attestation_statement: Dict[str, Any] = {}
    attestation_object_b64: Optional[str] = None
    client_data_b64: Optional[str] = None
    client_extension_results: Dict[str, Any] = {}
    attestation_certificate: Optional[Dict[str, Any]] = None

    if not isinstance(response, dict):
        return (
            attestation_format,
            attestation_statement,
            attestation_object_b64,
            client_data_b64,
            client_extension_results,
            attestation_certificate,
        )

    try:
        registration = RegistrationResponse.from_dict(response)
    except Exception as exc:  # pragma: no cover - debugging aid
        print(f"[DEBUG] Failed to parse registration response for attestation: {exc}")
        return (
            attestation_format,
            attestation_statement,
            attestation_object_b64,
            client_data_b64,
            client_extension_results,
            attestation_certificate,
        )

    attestation_object = registration.response.attestation_object
    attestation_format = getattr(attestation_object, "fmt", None) or "none"
    attestation_statement = attestation_object.att_stmt or {}
    attestation_object_b64 = _encode_base64url(bytes(attestation_object))

    if isinstance(attestation_statement, Mapping):
        cert_chain = attestation_statement.get("x5c") or []
        if isinstance(cert_chain, (list, tuple)) and cert_chain:
            try:
                first_cert = cert_chain[0]
                if isinstance(first_cert, str):
                    cert_bytes = base64.b64decode(first_cert)
                else:
                    cert_bytes = bytes(first_cert)
                attestation_certificate = serialize_attestation_certificate(cert_bytes)
            except Exception as cert_error:
                attestation_certificate = {"error": str(cert_error)}

    client_data = registration.response.client_data
    client_data_b64 = getattr(client_data, "b64", None)
    if client_data_b64 is None:
        client_data_b64 = _encode_base64url(bytes(client_data))

    extension_outputs = registration.client_extension_results
    if extension_outputs:
        if isinstance(extension_outputs, dict):
            client_extension_results = extension_outputs
        elif isinstance(extension_outputs, Mapping):
            client_extension_results = dict(extension_outputs)
        else:
            client_extension_results = extension_outputs  # type: ignore[assignment]

    return (
        attestation_format,
        attestation_statement,
        attestation_object_b64,
        client_data_b64,
        client_extension_results,
        attestation_certificate,
    )


def _format_x509_name(name: x509.Name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


def _parse_fido_transport_bitfield(raw_value: bytes):
    if not raw_value:
        return []

    data = raw_value
    if raw_value[0] == 0x03 and len(raw_value) >= 3:
        # BIT STRING tag followed by length and unused bits indicator
        unused_bits = raw_value[2]
        data = raw_value[3: 3 + raw_value[1] - 1]
    else:
        unused_bits = 0

    aggregate = 0
    for byte in data:
        aggregate = (aggregate << 8) | byte

    if unused_bits:
        aggregate >>= unused_bits

    transport_map = [
        (0x01, "USB"),
        (0x02, "NFC"),
        (0x04, "BLE"),
        (0x08, "TEST"),
        (0x10, "INTERNAL"),
        (0x20, "USB-C"),
        (0x40, "LIGHTNING"),
        (0x80, "BT CLASSIC"),
    ]

    transports = [label for mask, label in transport_map if aggregate & mask]
    return transports


def _serialize_public_key_info(public_key):
    info = {
        "type": public_key.__class__.__name__,
        "keySize": getattr(public_key, "key_size", None),
        "subjectPublicKeyInfoBase64": base64.b64encode(
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode("ascii"),
    }

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        info.update(
            {
                "type": "ECC",
                "curve": getattr(public_key.curve, "name", "unknown"),
                "uncompressedPoint": _colon_hex(
                    public_key.public_bytes(
                        encoding=serialization.Encoding.X962,
                        format=serialization.PublicFormat.UncompressedPoint,
                    )
                ),
            }
        )
    elif isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        modulus_hex = f"0x{numbers.n:x}"
        info.update(
            {
                "type": "RSA",
                "publicExponent": numbers.e,
                "modulusHex": modulus_hex,
            }
        )
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        info.update(
            {
                "type": public_key.__class__.__name__,
                "publicKeyHex": _colon_hex(
                    public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
                ),
            }
        )

    return info


def _serialize_extension_value(ext):
    value = ext.value
    if isinstance(value, x509.SubjectKeyIdentifier):
        return {"subjectKeyIdentifier": value.digest.hex()}
    if isinstance(value, x509.AuthorityKeyIdentifier):
        serialized = {}
        if value.key_identifier:
            serialized["keyIdentifier"] = value.key_identifier.hex()
        if value.authority_cert_serial_number is not None:
            serialized["authorityCertSerialNumber"] = str(value.authority_cert_serial_number)
        if value.authority_cert_issuer:
            serialized["authorityCertIssuer"] = [
                _format_x509_name(name) for name in value.authority_cert_issuer
            ]
        return serialized
    if isinstance(value, x509.BasicConstraints):
        return {"ca": value.ca, "pathLength": value.path_length}
    if isinstance(value, x509.UnrecognizedExtension):
        raw_hex = value.value.hex()
        serialized = {"hex": raw_hex}
        if ext.oid.dotted_string == "1.3.6.1.4.1.45724.1.1.4" and len(value.value) == 16:
            serialized["aaguidHex"] = raw_hex
            try:
                serialized["aaguidGuid"] = str(uuid.UUID(hex=raw_hex))
            except ValueError:
                pass
        elif ext.oid.dotted_string == "1.3.6.1.4.1.45724.2.1.1":
            serialized["transports"] = _parse_fido_transport_bitfield(value.value)
        return serialized

    try:
        return str(value)
    except Exception:
        return repr(value)


def _format_structured_value(value, indent: int = 0):
    """Format nested certificate data into readable text lines."""
    indent_str = " " * 4 * indent

    if value is None:
        return []

    if isinstance(value, (str, int, float)):
        return [f"{indent_str}{value}"]

    if isinstance(value, bool):
        return [f"{indent_str}{str(value).lower()}"]

    if isinstance(value, (list, tuple)):
        if not value:
            return []
        lines = []
        for item in value:
            if isinstance(item, (dict, list, tuple)):
                lines.append(f"{indent_str}-")
                lines.extend(_format_structured_value(item, indent + 1))
            else:
                lines.append(f"{indent_str}- {item}")
        return lines

    if isinstance(value, Mapping):
        entries = []
        for key, val in value.items():
            if val in (None, ""):
                continue
            if isinstance(key, str) and "base64" in key.lower():
                continue
            entries.append((key, val))

        if not entries:
            return []

        lines = []
        for key, val in entries:
            if isinstance(val, (dict, list, tuple)):
                lines.append(f"{indent_str}{key}:")
                lines.extend(_format_structured_value(val, indent + 1))
            else:
                lines.append(f"{indent_str}{key}: {val}")
        return lines

    return [f"{indent_str}{value}"]


def serialize_attestation_certificate(cert_bytes: bytes):
    if not cert_bytes:
        return None

    certificate = x509.load_der_x509_certificate(cert_bytes)
    version_number = certificate.version.value + 1
    version_hex = f"0x{certificate.version.value:x}"

    def _isoformat(value: datetime) -> str:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc).isoformat()
        return value.astimezone(timezone.utc).isoformat()

    def _get_cert_datetime(attribute: str) -> datetime:
        utc_attribute = f"{attribute}_utc"
        try:
            return getattr(certificate, utc_attribute)
        except AttributeError:
            return getattr(certificate, attribute)

    not_valid_before = _get_cert_datetime("not_valid_before")
    not_valid_after = _get_cert_datetime("not_valid_after")

    extensions = []
    for ext in certificate.extensions:
        extensions.append(
            {
                "oid": ext.oid.dotted_string,
                "name": getattr(ext.oid, "_name", ext.oid.dotted_string),
                "critical": ext.critical,
                "value": _serialize_extension_value(ext),
            }
        )

    fingerprints = {
        "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "sha1": certificate.fingerprint(hashes.SHA1()).hex(),
        "md5": certificate.fingerprint(hashes.MD5()).hex(),
    }

    der_bytes = certificate.public_bytes(serialization.Encoding.DER)
    der_base64 = base64.b64encode(der_bytes).decode("ascii")
    pem_body = "\n".join(textwrap.wrap(der_base64, 64))
    pem = f"-----BEGIN CERTIFICATE-----\n{pem_body}\n-----END CERTIFICATE-----"

    summary_lines = []

    def _append_line(line: str):
        summary_lines.append(line)

    def _append_blank_line():
        if summary_lines and summary_lines[-1] != "":
            summary_lines.append("")

    _append_line(f"Version: {version_number} ({version_hex})")
    _append_line(
        "Serial Number: "
        f"{certificate.serial_number} (0x{certificate.serial_number:x})"
    )
    signature_algorithm = getattr(
        certificate.signature_algorithm_oid,
        "_name",
        certificate.signature_algorithm_oid.dotted_string,
    )
    _append_line(f"Signature Algorithm: {signature_algorithm}")
    _append_line(f"Issuer: {_format_x509_name(certificate.issuer)}")

    _append_blank_line()
    _append_line("Validity:")
    _append_line(f"    Not Before: {_isoformat(not_valid_before)}")
    _append_line(f"    Not After: {_isoformat(not_valid_after)}")

    _append_blank_line()
    _append_line(f"Subject: {_format_x509_name(certificate.subject)}")

    public_key_info = _serialize_public_key_info(certificate.public_key())
    filtered_public_key_info = {
        key: value
        for key, value in public_key_info.items()
        if not (isinstance(key, str) and "base64" in key.lower())
    }
    if filtered_public_key_info:
        _append_blank_line()
        _append_line("Public Key Info:")
        summary_lines.extend(_format_structured_value(filtered_public_key_info, 1))

    if extensions:
        _append_blank_line()
        _append_line("Extensions:")
        for ext_info in extensions:
            oid = ext_info.get("oid")
            name = ext_info.get("name")
            label = name if name and name != oid else (oid or "Extension")
            if label and oid and label != oid:
                label = f"{label} ({oid})"
            elif not label:
                label = "Extension"
            if ext_info.get("critical"):
                label = f"{label} [critical]"
            _append_line(f"    - {label}")
            summary_lines.extend(
                _format_structured_value(ext_info.get("value"), indent=2)
            )

    if fingerprints:
        _append_blank_line()
        _append_line("Fingerprints:")
        summary_lines.extend(_format_structured_value(fingerprints, 1))

    summary = "\n".join(line for line in summary_lines if line is not None).strip()

    return {
        "version": {
            "display": f"{version_number} ({version_hex})",
            "numeric": version_number,
            "hex": version_hex,
        },
        "serialNumber": {
            "decimal": str(certificate.serial_number),
            "hex": f"0x{certificate.serial_number:x}",
        },
        "signatureAlgorithm": signature_algorithm,
        "issuer": _format_x509_name(certificate.issuer),
        "validity": {
            "notBefore": _isoformat(not_valid_before),
            "notAfter": _isoformat(not_valid_after),
        },
        "subject": _format_x509_name(certificate.subject),
        "publicKeyInfo": public_key_info,
        "extensions": extensions,
        "fingerprints": fingerprints,
        "derBase64": der_base64,
        "pem": pem,
        "summary": summary,
    }

@app.route("/")
def index():
    return redirect("/index.html")

@app.route("/api/register/begin", methods=["POST"])
def register_begin():
    uname = request.args.get("email")
    credentials = readkey(uname)
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

    return jsonify(_make_json_safe(dict(options)))

@app.route("/api/register/complete", methods=["POST"])
def register_complete():
    uname = request.args.get("email")
    credentials = readkey(uname)
    response = request.json or {}
    credential_response = response.get('response', {}) if isinstance(response, dict) else {}

    (
        attestation_format,
        attestation_statement,
        parsed_attestation_object,
        parsed_client_data_json,
        parsed_extension_results,
        attestation_certificate_details,
    ) = _extract_attestation_details(response)

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

    auth_data = server.register_complete(session["state"], response)

    # Store comprehensive credential data (same format as advanced)
    credential_info = {
        'credential_data': auth_data.credential_data,  # AttestedCredentialData
        'auth_data': auth_data,  # Full AuthenticatorData for flags, counter, etc.
        'user_info': {
            'name': uname,
            'display_name': uname,
            'user_handle': uname.encode('utf-8')  # Use username as user_handle for simple registration
        },
        'registration_time': time.time(),
        'client_data_json': client_data_json or '',
        'attestation_object': raw_attestation_object or '',
        'attestation_format': attestation_format,  # Store parsed attestation format
        'attestation_statement': attestation_statement,  # Store attestation statement for details
        'attestation_certificate': attestation_certificate_details,
        'client_extension_outputs': client_extension_results,
        # Store request parameters for simple registration (defaults)
        'request_params': {
            'user_verification': 'discouraged',
            'authenticator_attachment': 'cross-platform',
            'attestation': 'none',
            'resident_key': None,
            'extensions': {},
            'timeout': 90000
        },
        # Properties section - detailed credential information
        'properties': {
            'excludeCredentialsSentCount': 0,  # Simple auth doesn't use exclude credentials
            'excludeCredentialsUsed': False,   # Simple auth doesn't use exclude credentials
            'credentialIdLength': len(auth_data.credential_data.credential_id),
            'fakeCredentialIdLengthRequested': None,  # Simple auth doesn't use fake credentials
            'hintsSent': [],  # Simple auth doesn't use hints
            # Enhanced largeBlob debugging information (simple auth defaults)
            'largeBlobRequested': {},  # Simple auth doesn't use largeBlob
            'largeBlobClientOutput': client_extension_results.get('largeBlob', {}),
            'residentKeyRequested': None,  # Simple auth defaults
            'residentKeyRequired': False  # Simple auth defaults
        }
    }
    
    credentials.append(credential_info)
    # Persist the updated credentials list so authenticate can find it.
    savekey(uname, credentials)

    algo = auth_data.credential_data.public_key[3]
    algoname = ""
    if algo == -49:
        algoname = "ML-DSA-65 (PQC)"
    elif algo == -48:
        algoname = "ML-DSA-44 (PQC)"
    elif algo == -7:
        algoname = "ES256 (ECDSA)"
    elif algo == -257:
        algoname = "RS256 (RSA)"
    else:
        algoname = "Other (Classical)"

    # Extract actual credential information for debug
    debug_info = {
        "attestationFormat": attestation_format,
        "algorithmsUsed": [algo],
        "excludeCredentialsUsed": False,  # Simple auth doesn't use exclude credentials
        "hintsUsed": [],  # Simple auth doesn't use hints
        "credProtectUsed": "none",  # Simple auth doesn't use credProtect
        "enforceCredProtectUsed": False,
        "actualResidentKey": bool(auth_data.flags & 0x04) if hasattr(auth_data, 'flags') else False,  # RK flag from authenticator data
    }

    return jsonify({
        "status": "OK", 
        "algo": algoname,
        **debug_info
    })

@app.route("/api/authenticate/begin", methods=["POST"])
def authenticate_begin():
    uname = request.args.get("email")
    credentials = readkey(uname)
    if not credentials:
        abort(404)

    # Extract credential data in compatible format
    credential_data_list = [extract_credential_data(cred) for cred in credentials]
    
    options, state = server.authenticate_begin(
        credential_data_list,
        user_verification="discouraged"
    )
    session["state"] = state

    return jsonify(_make_json_safe(dict(options)))

@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    uname = request.args.get("email")
    credentials = readkey(uname)
    if not credentials:
        abort(404)

    # Extract credential data in compatible format
    credential_data_list = [extract_credential_data(cred) for cred in credentials]

    response = request.json
    server.authenticate_complete(
        session.pop("state"),
        credential_data_list,
        response,
    )

    # Extract actual authentication information for debug  
    debug_info = {
        "hintsUsed": [],  # Simple auth doesn't use hints
    }

    return jsonify({
        "status": "OK",
        **debug_info
    })

@app.route("/api/deletepub", methods=["POST"])
def deletepub():
    response = request.json
    email = response["email"]
    delkey(email)
    return jsonify({"status": "OK"})

@app.route("/api/downloadcred", methods=["GET"])
def downloadcred():
    name = request.args.get("email")
    name = name + "_credential_data.pkl"
    return send_file(os.path.join(basepath, name), as_attachment=True, download_name=name)

def convert_bytes_for_json(obj):
    """Recursively convert bytes-like objects to base64 strings for JSON serialization."""
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(obj)).decode('utf-8')
    elif isinstance(obj, dict):
        return {k: convert_bytes_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_bytes_for_json(item) for item in obj]
    else:
        return obj

@app.route("/api/credentials", methods=["GET"])
def list_credentials():
    """List all saved credentials from PKL files with comprehensive details"""
    credentials = []
    
    try:
        # Get all .pkl files in the server directory
        pkl_files = [f for f in os.listdir(basepath) if f.endswith('_credential_data.pkl')]
        
        for pkl_file in pkl_files:
            # Extract email from filename
            email = pkl_file.replace('_credential_data.pkl', '')
            
            try:
                # Load credentials for this email
                user_creds = readkey(email)
                for cred in user_creds:
                    try:
                        # Handle both old format (just AttestedCredentialData) and new format (dict with comprehensive data)
                        if isinstance(cred, dict) and 'credential_data' in cred:
                            # New format with comprehensive data
                            if isinstance(cred['credential_data'], dict):
                                # Simple dict format for testing
                                cred_data = cred['credential_data']
                                auth_data = cred['auth_data']
                                user_info = cred['user_info']
                                
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
                                    
                                    # Detailed WebAuthn data
                                    'aaguid': cred_data.get('aaguid').hex() if cred_data.get('aaguid') and isinstance(cred_data.get('aaguid'), bytes) else cred_data.get('aaguid'),
                                    'flags': auth_data.get('flags', {}),
                                    'clientExtensionOutputs': cred.get('client_extension_outputs', {}),
                                    'attestationFormat': cred.get('attestation_format', 'none'),  # Fixed: use attestation_format not attestation_object
                                    'attestationStatement': convert_bytes_for_json(cred.get('attestation_statement', {})),  # Convert bytes for JSON
                                    'publicKeyAlgorithm': cred_data.get('public_key', {}).get(3),
                                    
                                    # Properties
                                    'residentKey': auth_data.get('flags', {}).get('be', False),
                                    'largeBlob': cred.get('client_extension_outputs', {}).get('largeBlob', {}).get('supported', False),
                                    
                                    # Properties section - detailed credential information
                                    'properties': cred.get('properties', {}),
                                }

                                certificate_details = cred.get('attestation_certificate')
                                if certificate_details is not None:
                                    credential_info['attestationCertificate'] = certificate_details
                            else:
                                # New format with real FIDO2 objects
                                cred_data = cred['credential_data']
                                auth_data = cred['auth_data']
                                user_info = cred['user_info']
                                
                                # Extract detailed information
                                # Properties determined from multiple sources for best accuracy
                                # 1. First check credProps extension result (most reliable)
                                rk_from_credprops = cred.get('client_extension_outputs', {}).get('credProps', {}).get('rk', None)
                                
                                # 2. Check request parameters as fallback
                                rk_from_request = cred.get('request_params', {}).get('resident_key') == 'required'
                                
                                # 3. Use credProps if available, otherwise fall back to request params
                                resident_key_status = rk_from_credprops if rk_from_credprops is not None else rk_from_request
                                
                                # Debug resident key detection
                                
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
                                    
                                    # Detailed WebAuthn data
                                    'aaguid': cred_data.aaguid.hex() if hasattr(cred_data, 'aaguid') and cred_data.aaguid else None,
                                    'flags': {
                                        'up': bool(auth_data.flags & auth_data.FLAG.UP) if hasattr(auth_data, 'flags') else True,
                                        'uv': bool(auth_data.flags & auth_data.FLAG.UV) if hasattr(auth_data, 'flags') else True,
                                        'at': bool(auth_data.flags & auth_data.FLAG.AT) if hasattr(auth_data, 'flags') else True,
                                        'ed': bool(auth_data.flags & auth_data.FLAG.ED) if hasattr(auth_data, 'flags') else False,
                                        'be': bool(auth_data.flags & auth_data.FLAG.BE) if hasattr(auth_data, 'flags') else False,
                                        'bs': bool(auth_data.flags & auth_data.FLAG.BS) if hasattr(auth_data, 'flags') else False,
                                    },
                                    'clientExtensionOutputs': cred.get('client_extension_outputs', {}),
                                    'attestationFormat': cred.get('attestation_format', 'none'),  # Use stored attestation format
                                    'attestationStatement': convert_bytes_for_json(cred.get('attestation_statement', {})),  # Include attestation statement with bytes converted
                                    'publicKeyAlgorithm': cred_data.public_key[3] if hasattr(cred_data, 'public_key') and len(cred_data.public_key) > 3 else None,
                                    
                                    # Properties determined from multiple sources for best accuracy
                                    'residentKey': resident_key_status,
                                    'largeBlob': cred.get('client_extension_outputs', {}).get('largeBlob', {}).get('supported', False),
                                    
                                    # Add original request parameters for debugging/verification
                                    'requestParams': cred.get('request_params', {}),
                                    
                                    # Properties section - detailed credential information
                                    'properties': cred.get('properties', {}),
                                }

                                certificate_details = cred.get('attestation_certificate')
                                if certificate_details is not None:
                                    credential_info['attestationCertificate'] = certificate_details
                        else:
                            # Old format (just AttestedCredentialData)
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
                                
                                # Limited data available for old format
                                'aaguid': cred.aaguid.hex() if hasattr(cred, 'aaguid') and cred.aaguid else None,
                                'flags': {
                                    'up': True,  # Default assumptions for old data
                                    'uv': True,
                                    'at': True,
                                    'ed': False,
                                    'be': False,
                                    'bs': False,
                                },
                                'clientExtensionOutputs': {},
                                'attestationFormat': 'none',
                                'attestationStatement': {},  # No attestation statement for old format
                                'publicKeyAlgorithm': cred.public_key[3] if hasattr(cred, 'public_key') and len(cred.public_key) > 3 else None,
                                'residentKey': False,
                                'largeBlob': False,
                                
                                # Properties section - empty for old format
                                'properties': {},
                            }
                            
                        credentials.append(credential_info)
                    except Exception as e:
                        continue
            except Exception as e:
                continue
                
    except Exception as e:
        pass  # Continue if error reading credentials
    
    return jsonify(credentials)

# Advanced Authentication Endpoints
@app.route("/api/advanced/register/begin", methods=["POST"])
def advanced_register_begin():
    """
    Process WebAuthn CredentialCreationOptions JSON directly from the frontend.
    This preserves full extensibility and enables custom extensions.
    """
    data = request.json
    
    # Extract the publicKey object from the WebAuthn-standard JSON
    if not data or not data.get("publicKey"):
        return jsonify({"error": "Invalid request: Missing publicKey in CredentialCreationOptions"}), 400
    
    public_key = data["publicKey"]
    
    # Extract required fields with validation
    if not public_key.get("rp"):
        return jsonify({"error": "Missing required field: rp"}), 400
    if not public_key.get("user"):
        return jsonify({"error": "Missing required field: user"}), 400
    if not public_key.get("challenge"):
        return jsonify({"error": "Missing required field: challenge"}), 400
    
    # Extract user information
    user_info = public_key["user"]
    username = user_info.get("name", "")
    display_name = user_info.get("displayName", username)
    
    if not username:
        return jsonify({"error": "Username is required in user.name"}), 400
    
    # Get existing credentials for exclusion
    credentials = readkey(username)
    
    # Import required WebAuthn classes
    from fido2.webauthn import (
        PublicKeyCredentialUserEntity, 
        AttestationConveyancePreference,
        UserVerificationRequirement,
        AuthenticatorAttachment,
        ResidentKeyRequirement,
        PublicKeyCredentialParameters,
        PublicKeyCredentialType,
        PublicKeyCredentialDescriptor
    )
    from fido2.server import Fido2Server
    import secrets
    
    # Helper function to extract binary values from JSON format
    def extract_binary_value(value):
        if isinstance(value, str):
            return value
        elif isinstance(value, dict):
            if "$hex" in value:
                return bytes.fromhex(value["$hex"])
            elif "$base64" in value:
                return base64.urlsafe_b64decode(value["$base64"] + "==")
            elif "$base64url" in value:
                return base64.urlsafe_b64decode(value["$base64url"] + "==")
        return value
    
    # Process user ID
    user_id_value = user_info.get("id", "")
    if user_id_value:
        try:
            user_id_bytes = extract_binary_value(user_id_value)
            if isinstance(user_id_bytes, str):
                user_id_bytes = bytes.fromhex(user_id_bytes)
        except (ValueError, TypeError) as e:
            return jsonify({"error": f"Invalid user ID format: {e}"}), 400
    else:
        user_id_bytes = username.encode('utf-8')
    
    # Process challenge
    challenge_value = public_key.get("challenge", "")
    challenge_bytes = None
    if challenge_value:
        try:
            challenge_bytes = extract_binary_value(challenge_value)
            if isinstance(challenge_bytes, str):
                challenge_bytes = bytes.fromhex(challenge_bytes)
        except (ValueError, TypeError) as e:
            return jsonify({"error": f"Invalid challenge format: {e}"}), 400
    
    # Create temporary server instance
    temp_server = Fido2Server(rp)
    
    # Process timeout
    timeout = public_key.get("timeout", 90000)
    temp_server.timeout = timeout / 1000.0 if timeout else None
    
    # Process attestation
    attestation = public_key.get("attestation", "none")
    if attestation == "direct":
        temp_server.attestation = AttestationConveyancePreference.DIRECT
    elif attestation == "indirect":
        temp_server.attestation = AttestationConveyancePreference.INDIRECT
    elif attestation == "enterprise":
        temp_server.attestation = AttestationConveyancePreference.ENTERPRISE
    else:
        temp_server.attestation = AttestationConveyancePreference.NONE
    
    # Process pubKeyCredParams (algorithms)
    pub_key_cred_params = public_key.get("pubKeyCredParams", [])
    if pub_key_cred_params:
        allowed_algorithms = []
        for param in pub_key_cred_params:
            if isinstance(param, dict) and param.get("type") == "public-key" and "alg" in param:
                allowed_algorithms.append(
                    PublicKeyCredentialParameters(
                        PublicKeyCredentialType.PUBLIC_KEY,
                        param["alg"]
                    )
                )
        if allowed_algorithms:
            temp_server.allowed_algorithms = allowed_algorithms
    else:
        # Default algorithms
        temp_server.allowed_algorithms = [
            PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7),  # ES256
            PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -257),  # RS256
        ]
    
    # Process authenticatorSelection
    auth_selection = public_key.get("authenticatorSelection", {})
    
    uv_req = UserVerificationRequirement.PREFERRED
    user_verification = auth_selection.get("userVerification", "preferred")
    if user_verification == "required":
        uv_req = UserVerificationRequirement.REQUIRED
    elif user_verification == "discouraged":
        uv_req = UserVerificationRequirement.DISCOURAGED
    
    auth_attachment = None
    authenticator_attachment = auth_selection.get("authenticatorAttachment")
    if authenticator_attachment == "platform":
        auth_attachment = AuthenticatorAttachment.PLATFORM
    elif authenticator_attachment == "cross-platform":
        auth_attachment = AuthenticatorAttachment.CROSS_PLATFORM
    
    rk_req = ResidentKeyRequirement.PREFERRED
    resident_key = auth_selection.get("residentKey", "preferred")
    if auth_selection.get("requireResidentKey") is True:
        rk_req = ResidentKeyRequirement.REQUIRED
    elif resident_key == "required":
        rk_req = ResidentKeyRequirement.REQUIRED
    elif resident_key == "discouraged":
        rk_req = ResidentKeyRequirement.DISCOURAGED
    
    # Create user entity
    user_entity = PublicKeyCredentialUserEntity(
        id=user_id_bytes,
        name=username,
        display_name=display_name,
    )
    
    # Process excludeCredentials
    exclude_list = []
    exclude_credentials = public_key.get("excludeCredentials") if "excludeCredentials" in public_key else None
    if isinstance(exclude_credentials, list):
        for exclude_cred in exclude_credentials:
            if isinstance(exclude_cred, dict) and exclude_cred.get("type") == "public-key":
                cred_id = extract_binary_value(exclude_cred.get("id", ""))
                if isinstance(cred_id, str):
                    cred_id = bytes.fromhex(cred_id)
                if cred_id:
                    exclude_list.append(PublicKeyCredentialDescriptor(
                        type=PublicKeyCredentialType.PUBLIC_KEY,
                        id=cred_id
                    ))
    
    # Process extensions - pass through ALL extensions for full extensibility
    extensions = public_key.get("extensions", {})
    processed_extensions = {}
    
    # Process each extension generically to preserve custom extensions
    for ext_name, ext_value in extensions.items():
        if ext_name == "credProps":
            processed_extensions["credProps"] = bool(ext_value)
        elif ext_name == "minPinLength":
            processed_extensions["minPinLength"] = bool(ext_value)
        elif ext_name in ("credProtect", "credentialProtectionPolicy"):
            if isinstance(ext_value, str):
                protect_map = {
                    "userVerificationOptional": 1,
                    "userVerificationOptionalWithCredentialIDList": 2,
                    "userVerificationOptionalWithCredentialIdList": 2,
                    "userVerificationRequired": 3
                }
                processed_extensions["credProtect"] = protect_map.get(ext_value, ext_value)
            else:
                processed_extensions["credProtect"] = ext_value
        elif ext_name in ("enforceCredProtect", "enforceCredentialProtectionPolicy"):
            processed_extensions["enforceCredProtect"] = bool(ext_value)
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
                        first_value = extract_binary_value(prf_eval["first"])
                        if isinstance(first_value, str):
                            first_value = bytes.fromhex(first_value)
                        processed_eval["first"] = first_value
                    if "second" in prf_eval:
                        second_value = extract_binary_value(prf_eval["second"])
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
            # Pass through any custom extensions as-is for full extensibility
            processed_extensions[ext_name] = ext_value
    
    # Call Fido2Server.register_begin with processed parameters
    options, state = temp_server.register_begin(
        user_entity,
        exclude_list,
        user_verification=uv_req,
        authenticator_attachment=auth_attachment,
        resident_key_requirement=rk_req,
        challenge=challenge_bytes,
        extensions=processed_extensions if processed_extensions else None,
    )
    
    # Debug logging for largeBlob extension
    if "largeBlob" in processed_extensions:
        print(f"[DEBUG] largeBlob extension sent to Fido2Server: {processed_extensions['largeBlob']}")
        options_dict = dict(options)
        if 'extensions' in options_dict.get('publicKey', {}):
            print(f"[DEBUG] largeBlob extension in server response: {options_dict['publicKey'].get('extensions', {}).get('largeBlob')}")
        else:
            print(f"[DEBUG] No extensions in server response")
    
    # Store state and original request for completion
    session["advanced_state"] = state
    session["advanced_original_request"] = data
    
    return jsonify(_make_json_safe(dict(options)))

@app.route("/api/advanced/register/complete", methods=["POST"])
def advanced_register_complete():
    """
    Complete registration using the JSON editor content as primary source with credential response.
    The complete JSON editor content is now sent as the main object structure.
    """
    data = request.json
    
    # Extract credential response from special field
    response = data.get("__credential_response")
    if not response:
        return jsonify({"error": "Credential response is required"}), 400

    credential_response = response.get('response', {}) if isinstance(response, dict) else {}

    # The rest of the data IS the original JSON editor content (primary source of truth)
    original_request = {key: value for key, value in data.items() if not key.startswith("__")}
    
    if not original_request.get("publicKey"):
        return jsonify({"error": "Invalid request: Missing publicKey in JSON editor content"}), 400
    
    # Extract user information from the JSON editor content
    public_key = original_request["publicKey"]
    user_info = public_key.get("user", {})
    username = user_info.get("name", "")
    display_name = user_info.get("displayName", username)
    
    if not username:
        return jsonify({"error": "Username is required in user.name"}), 400
    
    credentials = readkey(username)
    
    auth_selection = public_key.get('authenticatorSelection', {})
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
    ) = _extract_attestation_details(response)

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

    try:
        # Complete registration using stored state
        auth_data = server.register_complete(session.pop("advanced_state"), response)

        # Debug logging for largeBlob extension results
        if 'largeBlob' in client_extension_results:
            print(f"[DEBUG] largeBlob client extension results: {client_extension_results['largeBlob']}")
        else:
            print(f"[DEBUG] No largeBlob extension results in client response")
            
        if hasattr(auth_data, 'extensions'):
            print(f"[DEBUG] Server auth_data extensions: {auth_data.extensions}")
        else:
            print(f"[DEBUG] No extensions in auth_data")
        
        # Helper function to extract binary values
        def extract_binary_value(value):
            if isinstance(value, str):
                return value
            elif isinstance(value, dict):
                if "$hex" in value:
                    return bytes.fromhex(value["$hex"])
                elif "$base64" in value:
                    return base64.urlsafe_b64decode(value["$base64"] + "==")
                elif "$base64url" in value:
                    return base64.urlsafe_b64decode(value["$base64url"] + "==")
            return value
        
        # Determine user handle from JSON editor content
        user_id_value = user_info.get("id", "")
        if user_id_value:
            try:
                user_handle = extract_binary_value(user_id_value)
                if isinstance(user_handle, str):
                    user_handle = bytes.fromhex(user_handle)
            except (ValueError, TypeError):
                user_handle = username.encode('utf-8')
        else:
            user_handle = username.encode('utf-8')
        
        # Store comprehensive credential data
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
            'client_extension_outputs': client_extension_results,
            # Store complete original WebAuthn request for full traceability
            'original_webauthn_request': original_request,
            # Properties section - detailed credential information
            'properties': {
                'excludeCredentialsSentCount': len(public_key.get('excludeCredentials', [])),
                'excludeCredentialsUsed': False,  # Successful registration means exclusion didn't trigger
                'credentialIdLength': len(auth_data.credential_data.credential_id),
                'fakeCredentialIdLengthRequested': None,  # Extract from original request if present
                'hintsSent': public_key.get('hints', []),
                # Enhanced largeBlob debugging information
                'largeBlobRequested': public_key.get('extensions', {}).get('largeBlob', {}),
                'largeBlobClientOutput': client_extension_results.get('largeBlob', {}),
                'residentKeyRequested': resident_key_requested,
                'residentKeyRequired': bool(resident_key_required)
            }
        }

        if attestation_certificate_details is not None:
            credential_info['attestation_certificate'] = attestation_certificate_details

        credentials.append(credential_info)
        savekey(username, credentials)
        
        # Get algorithm info
        algo = auth_data.credential_data.public_key[3]
        algoname = ""
        if algo == -49:
            algoname = "ML-DSA-65 (PQC)"
        elif algo == -48:
            algoname = "ML-DSA-44 (PQC)"
        elif algo == -7:
            algoname = "ES256 (ECDSA)"
        elif algo == -257:
            algoname = "RS256 (RSA)"
        else:
            algoname = "Other (Classical)"
        
        # Extract debug info from processed data and original request
        pub_key_params = public_key.get("pubKeyCredParams", [])
        algorithms_used = [param.get("alg") for param in pub_key_params if isinstance(param, dict) and "alg" in param]
        
        debug_info = {
            "attestationFormat": attestation_format,
            "algorithmsUsed": algorithms_used or [algo],
            "excludeCredentialsUsed": bool(public_key.get("excludeCredentials")),
            "hintsUsed": public_key.get("hints", []),
            "actualResidentKey": bool(auth_data.flags & 0x04) if hasattr(auth_data, 'flags') else False,
        }

        extensions_requested = public_key.get("extensions", {})
        if not isinstance(extensions_requested, dict):
            extensions_requested = {}

        cred_protect_requested = extensions_requested.get("credentialProtectionPolicy")
        if cred_protect_requested is None:
            cred_protect_requested = extensions_requested.get("credProtect")

        cred_protect_mapping = {
            1: "userVerificationOptional",
            2: "userVerificationOptionalWithCredentialIdList",
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
        if getattr(credential_data, 'aaguid', None):
            aaguid_bytes = bytes(credential_data.aaguid)
            aaguid_hex = aaguid_bytes.hex()
            try:
                aaguid_guid = str(uuid.UUID(bytes=aaguid_bytes))
            except ValueError:
                aaguid_guid = None

        flags_dict = {
            "AT": bool(auth_data.flags & auth_data.FLAG.AT),
            "BE": bool(auth_data.flags & auth_data.FLAG.BE),
            "BS": bool(auth_data.flags & auth_data.FLAG.BS),
            "ED": bool(auth_data.flags & auth_data.FLAG.ED),
            "UP": bool(auth_data.flags & auth_data.FLAG.UP),
            "UV": bool(auth_data.flags & auth_data.FLAG.UV),
        }

        authenticator_data_hex = bytes(auth_data).hex()
        registration_timestamp = datetime.fromtimestamp(
            credential_info['registration_time'], timezone.utc
        ).isoformat()

        resident_key_result = None
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
            },
            "residentKey": resident_key_result,
            "userHandle": {
                "base64": base64.b64encode(user_handle).decode('ascii'),
                "base64url": base64.urlsafe_b64encode(user_handle).rstrip(b'=').decode('ascii'),
                "hex": user_handle.hex(),
            },
        }

        if attestation_certificate_details:
            rp_info["attestationCertificate"] = attestation_certificate_details

        return jsonify({
            "status": "OK",
            "algo": algoname,
            **debug_info,
            "relyingParty": rp_info,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/advanced/authenticate/begin", methods=["POST"])
def advanced_authenticate_begin():
    """
    Process WebAuthn CredentialRequestOptions JSON directly from the frontend.
    This preserves full extensibility and enables custom extensions.
    """
    data = request.json
    
    # Extract the publicKey object from the WebAuthn-standard JSON
    if not data or not data.get("publicKey"):
        return jsonify({"error": "Invalid request: Missing publicKey in CredentialRequestOptions"}), 400
    
    public_key = data["publicKey"]
    
    # Extract required fields with validation
    if not public_key.get("challenge"):
        return jsonify({"error": "Missing required field: challenge"}), 400
    
    # Helper function to extract binary values
    def extract_binary_value(value):
        if isinstance(value, str):
            return value
        elif isinstance(value, dict):
            if "$hex" in value:
                return bytes.fromhex(value["$hex"])
            elif "$base64" in value:
                return base64.urlsafe_b64decode(value["$base64"] + "==")
            elif "$base64url" in value:
                return base64.urlsafe_b64decode(value["$base64url"] + "==")
        return value
    
    # Process challenge
    challenge_value = public_key.get("challenge", "")
    challenge_bytes = None
    if challenge_value:
        try:
            challenge_bytes = extract_binary_value(challenge_value)
            if isinstance(challenge_bytes, str):
                challenge_bytes = bytes.fromhex(challenge_bytes)
        except (ValueError, TypeError) as e:
            return jsonify({"error": f"Invalid challenge format: {e}"}), 400
    
    # Import required WebAuthn classes
    from fido2.webauthn import (
        UserVerificationRequirement,
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialType
    )
    from fido2.server import Fido2Server
    import secrets
    
    # Create temporary server instance
    temp_server = Fido2Server(rp)
    
    # Process timeout
    timeout = public_key.get("timeout", 90000)
    temp_server.timeout = timeout / 1000.0 if timeout else None
    
    # Process user verification
    user_verification = public_key.get("userVerification", "preferred")
    uv_req = UserVerificationRequirement.PREFERRED
    if user_verification == "required":
        uv_req = UserVerificationRequirement.REQUIRED
    elif user_verification == "discouraged":
        uv_req = UserVerificationRequirement.DISCOURAGED
    
    # Process allowCredentials
    allow_credentials = public_key.get("allowCredentials", [])
    selected_credentials = None
    
    if not allow_credentials or len(allow_credentials) == 0:
        # Empty allowCredentials for discoverable credentials only
        selected_credentials = None
    else:
        # Process allowCredentials list
        selected_credentials = []
        for allow_cred in allow_credentials:
            if isinstance(allow_cred, dict) and allow_cred.get("type") == "public-key":
                cred_id = extract_binary_value(allow_cred.get("id", ""))
                if isinstance(cred_id, str):
                    cred_id = bytes.fromhex(cred_id)
                if cred_id:
                    selected_credentials.append(PublicKeyCredentialDescriptor(
                        type=PublicKeyCredentialType.PUBLIC_KEY,
                        id=cred_id
                    ))
        
        # If no valid credentials were parsed but allowCredentials was specified,
        # try to match with stored credentials by scanning all users
        if not selected_credentials:
            try:
                pkl_files = [f for f in os.listdir(basepath) if f.endswith('_credential_data.pkl')]
                for pkl_file in pkl_files:
                    email = pkl_file.replace('_credential_data.pkl', '')
                    try:
                        user_creds = readkey(email)
                        credential_data_list = [extract_credential_data(cred) for cred in user_creds]
                        selected_credentials.extend(credential_data_list)
                    except Exception:
                        continue
            except Exception:
                selected_credentials = []
    
    # For non-empty allowCredentials, ensure we have credentials
    if allow_credentials and selected_credentials is not None and len(selected_credentials) == 0:
        return jsonify({"error": "No matching credentials found. Please register first."}), 404
    
    # Process extensions - pass through ALL extensions for full extensibility
    extensions = public_key.get("extensions", {})
    processed_extensions = {}
    
    # Process each extension generically to preserve custom extensions
    for ext_name, ext_value in extensions.items():
        if ext_name == "largeBlob":
            if isinstance(ext_value, dict):
                if ext_value.get("read"):
                    processed_extensions["largeBlob"] = {"read": True}
                elif ext_value.get("write"):
                    write_value = extract_binary_value(ext_value["write"])
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
                    first_value = extract_binary_value(prf_eval["first"])
                    if isinstance(first_value, str):
                        first_value = bytes.fromhex(first_value)
                    processed_eval["first"] = first_value
                if "second" in prf_eval:
                    second_value = extract_binary_value(prf_eval["second"])
                    if isinstance(second_value, str):
                        second_value = bytes.fromhex(second_value)
                    processed_eval["second"] = second_value
                if processed_eval:
                    processed_extensions["prf"] = {"eval": processed_eval}
            else:
                processed_extensions["prf"] = ext_value
        else:
            # Pass through any custom extensions as-is for full extensibility
            processed_extensions[ext_name] = ext_value
    
    # Call Fido2Server.authenticate_begin with processed parameters
    options, state = temp_server.authenticate_begin(
        selected_credentials,
        user_verification=uv_req,
        challenge=challenge_bytes,
        extensions=processed_extensions if processed_extensions else None,
    )
    
    # Store state and original request for completion
    session["advanced_auth_state"] = state
    session["advanced_original_auth_request"] = data
    
    return jsonify(_make_json_safe(dict(options)))

@app.route("/api/advanced/authenticate/complete", methods=["POST"])
def advanced_authenticate_complete():
    """
    Complete authentication using the JSON editor content as primary source with assertion response.
    The complete JSON editor content is now sent as the main object structure.
    """
    data = request.json
    
    # Extract assertion response from special field
    response = data.get("__assertion_response")
    if not response:
        return jsonify({"error": "Assertion response is required"}), 400
    
    # The rest of the data IS the original JSON editor content (primary source of truth)
    original_request = {key: value for key, value in data.items() if not key.startswith("__")}
    
    if not original_request.get("publicKey"):
        return jsonify({"error": "Invalid request: Missing publicKey in JSON editor content"}), 400
    
    # Get all credentials from all users to find the matching one
    all_credentials = []
    try:
        pkl_files = [f for f in os.listdir(basepath) if f.endswith('_credential_data.pkl')]
        for pkl_file in pkl_files:
            email = pkl_file.replace('_credential_data.pkl', '')
            try:
                user_creds = readkey(email)
                credential_data_list = [extract_credential_data(cred) for cred in user_creds]
                all_credentials.extend(credential_data_list)
            except Exception:
                continue
    except Exception:
        pass
        
    if not all_credentials:
        return jsonify({"error": "No credentials found"}), 404
    
    try:
        # Complete authentication using stored state
        auth_result = server.authenticate_complete(
            session.pop("advanced_auth_state"),
            all_credentials,
            response,
        )
        
        # Extract debug information from original request for traceability
        public_key = original_request.get("publicKey", {})
        hints_used = public_key.get("hints", [])
        
        debug_info = {
            "hintsUsed": hints_used,
        }
        
        return jsonify({
            "status": "OK",
            **debug_info
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

def main():
    # Note: using localhost without TLS, as some browsers do
    # not allow Webauthn in case of TLS certificate errors.
    # See https://lists.w3.org/Archives/Public/public-webauthn/2022Nov/0135.html
    app.run(
        host="localhost",
        port=5000,
        ssl_context=("localhost+1.pem", "localhost+1-key.pem"),
        debug=True
    )

if __name__ == "__main__":
    main()