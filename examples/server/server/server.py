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
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.server import Fido2Server
from flask import Flask, request, redirect, abort, jsonify, session, send_file

import os
import fido2.features
import base64
import pickle
import time

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

# Dynamic RP and server configuration for production deployments
def get_current_host():
    """Get the current host from request headers or environment"""
    try:
        # Check if we're in a request context
        if request and hasattr(request, 'headers'):
            # Try various headers that might contain the actual host
            host = (request.headers.get('X-Forwarded-Host') or 
                   request.headers.get('Host') or
                   request.headers.get('X-Original-Host'))
            if host:
                return host.split(':')[0]
    except:
        pass
    
    # Fallback to environment variables or localhost
    host = (os.environ.get('VERCEL_URL') or 
           os.environ.get('RAILWAY_STATIC_URL') or
           os.environ.get('HOST') or
           os.environ.get('DOMAIN') or
           'localhost')
    
    # Clean up the host (remove protocol if present)
    if '://' in host:
        host = host.split('://')[1]
    
    return host.split('/')[0]

# Check if we're in a production environment
is_production = os.environ.get('VERCEL') or os.environ.get('RAILWAY_ENVIRONMENT') or os.environ.get('DOCKER_CONTAINER')

if is_production:
    # Use dynamic server for production
    class DynamicFido2Server:
        def __init__(self):
            self._cached_server = None
            self._cached_host = None
        
        def _get_server(self):
            current_host = get_current_host()
            if self._cached_server is None or self._cached_host != current_host:
                rp = PublicKeyCredentialRpEntity(name="WebAuthn FIDO2 Test App", id=current_host)
                self._cached_server = Fido2Server(rp)
                self._cached_host = current_host
            return self._cached_server
        
        def __getattr__(self, name):
            return getattr(self._get_server(), name)
        
        @property
        def rp(self):
            return self._get_server().rp
    
    server = DynamicFido2Server()
    
    # Dynamic RP for production
    def get_dynamic_rp():
        current_host = get_current_host()
        return PublicKeyCredentialRpEntity(name="WebAuthn FIDO2 Test App", id=current_host)
    
    rp = get_dynamic_rp()
else:
    # Use localhost for development
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

    # For serverless environments, also provide state as a token
    # that can be sent back by the client
    import pickle
    import base64
    try:
        state_token = base64.b64encode(pickle.dumps(state)).decode('ascii')
        options_dict = dict(options)
        options_dict["_stateToken"] = state_token
        return jsonify(options_dict)
    except Exception:
        # Fallback to session-based approach
        return jsonify(dict(options))

@app.route("/api/register/complete", methods=["POST"])
def register_complete():
    uname = request.args.get("email")
    credentials = readkey(uname)
    response = request.json
    
    # Try to get state from various sources (serverless-compatible)
    state = None
    
    # First try: Check if state token is provided in the request
    state_token = response.get("_stateToken") if response else None
    if state_token:
        try:
            import pickle
            import base64
            state = pickle.loads(base64.b64decode(state_token.encode('ascii')))
        except Exception as e:
            return jsonify({
                "error": f"Invalid state token: {str(e)}"
            }), 400
    
    # Second try: Check session (for backward compatibility)
    elif "state" in session:
        state = session["state"]
    
    # If no state found, return error
    if state is None:
        return jsonify({
            "error": "Session state not found. In serverless environments, please ensure the state token from the begin response is included in the request as '_stateToken'."
        }), 400
    
    try:
        auth_data = server.register_complete(state, response)
    except Exception as e:
        return jsonify({
            "error": f"Registration completion failed: {str(e)}"
        }), 400

    # Extract attestation format from attestation object
    attestation_format = "none"  # Default
    attestation_statement = None
    try:
        # First try to get attestation from auth_data if available
        if hasattr(auth_data, 'attestation_object') and auth_data.attestation_object:
            attestation_format = auth_data.attestation_object.fmt
            if hasattr(auth_data.attestation_object, 'att_stmt'):
                attestation_statement = auth_data.attestation_object.att_stmt
        elif response.get('attestationObject'):
            # Fallback: Try to parse attestation object from response
            import cbor2
            import base64
            attestation_object_bytes = base64.b64decode(response['attestationObject'])
            attestation_object = cbor2.loads(attestation_object_bytes)
            attestation_format = attestation_object.get('fmt', 'none')
            attestation_statement = attestation_object.get('attStmt', {})
            
            # Debug print to check what we're getting
            print(f"[DEBUG] Parsed attestation format: {attestation_format}")
            print(f"[DEBUG] Attestation statement keys: {list(attestation_statement.keys()) if attestation_statement else 'None'}")
    except Exception as e:
        print(f"[DEBUG] Attestation parsing error: {e}")
        import traceback
        traceback.print_exc()

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
        'client_data_json': response.get('clientDataJSON', ''),
        'attestation_object': response.get('attestationObject', ''),
        'attestation_format': attestation_format,  # Store parsed attestation format
        'attestation_statement': attestation_statement,  # Store attestation statement for details
        'client_extension_outputs': response.get('clientExtensionResults', {}),
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
            'largeBlobClientOutput': response.get('clientExtensionResults', {}).get('largeBlob', {}),
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

    # For serverless environments, also provide state as a token
    # that can be sent back by the client
    import pickle
    import base64
    try:
        state_token = base64.b64encode(pickle.dumps(state)).decode('ascii')
        options_dict = dict(options)
        options_dict["_stateToken"] = state_token
        return jsonify(options_dict)
    except Exception:
        # Fallback to session-based approach
        return jsonify(dict(options))

@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    uname = request.args.get("email")
    credentials = readkey(uname)
    if not credentials:
        abort(404)

    # Extract credential data in compatible format
    credential_data_list = [extract_credential_data(cred) for cred in credentials]

    response = request.json
    
    # Try to get state from various sources (serverless-compatible)
    state = None
    
    # First try: Check if state token is provided in the request
    state_token = response.get("_stateToken") if response else None
    if state_token:
        try:
            import pickle
            import base64
            state = pickle.loads(base64.b64decode(state_token.encode('ascii')))
        except Exception as e:
            return jsonify({
                "error": f"Invalid state token: {str(e)}"
            }), 400
    
    # Second try: Check session (for backward compatibility)
    elif "state" in session:
        state = session.pop("state")
    
    # If no state found, return error
    if state is None:
        return jsonify({
            "error": "Session state not found. In serverless environments, please ensure the state token from the begin response is included in the request as '_stateToken'."
        }), 400
    
    try:
        server.authenticate_complete(
            state,
            credential_data_list,
            response,
        )
    except Exception as e:
        return jsonify({
            "error": f"Authentication completion failed: {str(e)}"
        }), 400

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
    """Recursively convert bytes objects to base64 strings for JSON serialization"""
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode('utf-8')
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
    if resident_key == "required":
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
    exclude_credentials = public_key.get("excludeCredentials", [])
    if exclude_credentials:
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
    elif credentials:
        # Default exclusion of existing credentials
        exclude_list = [extract_credential_data(cred) for cred in credentials]
    
    # Process extensions - pass through ALL extensions for full extensibility
    extensions = public_key.get("extensions", {})
    processed_extensions = {}
    
    # Process each extension generically to preserve custom extensions
    for ext_name, ext_value in extensions.items():
        if ext_name == "credProps":
            processed_extensions["credProps"] = bool(ext_value)
        elif ext_name == "minPinLength":
            processed_extensions["minPinLength"] = bool(ext_value)
        elif ext_name == "credProtect":
            if isinstance(ext_value, str):
                protect_map = {
                    "userVerificationOptional": 1,
                    "userVerificationOptionalWithCredentialIDList": 2, 
                    "userVerificationRequired": 3
                }
                processed_extensions["credProtect"] = protect_map.get(ext_value, ext_value)
            else:
                processed_extensions["credProtect"] = ext_value
        elif ext_name == "enforceCredProtect":
            processed_extensions["enforceCredProtect"] = bool(ext_value)
        elif ext_name == "largeBlob":
            processed_extensions["largeBlob"] = ext_value
        elif ext_name == "prf":
            # Process PRF extension while preserving custom format
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
    
    # For serverless environments, also provide state as a token
    # that can be sent back by the client
    import pickle
    import base64
    try:
        state_token = base64.b64encode(pickle.dumps(state)).decode('ascii')
        options_dict = dict(options)
        options_dict["_stateToken"] = state_token
        return jsonify(options_dict)
    except Exception:
        # Fallback to session-based approach
        return jsonify(dict(options))

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
    
    # Handle missing session state (common in serverless environments)
    if "advanced_state" not in session:
        return jsonify({
            "error": "Session state not found. In serverless environments, session state may not persist between requests. Please try refreshing the page and starting the registration flow again."
        }), 400
    
    try:
        # Complete registration using stored state
        auth_data = server.register_complete(session.pop("advanced_state"), response)
        
        # Debug logging for largeBlob extension results
        client_extension_results = response.get('clientExtensionResults', {})
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
        
        # Extract attestation information
        attestation_format = "none"
        attestation_statement = None
        
        try:
            if hasattr(auth_data, 'attestation_object') and auth_data.attestation_object:
                attestation_format = auth_data.attestation_object.fmt
                if hasattr(auth_data.attestation_object, 'att_stmt'):
                    attestation_statement = auth_data.attestation_object.att_stmt
            elif response.get('attestationObject'):
                import cbor2
                attestation_object_bytes = base64.b64decode(response['attestationObject'])
                attestation_object = cbor2.loads(attestation_object_bytes)
                attestation_format = attestation_object.get('fmt', 'none')
                attestation_statement = attestation_object.get('attStmt', {})
        except Exception as e:
            print(f"[DEBUG] Advanced - Attestation parsing error: {e}")
        
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
            'client_data_json': response.get('clientDataJSON', ''),
            'attestation_object': response.get('attestationObject', ''),
            'attestation_format': attestation_format,
            'attestation_statement': attestation_statement,
            'client_extension_outputs': response.get('clientExtensionResults', {}),
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
                'largeBlobClientOutput': response.get('clientExtensionResults', {}).get('largeBlob', {}),
                'residentKeyRequested': public_key.get('authenticatorSelection', {}).get('residentKey'),
                'residentKeyRequired': public_key.get('authenticatorSelection', {}).get('residentKey') == 'required'
            }
        }
        
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
        
        return jsonify({
            "status": "OK", 
            "algo": algoname,
            **debug_info
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
    
    # For serverless environments, also provide state as a token
    # that can be sent back by the client
    import pickle
    import base64
    try:
        state_token = base64.b64encode(pickle.dumps(state)).decode('ascii')
        options_dict = dict(options)
        options_dict["_stateToken"] = state_token
        return jsonify(options_dict)
    except Exception:
        # Fallback to session-based approach
        return jsonify(dict(options))

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
    
    # Try to get state from various sources (serverless-compatible)
    state = None
    
    # First try: Check if state token is provided in the request
    state_token = data.get("_stateToken") if data else None
    if state_token:
        try:
            import pickle
            import base64
            state = pickle.loads(base64.b64decode(state_token.encode('ascii')))
        except Exception as e:
            return jsonify({
                "error": f"Invalid state token: {str(e)}"
            }), 400
    
    # Second try: Check session (for backward compatibility)
    elif "advanced_auth_state" in session:
        state = session.pop("advanced_auth_state")
    
    # If no state found, return error
    if state is None:
        return jsonify({
            "error": "Session state not found. In serverless environments, please ensure the state token from the begin response is included in the request as '_stateToken'."
        }), 400
    
    try:
        # Complete authentication using stored state
        auth_result = server.authenticate_complete(
            state,
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
    app.run(host="localhost", debug=False)

if __name__ == "__main__":
    main()