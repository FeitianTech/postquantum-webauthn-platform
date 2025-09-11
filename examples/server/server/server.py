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
    print("\n\n\n\n")
    print(options)
    print("\n\n\n\n")

    return jsonify(dict(options))

@app.route("/api/register/complete", methods=["POST"])
def register_complete():
    uname = request.args.get("email")
    credentials = readkey(uname)
    response = request.json
    print("RegistrationResponse:", response)
    auth_data = server.register_complete(session["state"], response)

    credentials.append(auth_data.credential_data)
    # Persist the updated credentials list so authenticate can find it.
    savekey(uname, credentials)

    print("REGISTERED CREDENTIAL:", auth_data.credential_data)
    print("ALGO", auth_data.credential_data.public_key[3])
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

    return jsonify({"status": "OK", "algo": algoname})

@app.route("/api/authenticate/begin", methods=["POST"])
def authenticate_begin():
    uname = request.args.get("email")
    credentials = readkey(uname)
    if not credentials:
        abort(404)

    options, state = server.authenticate_begin(credentials)
    session["state"] = state

    return jsonify(dict(options))

@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    uname = request.args.get("email")
    credentials = readkey(uname)
    if not credentials:
        abort(404)

    response = request.json
    print("AuthenticationResponse:", response)
    server.authenticate_complete(
        session.pop("state"),
        credentials,
        response,
    )

    print("ASSERTION OK")
    return jsonify({"status": "OK"})

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

@app.route("/api/credentials", methods=["GET"])
def list_credentials():
    """List all saved credentials from PKL files"""
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
                    credential_info = {
                        'email': email,
                        'credentialId': base64.b64encode(cred.credential_id).decode('utf-8'),
                        'userName': getattr(cred, 'user_name', email),
                        'displayName': getattr(cred, 'display_name', email),
                        'algorithm': getattr(cred, 'algorithm', 'Unknown'),
                        'type': 'WebAuthn',
                        'createdAt': getattr(cred, 'created_at', None),
                        'signCount': getattr(cred, 'sign_count', 0)
                    }
                    credentials.append(credential_info)
            except Exception as e:
                print(f"Error reading credentials for {email}: {e}")
                continue
                
    except Exception as e:
        print(f"Error listing credential files: {e}")
    
    return jsonify(credentials)

# Advanced Authentication Endpoints
@app.route("/api/advanced/register/begin", methods=["POST"])
def advanced_register_begin():
    data = request.json
    username = data.get("username")
    display_name = data.get("displayName", username)
    user_id = data.get("userId")  # Custom user ID (hex string)
    attestation = data.get("attestation", "none")
    user_verification = data.get("userVerification", "preferred")
    authenticator_attachment = data.get("authenticatorAttachment")
    resident_key = data.get("residentKey", "preferred")
    exclude_credentials = data.get("excludeCredentials", True)
    fake_cred_length = data.get("fakeCredLength", 0)
    challenge = data.get("challenge")  # Custom challenge (hex string)
    timeout = data.get("timeout", 90000)
    pub_key_cred_params = data.get("pubKeyCredParams", [])
    hints = data.get("hints", [])
    extensions = data.get("extensions", {})
    
    if not username:
        return jsonify({"error": "Username is required"}), 400
    
    credentials = readkey(username)
    
    # Import required classes
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
    from fido2.cose import CoseKey
    from fido2.server import Fido2Server
    import secrets
    
    # Create a temporary server instance with custom settings
    temp_server = Fido2Server(rp)
    
    # Set timeout
    temp_server.timeout = timeout
    
    # Set attestation
    if attestation == "direct":
        temp_server.attestation = AttestationConveyancePreference.DIRECT
    elif attestation == "indirect":
        temp_server.attestation = AttestationConveyancePreference.INDIRECT
    elif attestation == "enterprise":
        temp_server.attestation = AttestationConveyancePreference.ENTERPRISE
    else:
        temp_server.attestation = AttestationConveyancePreference.NONE
    
    # Set allowed algorithms based on pubKeyCredParams
    if pub_key_cred_params:
        algorithm_map = {
            "EdDSA": -8, "ES256": -7, "RS256": -257, "ES384": -35, 
            "ES512": -36, "RS384": -258, "RS512": -259, "RS1": -65535
        }
        temp_server.allowed_algorithms = []
        for param in pub_key_cred_params:
            if param in algorithm_map:
                temp_server.allowed_algorithms.append(
                    PublicKeyCredentialParameters(
                        PublicKeyCredentialType.PUBLIC_KEY, 
                        algorithm_map[param]
                    )
                )
    
    # Convert string values to enum values
    uv_req = None
    if user_verification == "required":
        uv_req = UserVerificationRequirement.REQUIRED
    elif user_verification == "discouraged":
        uv_req = UserVerificationRequirement.DISCOURAGED
    elif user_verification == "preferred":
        uv_req = UserVerificationRequirement.PREFERRED
    
    auth_attachment = None
    if authenticator_attachment == "platform":
        auth_attachment = AuthenticatorAttachment.PLATFORM
    elif authenticator_attachment == "cross-platform":
        auth_attachment = AuthenticatorAttachment.CROSS_PLATFORM
    
    rk_req = None
    if resident_key == "required":
        rk_req = ResidentKeyRequirement.REQUIRED
    elif resident_key == "discouraged":
        rk_req = ResidentKeyRequirement.DISCOURAGED
    elif resident_key == "preferred":
        rk_req = ResidentKeyRequirement.PREFERRED
    
    # Prepare user entity with custom user ID if provided
    if user_id:
        try:
            user_id_bytes = bytes.fromhex(user_id)
        except ValueError:
            return jsonify({"error": "Invalid user ID hex format"}), 400
    else:
        user_id_bytes = username.encode('utf-8')
    
    user_entity = PublicKeyCredentialUserEntity(
        id=user_id_bytes,
        name=username,
        display_name=display_name,
    )
    
    # Prepare exclude list
    exclude_list = []
    if exclude_credentials and credentials:
        exclude_list = credentials
    
    # Add fake credential if requested
    if fake_cred_length > 0:
        fake_cred_id = secrets.token_bytes(fake_cred_length)
        fake_descriptor = PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=fake_cred_id
        )
        exclude_list = list(exclude_list) + [fake_descriptor]
    
    # Parse custom challenge
    challenge_bytes = None
    if challenge:
        try:
            challenge_bytes = bytes.fromhex(challenge)
        except ValueError:
            return jsonify({"error": "Invalid challenge hex format"}), 400
    
    # Process extensions
    processed_extensions = {}
    
    # credProps extension
    if extensions.get("credProps"):
        processed_extensions["credProps"] = True
    
    # minPinLength extension
    if extensions.get("minPinLength"):
        processed_extensions["minPinLength"] = True
    
    # credProtect extension
    cred_protect = extensions.get("credProtect")
    if cred_protect and cred_protect != "unspecified":
        protect_map = {
            "userVerificationOptional": 1,
            "userVerificationOptionalWithCredentialIDList": 2, 
            "userVerificationRequired": 3
        }
        if cred_protect in protect_map:
            processed_extensions["credProtect"] = protect_map[cred_protect]
            if extensions.get("enforceCredProtect"):
                processed_extensions["enforceCredProtect"] = True
    
    # largeBlob extension
    large_blob = extensions.get("largeBlob")
    if large_blob and large_blob != "unspecified":
        if large_blob == "required":
            processed_extensions["largeBlob"] = {"support": "required"}
        elif large_blob == "preferred":
            processed_extensions["largeBlob"] = {"support": "preferred"}
    
    # prf extension
    if extensions.get("prf"):
        prf_ext = {"eval": {}}
        prf_first = extensions.get("prfEvalFirst")
        prf_second = extensions.get("prfEvalSecond")
        
        if prf_first:
            try:
                prf_ext["eval"]["first"] = bytes.fromhex(prf_first)
            except ValueError:
                return jsonify({"error": "Invalid prf eval first hex format"}), 400
        
        if prf_second:
            try:
                prf_ext["eval"]["second"] = bytes.fromhex(prf_second)
            except ValueError:
                return jsonify({"error": "Invalid prf eval second hex format"}), 400
        
        if prf_ext["eval"]:
            processed_extensions["prf"] = prf_ext
    
    options, state = temp_server.register_begin(
        user_entity,
        exclude_list,
        user_verification=uv_req,
        authenticator_attachment=auth_attachment,
        resident_key_requirement=rk_req,
        challenge=challenge_bytes,
        extensions=processed_extensions if processed_extensions else None,
    )
    
    # Store additional data in session for potential use in complete
    session["advanced_state"] = state
    session["advanced_hints"] = hints  # Store hints for potential client processing
    
    return jsonify(dict(options))

@app.route("/api/advanced/register/complete", methods=["POST"])
def advanced_register_complete():
    data = request.json
    username = data.get("username")
    response = data.get("response")
    
    if not username or not response:
        return jsonify({"error": "Username and response are required"}), 400
    
    credentials = readkey(username)
    
    try:
        auth_data = server.register_complete(session.pop("advanced_state"), response)
        credentials.append(auth_data.credential_data)
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
        
        return jsonify({"status": "OK", "algo": algoname})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/advanced/authenticate/begin", methods=["POST"])
def advanced_authenticate_begin():
    data = request.json
    user_verification = data.get("userVerification", "preferred")
    allow_credentials = data.get("allowCredentials", "all")
    specific_credential_id = data.get("specificCredentialId")  # For selecting specific credential
    fake_cred_length = data.get("fakeCredLength", 0)
    challenge = data.get("challenge")  # Custom challenge (hex string)
    timeout = data.get("timeout", 90000)
    extensions = data.get("extensions", {})
    
    # Get credentials based on allowCredentials setting
    selected_credentials = []
    
    if allow_credentials == "empty":
        # Empty allowCredentials for discoverable credentials only
        selected_credentials = None
    elif allow_credentials == "all":
        # Get all credentials from all users
        try:
            pkl_files = [f for f in os.listdir(basepath) if f.endswith('_credential_data.pkl')]
            for pkl_file in pkl_files:
                email = pkl_file.replace('_credential_data.pkl', '')
                try:
                    user_creds = readkey(email)
                    selected_credentials.extend(user_creds)
                except Exception as e:
                    print(f"Error reading credentials for {email}: {e}")
                    continue
        except Exception as e:
            print(f"Error listing credential files: {e}")
            selected_credentials = []
    elif specific_credential_id:
        # Find specific credential by ID
        try:
            cred_id_bytes = base64.b64decode(specific_credential_id)
            pkl_files = [f for f in os.listdir(basepath) if f.endswith('_credential_data.pkl')]
            for pkl_file in pkl_files:
                email = pkl_file.replace('_credential_data.pkl', '')
                try:
                    user_creds = readkey(email)
                    for cred in user_creds:
                        if cred.credential_id == cred_id_bytes:
                            selected_credentials = [cred]
                            break
                    if selected_credentials:
                        break
                except Exception as e:
                    print(f"Error reading credentials for {email}: {e}")
                    continue
        except Exception as e:
            print(f"Error processing specific credential ID: {e}")
            selected_credentials = []
    
    if allow_credentials != "empty" and not selected_credentials:
        return jsonify({"error": "No credentials found. Please register first."}), 404
    
    # Import required classes
    from fido2.webauthn import (
        UserVerificationRequirement,
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialType
    )
    from fido2.server import Fido2Server
    import secrets
    
    # Create temporary server with custom timeout
    temp_server = Fido2Server(rp)
    temp_server.timeout = timeout
    
    # Convert string values to enum values
    uv_req = None
    if user_verification == "required":
        uv_req = UserVerificationRequirement.REQUIRED
    elif user_verification == "discouraged":
        uv_req = UserVerificationRequirement.DISCOURAGED
    elif user_verification == "preferred":
        uv_req = UserVerificationRequirement.PREFERRED
    
    # Prepare credentials list with fake credential if requested
    final_credentials = selected_credentials
    if fake_cred_length > 0 and final_credentials is not None:
        fake_cred_id = secrets.token_bytes(fake_cred_length)
        fake_descriptor = PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=fake_cred_id
        )
        final_credentials = list(final_credentials) + [fake_descriptor]
    
    # Parse custom challenge
    challenge_bytes = None
    if challenge:
        try:
            challenge_bytes = bytes.fromhex(challenge)
        except ValueError:
            return jsonify({"error": "Invalid challenge hex format"}), 400
    
    # Process extensions
    processed_extensions = {}
    
    # largeBlob extension for authentication
    large_blob = extensions.get("largeBlob")
    if large_blob:
        if large_blob == "read":
            processed_extensions["largeBlob"] = {"read": True}
        elif large_blob == "write":
            large_blob_data = extensions.get("largeBlobWrite")
            if large_blob_data:
                try:
                    blob_bytes = bytes.fromhex(large_blob_data)
                    processed_extensions["largeBlob"] = {"write": blob_bytes}
                except ValueError:
                    return jsonify({"error": "Invalid largeBlob write hex format"}), 400
    
    # prf extension for authentication
    if extensions.get("prf"):
        prf_ext = {"eval": {}}
        prf_first = extensions.get("prfEvalFirst")
        prf_second = extensions.get("prfEvalSecond")
        
        if prf_first:
            try:
                prf_ext["eval"]["first"] = bytes.fromhex(prf_first)
            except ValueError:
                return jsonify({"error": "Invalid prf eval first hex format"}), 400
        
        if prf_second:
            try:
                prf_ext["eval"]["second"] = bytes.fromhex(prf_second)
            except ValueError:
                return jsonify({"error": "Invalid prf eval second hex format"}), 400
        
        if prf_ext["eval"]:
            processed_extensions["prf"] = prf_ext
    
    options, state = temp_server.authenticate_begin(
        final_credentials,
        user_verification=uv_req,
        challenge=challenge_bytes,
        extensions=processed_extensions if processed_extensions else None,
    )
    
    session["advanced_auth_state"] = state
    
    return jsonify(dict(options))

@app.route("/api/advanced/authenticate/complete", methods=["POST"])
def advanced_authenticate_complete():
    data = request.json
    response = data.get("response")
    
    if not response:
        return jsonify({"error": "Response is required"}), 400
    
    # Get all credentials from all users to find the matching one
    all_credentials = []
    try:
        pkl_files = [f for f in os.listdir(basepath) if f.endswith('_credential_data.pkl')]
        for pkl_file in pkl_files:
            email = pkl_file.replace('_credential_data.pkl', '')
            try:
                user_creds = readkey(email)
                all_credentials.extend(user_creds)
            except Exception as e:
                print(f"Error reading credentials for {email}: {e}")
                continue
    except Exception as e:
        print(f"Error listing credential files: {e}")
        
    if not all_credentials:
        return jsonify({"error": "No credentials found"}), 404
    
    try:
        server.authenticate_complete(
            session.pop("advanced_auth_state"),
            all_credentials,
            response,
        )
        return jsonify({"status": "OK"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

def main():
    print(__doc__)
    # Note: using localhost without TLS, as some browsers do
    # not allow Webauthn in case of TLS certificate errors.
    # See https://lists.w3.org/Archives/Public/public-webauthn/2022Nov/0135.html
    app.run(host="localhost", debug=False)

if __name__ == "__main__":
    main()