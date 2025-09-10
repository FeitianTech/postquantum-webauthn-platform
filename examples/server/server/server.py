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
    return redirect("/app.html")

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

# Advanced Authentication Endpoints
@app.route("/api/advanced/register/begin", methods=["POST"])
def advanced_register_begin():
    data = request.json
    email = data.get("email")
    username = data.get("username", email)
    display_name = data.get("displayName", username)
    attestation = data.get("attestation", "none")
    user_verification = data.get("userVerification", "preferred")
    authenticator_attachment = data.get("authenticatorAttachment")
    resident_key = data.get("residentKey", "preferred")
    
    if not email:
        return jsonify({"error": "Email is required"}), 400
    
    credentials = readkey(email)
    
    # Import required classes
    from fido2.webauthn import (
        PublicKeyCredentialUserEntity, 
        AttestationConveyancePreference,
        UserVerificationRequirement,
        AuthenticatorAttachment,
        ResidentKeyRequirement
    )
    
    # Convert string values to enum values
    uv_req = None
    if user_verification == "required":
        uv_req = UserVerificationRequirement.REQUIRED
    elif user_verification == "discouraged":
        uv_req = UserVerificationRequirement.DISCOURAGED
    else:
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
    else:
        rk_req = ResidentKeyRequirement.PREFERRED
    
    options, state = server.register_begin(
        PublicKeyCredentialUserEntity(
            id=email.encode('utf-8'),
            name=username,
            display_name=display_name,
        ),
        credentials,
        user_verification=uv_req,
        authenticator_attachment=auth_attachment,
        resident_key_requirement=rk_req,
    )
    
    session["advanced_state"] = state
    return jsonify(dict(options))

@app.route("/api/advanced/register/complete", methods=["POST"])
def advanced_register_complete():
    data = request.json
    email = data.get("email")
    response = data.get("response")
    
    if not email or not response:
        return jsonify({"error": "Email and response are required"}), 400
    
    credentials = readkey(email)
    
    try:
        auth_data = server.register_complete(session.pop("advanced_state"), response)
        credentials.append(auth_data.credential_data)
        savekey(email, credentials)
        
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
    email = data.get("email")
    user_verification = data.get("userVerification", "preferred")
    
    if not email:
        return jsonify({"error": "Email is required"}), 400
    
    credentials = readkey(email)
    if not credentials:
        return jsonify({"error": "No credentials found"}), 404
    
    # Import required classes
    from fido2.webauthn import UserVerificationRequirement
    
    uv_req = None
    if user_verification == "required":
        uv_req = UserVerificationRequirement.REQUIRED
    elif user_verification == "discouraged":
        uv_req = UserVerificationRequirement.DISCOURAGED
    else:
        uv_req = UserVerificationRequirement.PREFERRED
    
    options, state = server.authenticate_begin(credentials, user_verification=uv_req)
    session["advanced_auth_state"] = state
    
    return jsonify(dict(options))

@app.route("/api/advanced/authenticate/complete", methods=["POST"])
def advanced_authenticate_complete():
    data = request.json
    email = data.get("email")
    response = data.get("response")
    
    if not email or not response:
        return jsonify({"error": "Email and response are required"}), 400
    
    credentials = readkey(email)
    if not credentials:
        return jsonify({"error": "No credentials found"}), 404
    
    try:
        server.authenticate_complete(
            session.pop("advanced_auth_state"),
            credentials,
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