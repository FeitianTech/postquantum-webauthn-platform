"""
Vercel serverless function entry point for the WebAuthn FIDO2 test application.
This serves the Flask application from examples/server in a serverless environment.
"""

import sys
import os

# Add the project paths to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
server_dir = os.path.join(project_root, 'examples', 'server')
sys.path.insert(0, project_root)
sys.path.insert(0, server_dir)

try:
    # Import all the functionality from the server module
    from server.server import *
    from flask import request, jsonify, session, abort
    import time
    
    # Configure app for Vercel serverless environment  
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vercel-webauthn-secret-key')
    
    # Override the app secret key to ensure session consistency in serverless environment
    app.secret_key = app.config['SECRET_KEY']
    
    # Simple fix: Create a new RP and server with dynamic host detection
    from fido2.webauthn import PublicKeyCredentialRpEntity
    from fido2.server import Fido2Server
    
    # Function to get the correct host
    def get_current_host():
        from flask import request
        try:
            if request and hasattr(request, 'headers'):
                host = (request.headers.get('X-Forwarded-Host') or 
                        request.headers.get('Host'))
                if host:
                    return host.split(':')[0]
        except:
            pass
        
        # Fallback to environment or localhost
        vercel_url = os.environ.get('VERCEL_URL', 'localhost')
        if '://' in vercel_url:
            vercel_url = vercel_url.split('://')[1]
        return vercel_url.split('/')[0]
    
    # Override the endpoints to use dynamic RP
    original_register_begin = globals().get('register_begin')
    original_register_complete = globals().get('register_complete')
    original_authenticate_begin = globals().get('authenticate_begin')
    original_authenticate_complete = globals().get('authenticate_complete')
    
    @app.route("/api/register/begin", methods=["POST"])
    def register_begin_fixed():
        # Create server with correct RP ID for this request
        current_host = get_current_host()
        rp = PublicKeyCredentialRpEntity(name="WebAuthn FIDO2 Test App", id=current_host)
        request_server = Fido2Server(rp)
        
        uname = request.args.get("email")
        credentials = readkey(uname)
        options, state = request_server.register_begin(
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
        return jsonify(dict(options))
    
    @app.route("/api/register/complete", methods=["POST"])
    def register_complete_fixed():
        # Create server with correct RP ID for this request
        current_host = get_current_host()
        rp = PublicKeyCredentialRpEntity(name="WebAuthn FIDO2 Test App", id=current_host)
        request_server = Fido2Server(rp)
        
        uname = request.args.get("email")
        credentials = readkey(uname)
        response = request.json
        auth_data = request_server.register_complete(session["state"], response)
        
        # Rest of the original logic...
        attestation_format = "none"
        attestation_statement = None
        try:
            if hasattr(auth_data, 'attestation_object') and auth_data.attestation_object:
                attestation_format = auth_data.attestation_object.fmt
                if hasattr(auth_data.attestation_object, 'att_stmt'):
                    attestation_statement = auth_data.attestation_object.att_stmt
        except Exception:
            pass
        
        # Store the credential data
        cred_data = {
            'credential_data': auth_data.credential_data,
            'attestation_format': attestation_format,
            'attestation_statement': attestation_statement,
            'timestamp': int(time.time()),
        }
        
        credentials.append(cred_data)
        savekey(uname, credentials)
        
        info = {
            "aaguid": auth_data.credential_data.aaguid.hex() if auth_data.credential_data.aaguid else None,
            "attestation_format": attestation_format,
            "algorithm": auth_data.credential_data.public_key.ALGORITHM,
        }
        
        return jsonify(info)
    
    @app.route("/api/authenticate/begin", methods=["POST"])
    def authenticate_begin_fixed():
        # Create server with correct RP ID for this request
        current_host = get_current_host()
        rp = PublicKeyCredentialRpEntity(name="WebAuthn FIDO2 Test App", id=current_host)
        request_server = Fido2Server(rp)
        
        uname = request.args.get("email")
        credentials = readkey(uname)
        if not credentials:
            abort(404)
        
        # Extract credential data in compatible format
        credential_data_list = [extract_credential_data(cred) for cred in credentials]
        
        options, state = request_server.authenticate_begin(
            credential_data_list,
            user_verification="discouraged"
        )
        session["state"] = state
        
        return jsonify(dict(options))
    
    @app.route("/api/authenticate/complete", methods=["POST"])
    def authenticate_complete_fixed():
        # Create server with correct RP ID for this request
        current_host = get_current_host()
        rp = PublicKeyCredentialRpEntity(name="WebAuthn FIDO2 Test App", id=current_host)
        request_server = Fido2Server(rp)
        
        uname = request.args.get("email")
        credentials = readkey(uname)
        
        # Extract credential data in compatible format
        credential_data_list = [extract_credential_data(cred) for cred in credentials]
        
        response = request.json
        request_server.authenticate_complete(
            session.pop("state"),
            credential_data_list,
            response,
        )
        
        # Extract authentication information for debug  
        debug_info = {
            "hintsUsed": [],  # Simple auth doesn't use hints
        }
        
        return jsonify(debug_info)
    
    # Override the basepath for credential storage
    import server.server as server_module
    server_module.basepath = os.environ.get('CREDENTIAL_STORAGE_PATH', '/tmp')
    
    # Override static file serving
    from flask import send_from_directory
    
    @app.route('/static/<path:filename>')
    def static_files_override(filename):
        """Serve static files from public directory for Vercel"""
        public_dir = os.path.join(project_root, 'public')
        return send_from_directory(public_dir, filename)

except Exception as e:
    # If there's any import error, create a minimal error handler
    from flask import Flask, jsonify
    app = Flask(__name__)
    
    @app.route('/<path:path>')
    def error_handler(path):
        return jsonify({
            "error": f"Import error: {str(e)}",
            "path": path
        }), 500

# For Vercel, the app object needs to be available at module level

# Override static file serving to use the public directory
@app.route('/static/<path:filename>')
def static_files_override(filename):
    """Serve static files from public directory for Vercel"""
    public_dir = os.path.join(project_root, 'public')
    return send_from_directory(public_dir, filename)

# Note: The original index route from server.py is preserved
# No need to override it as it already serves index.html correctly

# For Vercel, the app object needs to be available at module level
# This will be the WSGI application