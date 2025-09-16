"""
Minimal Vercel-compatible WebAuthn FIDO2 implementation
This avoids complex imports and path issues by implementing core functionality directly
"""

from flask import Flask, request, jsonify, session
import os
import json
import base64

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'vercel-webauthn-secret-key')

# Simple credential storage in memory (for demo purposes)
CREDENTIALS = {}

@app.route('/api/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'environment': 'vercel',
        'message': 'Minimal WebAuthn implementation running'
    })

@app.route('/api/credentials')
def credentials():
    """List stored credentials"""
    return jsonify({
        'credentials': list(CREDENTIALS.keys()),
        'count': len(CREDENTIALS)
    })

@app.route('/api/register/begin', methods=['GET', 'POST'])
def register_begin():
    """Begin WebAuthn registration"""
    try:
        # Import fido2 here to avoid path issues
        from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
        from fido2.server import Fido2Server
        import secrets
        
        email = request.args.get('email', 'test@example.com')
        
        # Get host for RP ID
        host = request.headers.get('X-Forwarded-Host') or request.headers.get('Host') or 'localhost'
        if ':' in host:
            host = host.split(':')[0]
        
        # Create RP and server
        rp = PublicKeyCredentialRpEntity(name="WebAuthn FIDO2 Test App", id=host)
        server = Fido2Server(rp)
        
        # Create user
        user = PublicKeyCredentialUserEntity(
            id=email.encode('utf-8'),
            name=email,
            display_name=email
        )
        
        # Get existing credentials for this user
        user_credentials = CREDENTIALS.get(email, [])
        
        # Begin registration
        options, state = server.register_begin(user, user_credentials)
        
        # Store state in session
        session['registration_state'] = state
        session['email'] = email
        
        # Convert options to JSON-serializable format
        pk = options.public_key
        options_dict = {
            "publicKey": {
                "challenge": base64.urlsafe_b64encode(pk.challenge).decode().rstrip('='),
                "rp": {"id": pk.rp.id, "name": pk.rp.name},
                "user": {
                    "id": base64.urlsafe_b64encode(pk.user.id).decode().rstrip('='),
                    "name": pk.user.name,
                    "displayName": pk.user.display_name
                },
                "pubKeyCredParams": [{"type": "public-key", "alg": alg.alg} for alg in pk.pub_key_cred_params],
                "timeout": getattr(pk, 'timeout', 60000),
                "attestation": getattr(pk, 'attestation', 'none')
            }
        }
        
        # Add state token for serverless environments
        import pickle
        state_token = base64.b64encode(pickle.dumps(state)).decode('ascii')
        options_dict["_stateToken"] = state_token
        
        return jsonify(options_dict)
        
    except Exception as e:
        import traceback
        return jsonify({
            'error': f'Registration begin failed: {str(e)}',
            'traceback': traceback.format_exc()[-500:]
        }), 500

@app.route('/api/register/complete', methods=['POST'])
def register_complete():
    """Complete WebAuthn registration"""
    try:
        # Import fido2 here to avoid path issues
        from fido2.webauthn import PublicKeyCredentialRpEntity
        from fido2.server import Fido2Server
        import pickle
        
        email = request.args.get('email') or session.get('email', 'test@example.com')
        response_data = request.json
        
        if not response_data:
            return jsonify({'error': 'No response data provided'}), 400
        
        # Get state from token or session
        state = None
        state_token = response_data.get("_stateToken")
        if state_token:
            try:
                state = pickle.loads(base64.b64decode(state_token.encode('ascii')))
            except Exception:
                pass
        
        if not state and 'registration_state' in session:
            state = session['registration_state']
        
        if not state:
            return jsonify({'error': 'No registration state found'}), 400
        
        # Get host for RP ID
        host = request.headers.get('X-Forwarded-Host') or request.headers.get('Host') or 'localhost'
        if ':' in host:
            host = host.split(':')[0]
        
        # Create RP and server
        rp = PublicKeyCredentialRpEntity(name="WebAuthn FIDO2 Test App", id=host)
        server = Fido2Server(rp)
        
        # Complete registration
        auth_data = server.register_complete(state, response_data)
        
        # Store credential
        if email not in CREDENTIALS:
            CREDENTIALS[email] = []
        
        # Create credential info
        credential_info = {
            'credential_id': base64.b64encode(auth_data.credential_data.credential_id).decode(),
            'public_key': base64.b64encode(auth_data.credential_data.public_key).decode(),
            'sign_count': auth_data.credential_data.sign_count,
            'registered_at': str(auth_data.credential_data)
        }
        
        CREDENTIALS[email].append(credential_info)
        
        # Clear session
        session.pop('registration_state', None)
        
        return jsonify({
            'status': 'ok',
            'message': 'Registration completed successfully',
            'email': email,
            'credential_count': len(CREDENTIALS[email])
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            'error': f'Registration completion failed: {str(e)}',
            'traceback': traceback.format_exc()[-500:]
        }), 500

@app.route('/api/authenticate/begin', methods=['GET', 'POST'])
def authenticate_begin():
    """Begin WebAuthn authentication"""
    try:
        from fido2.webauthn import PublicKeyCredentialRpEntity
        from fido2.server import Fido2Server
        
        email = request.args.get('email', 'test@example.com')
        
        # Get credentials for this user
        user_credentials = CREDENTIALS.get(email, [])
        if not user_credentials:
            return jsonify({'error': 'No credentials found for user'}), 404
        
        # Get host for RP ID
        host = request.headers.get('X-Forwarded-Host') or request.headers.get('Host') or 'localhost'
        if ':' in host:
            host = host.split(':')[0]
        
        # Create RP and server
        rp = PublicKeyCredentialRpEntity(name="WebAuthn FIDO2 Test App", id=host)
        server = Fido2Server(rp)
        
        # Convert stored credentials to proper format
        creds = []
        for cred in user_credentials:
            cred_id = base64.b64decode(cred['credential_id'])
            # Create a minimal credential descriptor
            creds.append({'id': cred_id, 'type': 'public-key'})
        
        # Begin authentication
        options, state = server.authenticate_begin(creds)
        
        # Store state
        session['auth_state'] = state
        session['email'] = email
        
        # Convert to dict and add state token
        options_dict = dict(options)
        
        import pickle
        state_token = base64.b64encode(pickle.dumps(state)).decode('ascii')
        options_dict["_stateToken"] = state_token
        
        return jsonify(options_dict)
        
    except Exception as e:
        import traceback
        return jsonify({
            'error': f'Authentication begin failed: {str(e)}',
            'traceback': traceback.format_exc()[-500:]
        }), 500

@app.route('/api/authenticate/complete', methods=['POST'])
def authenticate_complete():
    """Complete WebAuthn authentication"""
    try:
        from fido2.webauthn import PublicKeyCredentialRpEntity
        from fido2.server import Fido2Server
        import pickle
        
        email = request.args.get('email') or session.get('email', 'test@example.com')
        response_data = request.json
        
        if not response_data:
            return jsonify({'error': 'No response data provided'}), 400
        
        # Get state
        state = None
        state_token = response_data.get("_stateToken")
        if state_token:
            try:
                state = pickle.loads(base64.b64decode(state_token.encode('ascii')))
            except Exception:
                pass
        
        if not state and 'auth_state' in session:
            state = session['auth_state']
        
        if not state:
            return jsonify({'error': 'No authentication state found'}), 400
        
        # Get credentials
        user_credentials = CREDENTIALS.get(email, [])
        if not user_credentials:
            return jsonify({'error': 'No credentials found'}), 404
        
        # Get host for RP ID
        host = request.headers.get('X-Forwarded-Host') or request.headers.get('Host') or 'localhost'
        if ':' in host:
            host = host.split(':')[0]
        
        # Create RP and server
        rp = PublicKeyCredentialRpEntity(name="WebAuthn FIDO2 Test App", id=host)
        server = Fido2Server(rp)
        
        # Convert credentials for authentication
        creds = []
        for cred in user_credentials:
            cred_id = base64.b64decode(cred['credential_id'])
            pub_key = base64.b64decode(cred['public_key'])
            creds.append({
                'credential_id': cred_id,
                'public_key': pub_key,
                'sign_count': cred['sign_count']
            })
        
        # Complete authentication
        server.authenticate_complete(state, creds, response_data)
        
        # Clear session
        session.pop('auth_state', None)
        
        return jsonify({
            'status': 'ok',
            'message': 'Authentication completed successfully',
            'email': email
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            'error': f'Authentication completion failed: {str(e)}',
            'traceback': traceback.format_exc()[-500:]
        }), 500

# Add global error handler
@app.errorhandler(500)
def handle_500(error):
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500

# Add CORS headers
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response