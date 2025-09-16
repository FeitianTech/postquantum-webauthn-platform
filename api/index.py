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
    # First, we need to patch the server module BEFORE importing it
    # to avoid route conflicts
    import server.server as server_module
    from fido2.webauthn import PublicKeyCredentialRpEntity
    from fido2.server import Fido2Server
    from flask import request
    
    # Function to get the correct host for this deployment
    def get_current_host():
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
    
    # Create a dynamic server class that creates the right RP per request
    class VercelFido2Server:
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
    
    # Replace the server variable before importing the rest
    server_module.server = VercelFido2Server()
    
    # Also update the RP
    def get_dynamic_rp():
        current_host = get_current_host()
        return PublicKeyCredentialRpEntity(name="WebAuthn FIDO2 Test App", id=current_host)
    
    server_module.rp = get_dynamic_rp()
    
    # Now import all the functionality with our patched server
    from server.server import *
    from flask import request, jsonify, session, abort, send_from_directory
    import time
    
    # Configure app for Vercel serverless environment  
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vercel-webauthn-secret-key')
    
    # Override the app secret key to ensure session consistency in serverless environment
    app.secret_key = app.config['SECRET_KEY']
    
    # Override the basepath for credential storage
    server_module.basepath = os.environ.get('CREDENTIAL_STORAGE_PATH', '/tmp')
    
    # Override static file serving
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