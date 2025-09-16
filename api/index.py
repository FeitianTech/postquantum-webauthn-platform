"""
Vercel serverless function entry point for the WebAuthn FIDO2 test application.
This serves the Flask application from examples/server in a serverless environment.
"""

import sys
import os
import tempfile
from flask import Flask, send_from_directory

# Add the project paths to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
server_dir = os.path.join(project_root, 'examples', 'server')
sys.path.insert(0, project_root)
sys.path.insert(0, server_dir)

# Import all the functionality from the server module
from server.server import *

# Configure app for Vercel serverless environment  
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vercel-webauthn-secret-key')

# Override the app secret key to ensure session consistency in serverless environment
app.secret_key = app.config['SECRET_KEY']

# Fix Relying Party ID for Vercel deployment
# The original server.py hardcodes RP ID to "localhost" which fails in production
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.server import Fido2Server

# Create a wrapper that dynamically determines the RP ID based on the deployment environment
class DynamicFido2Server:
    def __init__(self, fallback_server):
        self.fallback_server = fallback_server
        self._cached_server = None
        self._cached_host = None
    
    def _get_current_host(self):
        """Get current host from environment or request"""
        from flask import request, has_request_context
        
        if has_request_context():
            # Try to get host from Vercel headers
            host = (request.headers.get('X-Forwarded-Host') or 
                   request.headers.get('Host') or 
                   request.headers.get('X-Original-Host'))
            if host:
                return host.split(':')[0]  # Remove port if present
        
        # Fallback to environment variable or localhost
        return os.environ.get('VERCEL_URL', 'localhost').replace('https://', '').replace('http://', '')
    
    def _get_server(self):
        """Get Fido2Server instance with correct RP ID for current request"""
        current_host = self._get_current_host()
        
        if self._cached_server is None or self._cached_host != current_host:
            rp = PublicKeyCredentialRpEntity(name="WebAuthn FIDO2 Test App", id=current_host)
            self._cached_server = Fido2Server(rp)
            self._cached_host = current_host
            
        return self._cached_server
    
    def __getattr__(self, name):
        """Delegate all calls to the dynamic server instance"""
        return getattr(self._get_server(), name)

# Replace the global server variable with our dynamic wrapper
import server.server as server_module
server_module.server = DynamicFido2Server(server_module.server)

# Override the basepath for credential storage to use /tmp in serverless environment
import server.server as server_module
server_module.basepath = os.environ.get('CREDENTIAL_STORAGE_PATH', '/tmp')

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