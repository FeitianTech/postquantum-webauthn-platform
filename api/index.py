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