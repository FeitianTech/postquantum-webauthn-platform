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

# Set environment variable to indicate we're in Vercel
os.environ['VERCEL'] = 'true'

try:
    # Import the Flask application
    from server.server import app
    from flask import send_from_directory
    
    # Configure app for Vercel serverless environment  
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vercel-webauthn-secret-key')
    app.secret_key = app.config['SECRET_KEY']
    
    # Override the basepath for credential storage in serverless environment
    import server.server as server_module
    server_module.basepath = '/tmp'
    
    # Override static file serving for Vercel
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
            "path": path,
            "sys_path": sys.path[:3]  # Show first 3 paths for debugging
        }), 500

# The Flask app is automatically served by Vercel's Python runtime

# For Vercel, the app object needs to be available at module level

# Note: The static file override is already defined above
# The original index route from server.py is preserved
# No need to override it as it already serves index.html correctly

# For Vercel, the app object needs to be available at module level
# This will be the WSGI application