"""
Vercel serverless function entry point for the WebAuthn FIDO2 test application.
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

from flask import Flask, jsonify, request

# Create app and configure for Vercel
try:
    from server.server import app
    
    # Configure app for Vercel serverless environment  
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vercel-webauthn-secret-key')
    app.secret_key = app.config['SECRET_KEY']
    
    # Override the basepath for credential storage in serverless environment
    import server.server as server_module
    server_module.basepath = '/tmp'
    
    # Add health endpoint for debugging
    @app.route('/api/health')
    def health():
        try:
            server_info = {
                "server_type": type(server_module.server).__name__,
                "is_production": getattr(server_module, 'is_production', False),
                "basepath": getattr(server_module, 'basepath', 'not set'),
                "vercel_env": os.environ.get('VERCEL', 'false')
            }
            return jsonify({
                "status": "ok", 
                "environment": "vercel",
                "server_info": server_info
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "error": str(e),
                "environment": "vercel"
            }), 500
    
    # Add global error handler for API endpoints
    @app.errorhandler(500)
    def handle_500(error):
        if request.path.startswith('/api/'):
            import traceback
            return jsonify({
                "error": "Internal server error",
                "path": request.path,
                "method": request.method,
                "traceback": traceback.format_exc()[-500:]
            }), 500
        return error
    
except Exception as e:
    # Fallback app if import fails
    app = Flask(__name__)
    
    @app.route('/')
    @app.route('/<path:path>')
    def fallback(path=''):
        import traceback
        return jsonify({
            "error": f"Import failed: {str(e)}", 
            "path": path,
            "traceback": traceback.format_exc()[-500:]
        }), 500