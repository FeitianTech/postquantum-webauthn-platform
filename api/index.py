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
    
    @app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
    def error_handler(path):
        return jsonify({
            "error": f"Import error: {str(e)}",
            "path": path,
            "method": request.method if 'request' in globals() else 'unknown',
            "sys_path": sys.path[:3]  # Show first 3 paths for debugging
        }), 500

# Add debugging route to understand what's happening
@app.route('/api/debug', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def debug_endpoint():
    """Debug endpoint to understand request handling"""
    from flask import request, jsonify
    return jsonify({
        "method": request.method,
        "path": request.path,
        "args": dict(request.args),
        "headers": dict(request.headers),
        "content_type": request.content_type,
        "data": request.get_data(as_text=True)[:200] if request.get_data() else None,
        "available_routes": [str(rule) for rule in app.url_map.iter_rules()][:10],
        "environment": "vercel" if os.environ.get('VERCEL') else "local"
    })

# Add explicit error handling for common routes
@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 Method Not Allowed errors"""
    from flask import request, jsonify
    return jsonify({
        "error": "Method Not Allowed",
        "method": request.method,
        "path": request.path,
        "allowed_methods": [method for method in ['GET', 'POST', 'PUT', 'DELETE'] if hasattr(error, 'allowed_methods')],
        "message": "This endpoint might not support the requested HTTP method",
        "suggestion": "Try using POST for registration/authentication endpoints"
    }), 405

@app.errorhandler(404)
def not_found(error):
    """Handle 404 Not Found errors"""
    from flask import request, jsonify
    return jsonify({
        "error": "Not Found",
        "method": request.method,
        "path": request.path,
        "message": "The requested endpoint was not found",
        "available_endpoints": [rule.rule for rule in app.url_map.iter_rules() if '/api/' in rule.rule][:10]
    }), 404

# The Flask app is automatically served by Vercel's Python runtime

# For Vercel, the app object needs to be available at module level

# Note: The static file override is already defined above
# The original index route from server.py is preserved
# No need to override it as it already serves index.html correctly

# For Vercel, the app object needs to be available at module level
# This will be the WSGI application