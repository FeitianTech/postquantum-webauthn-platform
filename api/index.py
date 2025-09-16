"""
Vercel serverless function entry point for the WebAuthn FIDO2 test application.
This serves the Flask application from examples/server in a serverless environment.
"""

import sys
import os
import json

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
    from flask import send_from_directory, request, jsonify
    
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
    
    # Add error handlers to ensure JSON responses for API endpoints
    @app.errorhandler(500)
    def internal_server_error(error):
        """Handle 500 errors with JSON response for API endpoints"""
        if request.path.startswith('/api/'):
            import traceback
            return jsonify({
                "error": "Internal server error",
                "path": request.path,
                "method": request.method,
                "message": "The server encountered an internal error",
                "traceback": traceback.format_exc()[-500:] if traceback else None
            }), 500
        return error
    
    # Add health check endpoint specifically for Vercel debugging
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """Health check endpoint for Vercel"""
        try:
            import server.server as server_module
            
            # Check server configuration
            server_info = {
                "server_type": type(server_module.server).__name__,
                "is_production": getattr(server_module, 'is_production', False),
                "basepath": getattr(server_module, 'basepath', 'not set'),
                "vercel_env": os.environ.get('VERCEL', 'false'),
                "current_host": server_module.get_current_host()
            }
            
            if hasattr(server_module.server, 'rp'):
                server_info['rp_id'] = server_module.server.rp.id
                server_info['rp_name'] = server_module.server.rp.name
            
            return jsonify({
                "status": "healthy",
                "server_info": server_info,
                "environment": "vercel" if os.environ.get('VERCEL') else "local"
            })
        except Exception as e:
            import traceback
            return jsonify({
                "status": "unhealthy",
                "error": str(e),
                "traceback": traceback.format_exc()[-500:]
            }), 500

except Exception as e:
    # If there's any import error, create a minimal error handler
    from flask import Flask, jsonify, request
    app = Flask(__name__)
    
    @app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
    def error_handler(path):
        return jsonify({
            "error": f"Import error: {str(e)}",
            "path": path,
            "method": request.method,
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

# Vercel handler function for alternative invocation
def handler(request):
    """Vercel serverless function handler for alternative invocation"""
    try:
        # Extract request details from Vercel format
        method = request.get('method', 'GET')
        path = request.get('path', '/')
        query_string = request.get('query', {})
        headers = request.get('headers', {})
        body = request.get('body', '')
        
        # Convert query parameters to proper format
        query_args = []
        for key, value in query_string.items():
            if isinstance(value, list):
                for v in value:
                    query_args.append(f"{key}={v}")
            else:
                query_args.append(f"{key}={value}")
        query_str = '&'.join(query_args)
        
        # Create Flask test request context
        with app.test_request_context(
            path=path,
            method=method,
            query_string=query_str,
            headers=headers,
            data=body,
            content_type=headers.get('content-type', 'application/json')
        ):
            # Process request through Flask
            response = app.full_dispatch_request()
            
            return {
                'statusCode': response.status_code,
                'headers': {
                    'Content-Type': response.content_type or 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type',
                    **dict(response.headers)
                },
                'body': response.get_data(as_text=True)
            }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'error': f'Handler error: {str(e)}',
                'path': request.get('path', '/'),
                'method': request.get('method', 'GET')
            })
        }

# For Vercel, the app object needs to be available at module level
# This will be the WSGI application