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
    from flask import send_from_directory, jsonify, request
    
    # Configure app for Vercel serverless environment  
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vercel-webauthn-secret-key')
    app.secret_key = app.config['SECRET_KEY']
    
    # Override the basepath for credential storage in serverless environment
    import server.server as server_module
    server_module.basepath = '/tmp'
    
    # Add global error handler to ensure JSON responses for API endpoints
    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 errors with JSON response for API endpoints"""
        import traceback
        if request.path.startswith('/api/'):
            # Get the actual exception details
            tb = traceback.format_exc()
            return jsonify({
                "error": "Internal server error occurred during request processing",
                "path": request.path,
                "method": request.method,
                "message": "Please check the server logs for more details",
                "traceback": tb[-1000:] if tb else None  # Last 1000 chars of traceback
            }), 500
        else:
            # For non-API requests, return default error
            return error
            
    # Add error handler for all exceptions to ensure JSON responses
    @app.errorhandler(Exception)
    def handle_exception(e):
        """Handle all exceptions with JSON response for API endpoints"""
        import traceback
        if request.path.startswith('/api/'):
            tb = traceback.format_exc()
            return jsonify({
                "error": f"Unhandled exception: {str(e)}",
                "path": request.path,
                "method": request.method,
                "exception_type": type(e).__name__,
                "traceback": tb[-1000:] if tb else None
            }), 500
        else:
            # For non-API requests, re-raise the exception
            raise e
            
    # Override Flask's error handling for WebAuthn-specific endpoints
    def wrap_webauthn_endpoint(func):
        """Wrapper to ensure WebAuthn endpoints return JSON errors"""
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                return jsonify({
                    "error": f"WebAuthn operation failed: {str(e)}",
                    "endpoint": request.path,
                    "method": request.method
                }), 500
        wrapper.__name__ = func.__name__
        return wrapper
    
    # Apply wrapper to WebAuthn endpoints after import
    # Also add a safety check to ensure the server has a valid RP ID
    @app.before_request
    def ensure_valid_rp():
        """Ensure the server has a valid RP ID before processing requests"""
        if request.path.startswith('/api/') and request.path not in ['/api/debug', '/api/health']:
            try:
                import server.server as server_module
                
                # For production environments, ensure the server is properly configured
                if getattr(server_module, 'is_production', False):
                    # Get current host for this request
                    current_host = None
                    
                    # Try to get host from request headers
                    if request and hasattr(request, 'headers'):
                        current_host = (request.headers.get('X-Forwarded-Host') or 
                                      request.headers.get('Host') or
                                      request.headers.get('X-Original-Host'))
                        if current_host:
                            current_host = current_host.split(':')[0]
                    
                    # Fallback to environment variables
                    if not current_host:
                        current_host = (os.environ.get('VERCEL_URL') or 
                                      os.environ.get('RAILWAY_STATIC_URL') or
                                      os.environ.get('HOST') or
                                      os.environ.get('DOMAIN') or
                                      'localhost')
                        if '://' in current_host:
                            current_host = current_host.split('://')[1]
                        current_host = current_host.split('/')[0]
                    
                    # Ensure server is configured with the correct RP ID
                    if hasattr(server_module.server, '_cached_host'):
                        if server_module.server._cached_host != current_host:
                            # Force refresh of the server instance with correct host
                            server_module.server._cached_server = None
                            server_module.server._cached_host = None
                    
            except Exception as e:
                # If there's an error in the before_request, log it but don't fail the request
                print(f"Warning: RP ID validation failed: {e}")
                pass
    
    # Override static file serving for Vercel
    @app.route('/static/<path:filename>')
    def static_files_override(filename):
        """Serve static files from public directory for Vercel"""
        public_dir = os.path.join(project_root, 'public')
        return send_from_directory(public_dir, filename)

except Exception as e:
    # If there's any import error, create a minimal error handler
    from flask import Flask, jsonify, request
    app = Flask(__name__)
    
    # Set a secret key even for the error app
    app.secret_key = os.environ.get('SECRET_KEY', 'vercel-webauthn-error-key')
    
    @app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
    def error_handler(path):
        return jsonify({
            "error": f"Import error: {str(e)}",
            "path": path,
            "method": request.method,
            "sys_path": sys.path[:3],  # Show first 3 paths for debugging
            "current_dir": current_dir,
            "project_root": project_root,
            "server_dir": server_dir,
            "vercel_env": os.environ.get('VERCEL', 'false')
        }), 500
        
    @app.route('/api/debug', methods=['GET', 'POST'])
    def debug_error():
        return jsonify({
            "status": "error_mode",
            "import_error": str(e),
            "environment": "vercel" if os.environ.get('VERCEL') else "local"
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
        "environment": "vercel" if os.environ.get('VERCEL') else "local",
        "secret_key_set": bool(app.secret_key),
        "basepath": getattr(server_module, 'basepath', 'not set')
    })

# Add health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for Vercel"""
    try:
        # Test basic functionality
        import server.server as server_module
        
        # Check if we're using the dynamic server
        server_info = {}
        if hasattr(server_module, 'server'):
            server_info['server_type'] = type(server_module.server).__name__
            if hasattr(server_module.server, 'rp'):
                server_info['rp_id'] = server_module.server.rp.id
                server_info['rp_name'] = server_module.server.rp.name
        
        # Check current host detection
        try:
            current_host = server_module.get_current_host()
            server_info['detected_host'] = current_host
        except Exception as e:
            server_info['host_detection_error'] = str(e)
            
        return jsonify({
            "status": "healthy",
            "environment": "vercel" if os.environ.get('VERCEL') else "local",
            "basepath": getattr(server_module, 'basepath', 'not set'),
            "server_available": hasattr(server_module, 'server'),
            "rp_available": hasattr(server_module, 'rp'),
            "server_info": server_info,
            "is_production": getattr(server_module, 'is_production', False)
        })
    except Exception as e:
        import traceback
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "traceback": traceback.format_exc()[-500:]
        }), 500

# Add test endpoint for WebAuthn registration flow
@app.route('/api/test-registration', methods=['POST'])
def test_registration():
    """Test WebAuthn registration flow to help debug issues"""
    try:
        import server.server as server_module
        from fido2.webauthn import PublicKeyCredentialUserEntity
        
        # Test the registration begin flow
        test_user = PublicKeyCredentialUserEntity(
            id=b"test_user_id",
            name="test_user",
            display_name="Test User",
        )
        
        # Try to call register_begin with test user
        options, state = server_module.server.register_begin(
            test_user,
            [],  # No existing credentials
            user_verification="discouraged",
            authenticator_attachment="cross-platform",
        )
        
        return jsonify({
            "status": "success",
            "message": "Registration begin flow working correctly",
            "options_available": bool(options),
            "state_available": bool(state),
            "rp_id": server_module.server.rp.id,
            "rp_name": server_module.server.rp.name,
            "challenge_length": len(options.challenge) if hasattr(options, 'challenge') else 0
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()[-1000:]
        }), 500

# Add test endpoint for file system operations
@app.route('/api/test-filesystem', methods=['GET'])
def test_filesystem():
    """Test file system operations for credential storage"""
    try:
        import server.server as server_module
        import tempfile
        import os
        
        # Test writing to basepath
        basepath = getattr(server_module, 'basepath', '/tmp')
        
        test_results = {
            "basepath": basepath,
            "basepath_exists": os.path.exists(basepath),
            "basepath_writable": os.access(basepath, os.W_OK),
            "tmp_writable": os.access('/tmp', os.W_OK),
        }
        
        # Try to write a test file
        try:
            test_file = os.path.join(basepath, 'test_write.txt')
            with open(test_file, 'w') as f:
                f.write('test')
            test_results["write_test"] = "success"
            
            # Try to read it back
            with open(test_file, 'r') as f:
                content = f.read()
            test_results["read_test"] = "success" if content == 'test' else "failed"
            
            # Clean up
            os.remove(test_file)
            test_results["cleanup_test"] = "success"
            
        except Exception as e:
            test_results["write_test"] = f"failed: {str(e)}"
        
        return jsonify({
            "status": "success",
            "test_results": test_results
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()[-500:]
        }), 500

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
# This will be the WSGI application that Vercel will invoke

# Also add a handler function for serverless compatibility
def handler(request):
    """Vercel serverless function handler (alternative invocation method)"""
    try:
        from flask import request as flask_request
        
        # Extract request data for Vercel format
        method = request.get('httpMethod', request.get('method', 'GET'))
        path = request.get('path', '/')
        query = request.get('queryStringParameters', {}) or {}
        headers = request.get('headers', {})
        body = request.get('body', '')
        
        # Convert query parameters to proper format
        query_string = []
        for key, value in query.items():
            if isinstance(value, list):
                for v in value:
                    query_string.append(f"{key}={v}")
            else:
                query_string.append(f"{key}={value}")
        query_str = '&'.join(query_string)
        
        # Process request through Flask
        with app.test_request_context(
            path=path,
            method=method, 
            query_string=query_str,
            headers=headers,
            data=body,
            content_type=headers.get('content-type', 'application/json')
        ):
            try:
                response = app.full_dispatch_request()
                return {
                    'statusCode': response.status_code,
                    'headers': {
                        'Content-Type': response.content_type,
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
                        'error': f'Flask dispatch error: {str(e)}',
                        'path': path,
                        'method': method
                    })
                }
                
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'error': f'Handler error: {str(e)}',
                'request_keys': list(request.keys()) if isinstance(request, dict) else 'not_dict'
            })
        }

# Make sure app is available at module level for Vercel WSGI
# This is the primary way Vercel will invoke the Flask application