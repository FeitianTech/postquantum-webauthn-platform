"""
Alternative Vercel serverless function approach - individual endpoint handlers.
This creates separate functions for each WebAuthn endpoint to avoid routing issues.
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

def handler(request):
    """Main Vercel handler that routes to appropriate Flask endpoints"""
    try:
        # Import Flask components
        from server.server import app
        from flask import Flask
        
        # Configure app for Vercel
        app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vercel-webauthn-secret-key')
        app.secret_key = app.config['SECRET_KEY']
        
        # Override the basepath for credential storage
        import server.server as server_module
        server_module.basepath = '/tmp'
        
        # Extract request details
        method = request.get('httpMethod', request.get('method', 'GET'))
        path = request.get('path', '/')
        query_string = request.get('queryStringParameters') or {}
        headers = request.get('headers', {})
        body = request.get('body', '')
        
        # Convert query string to Flask format
        query_args = []
        for key, value in query_string.items():
            if isinstance(value, list):
                for v in value:
                    query_args.append(f"{key}={v}")
            else:
                query_args.append(f"{key}={value}")
        query_string_formatted = '&'.join(query_args)
        
        # Create Flask test request
        with app.test_request_context(
            path=path,
            method=method,
            query_string=query_string_formatted,
            headers=headers,
            data=body,
            content_type=headers.get('content-type', 'application/json')
        ):
            try:
                # Process the request through Flask
                response = app.full_dispatch_request()
                
                # Convert Flask response to Vercel format
                return {
                    'statusCode': response.status_code,
                    'headers': {
                        'Content-Type': response.content_type,
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                        **dict(response.headers)
                    },
                    'body': response.get_data(as_text=True)
                }
                
            except Exception as e:
                return {
                    'statusCode': 500,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({
                        'error': f'Flask request error: {str(e)}',
                        'method': method,
                        'path': path
                    })
                }
                
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'error': f'Handler error: {str(e)}',
                'request': str(request)[:500]
            })
        }

# Also provide the app for WSGI compatibility
try:
    from server.server import app
    
    # Configure app for Vercel
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vercel-webauthn-secret-key')
    app.secret_key = app.config['SECRET_KEY']
    
    import server.server as server_module
    server_module.basepath = '/tmp'
    
except Exception as e:
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
    def error_handler(path):
        return {
            'error': f'App creation error: {str(e)}',
            'path': path
        }, 500