"""
Individual Vercel serverless functions for each WebAuthn endpoint.
This approach creates separate functions to avoid routing conflicts.
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

def register_begin(request):
    """Handle /api/register/begin endpoint"""
    try:
        # Import and configure Flask app
        from server.server import app
        import server.server as server_module
        
        app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vercel-webauthn-secret-key')
        app.secret_key = app.config['SECRET_KEY']
        server_module.basepath = '/tmp'
        
        # Extract email from query parameters
        email = request.get('query', {}).get('email', [''])[0] if isinstance(request.get('query', {}).get('email'), list) else request.get('query', {}).get('email', '')
        
        # Create Flask context and call the endpoint
        with app.test_request_context(f'/api/register/begin?email={email}', method='POST'):
            from server.server import register_begin as flask_register_begin
            response = flask_register_begin()
            
            if hasattr(response, 'get_json'):
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps(response.get_json())
                }
            else:
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps(response)
                }
                
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': f'register_begin error: {str(e)}'})
        }

def register_complete(request):
    """Handle /api/register/complete endpoint"""
    try:
        # Import and configure Flask app
        from server.server import app
        import server.server as server_module
        
        app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vercel-webauthn-secret-key')
        app.secret_key = app.config['SECRET_KEY']
        server_module.basepath = '/tmp'
        
        # Extract email and body data
        email = request.get('query', {}).get('email', [''])[0] if isinstance(request.get('query', {}).get('email'), list) else request.get('query', {}).get('email', '')
        body = request.get('body', '{}')
        if isinstance(body, str):
            body_data = json.loads(body)
        else:
            body_data = body
        
        # Create Flask context and call the endpoint
        with app.test_request_context(
            f'/api/register/complete?email={email}', 
            method='POST',
            json=body_data,
            content_type='application/json'
        ):
            from server.server import register_complete as flask_register_complete
            response = flask_register_complete()
            
            if hasattr(response, 'get_json'):
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps(response.get_json())
                }
            else:
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps(response)
                }
                
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': f'register_complete error: {str(e)}'})
        }

# Export functions
__all__ = ['register_begin', 'register_complete']