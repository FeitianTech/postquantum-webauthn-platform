"""
Vercel-compatible serverless function handler for WebAuthn FIDO2 test application.
This follows Vercel's Python function convention.
"""

import sys
import os
import json
from urllib.parse import parse_qs, urlparse

# Add the project paths to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
server_dir = os.path.join(project_root, 'examples', 'server')
sys.path.insert(0, project_root)
sys.path.insert(0, server_dir)

# Import Flask and WebAuthn dependencies
from flask import Flask, request as flask_request
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.server import Fido2Server

# Initialize Flask app for serverless
app = Flask(__name__)

def get_host_from_request(request_data):
    """Extract host from Vercel request"""
    headers = request_data.get('headers', {})
    # Try various header names that Vercel might use
    host = (headers.get('x-forwarded-host') or 
            headers.get('host') or 
            headers.get('x-vercel-forwarded-host') or
            'localhost')
    return host.split(':')[0]

def get_rp_entity(host):
    """Create RP entity with dynamic host"""
    return PublicKeyCredentialRpEntity(name="WebAuthn FIDO2 Test App", id=host)

def handler(request):
    """Main Vercel serverless function handler"""
    try:
        # Extract request data
        method = request.get('method', 'GET')
        path = request.get('path', '/')
        query = request.get('query', {})
        headers = request.get('headers', {})
        body = request.get('body', '')
        
        # Get the current host for RP ID
        current_host = get_host_from_request(request)
        
        # Set up Flask application context
        with app.test_request_context(path, method=method, query_string=query, headers=headers, data=body):
            # Import and patch the server module
            import server.server as server_module
            
            # Replace server with dynamic RP
            rp = get_rp_entity(current_host)
            server_module.server = Fido2Server(rp)
            server_module.rp = rp
            
            # Configure app for serverless
            app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vercel-webauthn-secret-key')
            app.secret_key = app.config['SECRET_KEY']
            server_module.basepath = '/tmp'
            
            # Import routes after patching
            from server.server import *
            
            # Process the request
            try:
                response = app.full_dispatch_request()
                
                # Convert Flask response to Vercel format
                return {
                    'statusCode': response.status_code,
                    'headers': dict(response.headers),
                    'body': response.get_data(as_text=True)
                }
            except Exception as e:
                return {
                    'statusCode': 500,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'error': f'Request processing error: {str(e)}'})
                }
                
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': f'Handler error: {str(e)}'})
        }

# For compatibility with different Vercel invocation methods
def main(request):
    """Alternative entry point"""
    return handler(request)

# Export for Vercel
__all__ = ['handler', 'main']