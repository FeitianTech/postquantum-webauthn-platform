"""
Modified server.py for containerized deployment with dynamic RP ID support.
This version automatically detects the deployment host and configures WebAuthn accordingly.
"""

import os
from flask import Flask, request
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.server import Fido2Server

def get_current_host():
    """Get the current host from request headers or environment"""
    try:
        # Check if we're in a request context
        if request and hasattr(request, 'headers'):
            # Try various headers that might contain the actual host
            host = (request.headers.get('X-Forwarded-Host') or 
                   request.headers.get('Host') or
                   request.headers.get('X-Original-Host'))
            if host:
                return host.split(':')[0]
    except:
        pass
    
    # Fallback to environment variables
    host = (os.environ.get('VERCEL_URL') or 
           os.environ.get('RAILWAY_STATIC_URL') or
           os.environ.get('HOST') or
           os.environ.get('DOMAIN') or
           'localhost')
    
    # Clean up the host (remove protocol if present)
    if '://' in host:
        host = host.split('://')[1]
    
    return host.split('/')[0]

def create_dynamic_server():
    """Create FIDO2 server with dynamic RP ID"""
    host = get_current_host()
    rp = PublicKeyCredentialRpEntity(name="WebAuthn FIDO2 Test App", id=host)
    return Fido2Server(rp)

# This wrapper will be imported by the original server.py
class DynamicFido2Server:
    """Wrapper that creates the right server instance per request"""
    
    def __init__(self):
        self._cached_server = None
        self._cached_host = None
    
    def _get_server(self):
        current_host = get_current_host()
        if self._cached_server is None or self._cached_host != current_host:
            rp = PublicKeyCredentialRpEntity(name="WebAuthn FIDO2 Test App", id=current_host)
            self._cached_server = Fido2Server(rp)
            self._cached_host = current_host
        return self._cached_server
    
    def __getattr__(self, name):
        return getattr(self._get_server(), name)
    
    @property
    def rp(self):
        return self._get_server().rp