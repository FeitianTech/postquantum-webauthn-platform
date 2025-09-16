#!/bin/bash

# Setup script for HTTPS WebAuthn test server
# This script helps you set up SSL certificates for the WebAuthn test application

echo "WebAuthn FIDO2 Test Application - HTTPS Setup"
echo "=============================================="
echo

# Check if mkcert is installed
if ! command -v mkcert &> /dev/null; then
    echo "❌ mkcert is not installed."
    echo
    echo "Please install mkcert first:"
    echo "- macOS: brew install mkcert"
    echo "- Windows: choco install mkcert or scoop install mkcert"
    echo "- Linux: Visit https://github.com/FiloSottile/mkcert#installation"
    echo
    exit 1
fi

echo "✅ mkcert is installed"

# Check if mkcert CA is installed
if ! mkcert -CAROOT &> /dev/null; then
    echo "📋 Installing mkcert CA..."
    mkcert -install
    echo "✅ mkcert CA installed"
else
    echo "✅ mkcert CA already installed"
fi

# Generate certificates
echo "📋 Generating SSL certificates..."
cd examples/server/server/

if mkcert localhost 127.0.0.1 ::1; then
    echo "✅ SSL certificates generated successfully"
    echo
    echo "🚀 You can now start the HTTPS server:"
    echo "   python server.py"
    echo
    echo "   Then open: https://127.0.0.1:5000"
    echo
    echo "💡 For HTTP mode (limited features): python server.py --http"
else
    echo "❌ Failed to generate SSL certificates"
    exit 1
fi