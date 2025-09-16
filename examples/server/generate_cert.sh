#!/bin/bash

# Generate self-signed certificate for WebAuthn development with localhost
# This creates a certificate that can be trusted by browsers when manually imported

echo "Generating self-signed certificate for localhost WebAuthn development..."

# Create OpenSSL configuration file
cat > localhost.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Development
L = WebAuthn
O = FIDO2 Test
CN = localhost

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
basicConstraints = CA:false

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate private key and certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout key.pem \
    -out cert.pem \
    -config localhost.conf \
    -extensions v3_req

# Set proper permissions
chmod 600 key.pem
chmod 644 cert.pem

echo "Certificate generated successfully!"
echo ""
echo "Files created:"
echo "  - cert.pem (certificate)"
echo "  - key.pem (private key)"
echo "  - localhost.conf (OpenSSL configuration)"
echo ""
echo "To use this certificate with browsers:"
echo ""
echo "Chrome/Edge:"
echo "  1. Go to chrome://settings/certificates"
echo "  2. Click 'Authorities' tab"
echo "  3. Click 'Import' and select cert.pem"
echo "  4. Check 'Trust this certificate for identifying websites'"
echo ""
echo "Firefox:"
echo "  1. Go to about:preferences#privacy"
echo "  2. Scroll to 'Certificates' section"
echo "  3. Click 'View Certificates'"
echo "  4. Go to 'Authorities' tab"
echo "  5. Click 'Import' and select cert.pem"
echo "  6. Check 'Trust this CA to identify websites'"
echo ""
echo "Safari (macOS):"
echo "  1. Double-click cert.pem to add to Keychain"
echo "  2. Open Keychain Access"
echo "  3. Find the certificate and double-click it"
echo "  4. Expand 'Trust' section"
echo "  5. Set 'When using this certificate' to 'Always Trust'"
echo ""
echo "After importing, restart your browser and visit https://localhost:5000"