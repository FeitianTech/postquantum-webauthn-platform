# WebAuthn FIDO2 HTTPS Development Setup

This document explains how to run the WebAuthn FIDO2 test application with HTTPS to access advanced features like attestation and largeBlob extensions.

## The Problem

When using HTTP for WebAuthn development, some features are limited because WebAuthn requires a secure context. While browsers treat `http://localhost` as a secure context for basic WebAuthn functionality, some advanced features like attestation validation and certain extensions may not work properly without true HTTPS.

## Solution Options

### Option 1: Trusted Self-Signed Certificate (Recommended)

This option creates a self-signed certificate that you manually trust in your browser.

1. **Generate the certificate:**
   ```bash
   cd examples/server
   ./generate_cert.sh
   ```

2. **Import the certificate into your browser:**
   
   **Chrome/Edge:**
   - Go to `chrome://settings/certificates`
   - Click 'Authorities' tab
   - Click 'Import' and select `cert.pem`
   - Check 'Trust this certificate for identifying websites'
   
   **Firefox:**
   - Go to `about:preferences#privacy`
   - Scroll to 'Certificates' section
   - Click 'View Certificates'
   - Go to 'Authorities' tab
   - Click 'Import' and select `cert.pem`
   - Check 'Trust this CA to identify websites'
   
   **Safari (macOS):**
   - Double-click `cert.pem` to add to Keychain
   - Open Keychain Access
   - Find the certificate and double-click it
   - Expand 'Trust' section
   - Set 'When using this certificate' to 'Always Trust'

3. **Restart your browser** and visit `https://localhost:5000`

### Option 2: Ignore Certificate Errors (Development Only)

**⚠️ WARNING: Only use this for development! Never use these flags for browsing the internet.**

Start your browser with certificate validation disabled:

**Chrome/Edge:**
```bash
# Linux/macOS
google-chrome --ignore-certificate-errors --ignore-ssl-errors --allow-running-insecure-content

# Windows
chrome.exe --ignore-certificate-errors --ignore-ssl-errors --allow-running-insecure-content
```

**Firefox:**
Set `security.tls.insecure_fallback_hosts` to `localhost` in `about:config`

### Option 3: Use mkcert (Alternative)

If you prefer a more automated approach, you can use [mkcert](https://github.com/FiloSottile/mkcert):

```bash
# Install mkcert (varies by OS)
# macOS: brew install mkcert
# Linux: See mkcert documentation

# Create and install local CA
mkcert -install

# Generate certificate for localhost
mkcert localhost 127.0.0.1 ::1

# Rename files to match the server expectations
mv localhost+2.pem cert.pem
mv localhost+2-key.pem key.pem
```

## Running the Server

After setting up certificates, run the server:

```bash
cd examples/server
python server/server.py
```

Visit `https://localhost:5000` in your browser.

## Verifying the Setup

1. Visit `https://localhost:5000`
2. You should see a secure connection (lock icon in browser)
3. Try registering a WebAuthn credential
4. Advanced features like attestation and extensions should now work properly

## Troubleshooting

**"Security Error" during WebAuthn registration:**
- Ensure your certificate is properly trusted by the browser
- Restart the browser after importing the certificate
- Check browser developer console for specific error messages

**Certificate not trusted:**
- Verify the certificate was imported correctly
- Make sure you selected the right trust options during import
- Try the "ignore certificate errors" option as a temporary workaround

**Still getting HTTP warnings:**
- Ensure you're visiting `https://localhost:5000` (not `http://`)
- Clear browser cache and cookies for localhost

## Why This Matters

With proper HTTPS setup, you can test:
- Full attestation validation
- LargeBlob extension functionality
- Advanced WebAuthn features that require a fully secure context
- Real-world deployment scenarios

## Security Note

These certificates are for development only. Never use self-signed certificates or certificate error bypassing in production environments.