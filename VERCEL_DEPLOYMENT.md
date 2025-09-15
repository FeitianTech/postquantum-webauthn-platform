# WebAuthn FIDO2 Test Application - Vercel Deployment Guide

This repository contains a WebAuthn FIDO2 test application that has been configured for easy deployment to Vercel.

## 🚀 Quick Deployment to Vercel

### Option 1: Deploy from GitHub (Recommended)

1. **Fork this repository** to your GitHub account
2. **Connect to Vercel**:
   - Go to [Vercel Dashboard](https://vercel.com/dashboard)
   - Click "New Project"
   - Import your forked repository
   - Click "Deploy"

### Option 2: Deploy with Vercel CLI

1. **Install Vercel CLI**:
   ```bash
   npm install -g vercel
   ```

2. **Clone and deploy**:
   ```bash
   git clone <your-repo-url>
   cd python-fido2-webauthn-test
   vercel --prod
   ```

## 📁 Project Structure

```
├── api/
│   └── index.py          # Vercel serverless function entry point
├── public/               # Static files (HTML, CSS, JS)
│   ├── index.html
│   ├── script.js
│   ├── styles.css
│   └── webauthn-json.browser-ponyfill.js
├── fido2/               # FIDO2 Python library (included)
├── examples/server/     # Original Flask application
├── vercel.json          # Vercel configuration
├── requirements.txt     # Python dependencies
└── .vercelignore       # Files to exclude from deployment
```

## ⚙️ Configuration

### Environment Variables

The application will use these environment variables if set:

- `SECRET_KEY`: Flask secret key for sessions (auto-generated if not set)
- `CREDENTIAL_STORAGE_PATH`: Path for credential storage (defaults to `/tmp`)

### Vercel Configuration

The `vercel.json` file is pre-configured with:
- Python runtime for the Flask application
- Static file serving from the `public/` directory
- Proper routing for API endpoints
- 30-second function timeout for WebAuthn operations

## 🔧 Features

This deployment maintains all the original WebAuthn FIDO2 test application features:

### ✅ Core WebAuthn Operations
- **Registration**: Create new WebAuthn credentials
- **Authentication**: Authenticate with existing credentials
- **JSON Editor Primary Source**: Complete control over WebAuthn parameters

### ✅ Advanced Features
- **Custom Extensions**: Full support for WebAuthn extensions
- **Binary Format Support**: Multiple encoding formats (`$hex`, `$base64`, `$base64url`)
- **Detailed Credential Properties**: View real credential data and debug information
- **largeBlob Extension Debugging**: Comprehensive debugging for largeBlob issues

### ✅ Developer Features
- **Extensible JSON Editor**: Direct control over WebAuthn requests
- **Debug Information**: Detailed logs and credential analysis
- **Future-Proof**: Automatically supports new WebAuthn features

## 🌐 Domain Configuration

After deployment, your application will be available at:
- `https://your-project-name.vercel.app`

For production use, you may want to:
1. **Configure a custom domain** in your Vercel project settings
2. **Update the Relying Party ID** in the application to match your domain
3. **Set proper HTTPS** (Vercel provides this automatically)

## 📝 Important Notes

### Session Storage
- Sessions are stored in memory and will reset between function invocations
- For production use, consider implementing persistent session storage

### Credential Storage
- Credentials are stored in `/tmp` by default (ephemeral in serverless)
- For production use, consider implementing database storage for credentials

### WebAuthn Requirements
- WebAuthn requires HTTPS in production (Vercel provides this)
- The application is configured to work with `localhost` for development

## 🔍 Testing Your Deployment

After deployment:

1. **Open your Vercel URL** in a WebAuthn-supported browser
2. **Register a credential** using the Registration tab
3. **Test authentication** using the Authentication tab
4. **Try the JSON editor** for advanced WebAuthn operations

## 🛠️ Local Development

To run locally (matching the Vercel environment):

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
cd examples/server
python -m server.server
```

## 📚 Additional Resources

- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [FIDO2 Python Library](https://github.com/Yubico/python-fido2)
- [Vercel Python Documentation](https://vercel.com/docs/functions/serverless-functions/runtimes/python)

## 🤝 Contributing

This application is based on the python-fido2 library. For contributions to the core library, please visit the [official repository](https://github.com/Yubico/python-fido2).

---

**Ready to deploy!** 🎉 Your WebAuthn FIDO2 test application is now fully configured for Vercel deployment.