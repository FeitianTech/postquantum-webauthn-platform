# Dependencies Guide

This document explains the dependencies needed for the WebAuthn FIDO2 Test Application.

## Core Dependencies (Required)

### Production Dependencies
These are automatically installed by Vercel from `requirements.txt`:

- **Flask** (>=2.0, <4.0) - Web framework for the application
- **cryptography** (>=2.6, !=35, <45) - Cryptographic operations required by FIDO2
- **werkzeug**, **jinja2**, **blinker**, **itsdangerous**, **click** - Flask ecosystem dependencies

### Local Dependencies
- **fido2** (1.2.1-dev.0) - FIDO2/WebAuthn library included locally in this repository

## Optional Dependencies

### PC/SC Smart Card Support
For physical smart card/FIDO key support (requires system libraries):
```bash
# Install system dependencies first (Linux/macOS)
sudo apt-get install libpcsclite-dev  # Ubuntu/Debian
# or
brew install pcsc-lite  # macOS

# Then install Python package
pip install "fido2[pcsc]"
# or
pip install pyscard>=1.9.0
```

### Post-Quantum Cryptography (PQC)
Experimental support for post-quantum cryptographic algorithms:
```bash
pip install oqs-python pqcrypto
```

## Local Development Setup

### Quick Setup (Recommended)
```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or
.\.venv\Scripts\Activate.ps1  # Windows PowerShell

# Install core dependencies
pip install --upgrade pip
pip install flask fido2

# Verify installation
python -c "import fido2, flask; print('Dependencies OK')"
```

### Poetry Setup (Alternative)
```bash
# Install Poetry if not already installed
pipx install poetry

# Configure Poetry for this project
poetry config virtualenvs.in-project true
poetry env use 3.12  # or your Python version

# Install dependencies
poetry install

# Verify
poetry run python -c "import fido2; print('FIDO2 OK')"
```

## Deployment Dependencies

### Vercel (Production)
Dependencies are automatically installed from `requirements.txt`. No additional configuration needed.

### Local Server
```bash
# Run the development server
python examples/server/server/server.py
```

The server will start on http://localhost:5000

## Troubleshooting

### Missing Flask Error
If you see "No module named 'flask'", install Flask:
```bash
pip install flask
```

### PC/SC Compilation Errors
If pyscard fails to install, you may be missing system libraries. PC/SC support is optional for basic WebAuthn functionality.

### Import Errors
Make sure the project root is in your Python path:
```python
import sys
sys.path.insert(0, '.')
import fido2
```

## Version Compatibility

- **Python**: 3.8+ (3.9+ recommended for Vercel)
- **Flask**: 2.0+ (tested with 3.1.x)
- **Cryptography**: 2.6+ (excludes version 35 due to compatibility issues)
- **Browser**: Modern browsers with WebAuthn support (Chrome, Firefox, Safari, Edge)