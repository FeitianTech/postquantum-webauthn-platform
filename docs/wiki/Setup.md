# Setup

This guide consolidates the steps required to get the demo server running locally with optional post-quantum support.

## Prerequisites

Install Git and Python 3.12 or later with pip on your target workstation. The project supports Windows 10/11 and macOS (Intel or Apple Silicon) when paired with a modern WebAuthn-capable browser such as Edge, Chrome, Safari, or Firefox.【F:README.adoc†L14-L20】【F:README.adoc†L24-L27】

## Clone the Repository

Use Git to fetch the sources and move into the project directory:

```bash
git clone https://github.com/FeitianTech/postquantum-webauthn-platform.git
cd postquantum-webauthn-platform
```

【F:README.adoc†L31-L36】

## Python Environment

Create a virtual environment and install runtime dependencies using either PowerShell on Windows or a shell on macOS. Both workflows upgrade pip and install the `requirements.txt` bundle, with optional PC/SC extras available for smart-card testing.【F:README.adoc†L42-L70】

## Enabling Post-Quantum Cryptography

Activate your virtual environment and install the PQC extras via `pip install "[pqc]"`, then verify that the `oqs` module imports successfully.【F:README.adoc†L72-L92】 Follow the upstream instructions to build `liboqs` for your platform and install the `liboqs-python` bindings so the demo can negotiate ML-DSA algorithms.【F:README.adoc†L95-L151】 After installation, confirm the enabled signature set using `python -c "import oqs; print(oqs.get_version()); print(oqs.get_enabled_sigs())"` and ensure the algorithms you plan to exercise are listed.【F:README.adoc†L153-L167】

## Local HTTPS Certificates

Generate trusted certificates with mkcert so browsers permit WebAuthn requests. Install mkcert using Chocolatey on Windows or Homebrew on macOS, then create a certificate for `demo.ftsafe.demo`. Rename the outputs to `demo.ftsafe.demo.pem` and `demo.ftsafe.demo-key.pem` before launching the server to avoid TLS errors.【F:README.adoc†L171-L215】

## Quickstart Run

Once dependencies and certificates are in place, activate your virtual environment and start the Flask app:

```bash
python server/server/app.py
```

The server binds to `https://demo.ftsafe.demo:5000/` and will open in your browser when you follow the printed link.【F:README.adoc†L218-L247】
