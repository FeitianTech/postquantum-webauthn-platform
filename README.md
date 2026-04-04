# FIDO2/WebAuthn Test Platform and Developer Tools

[![CI](https://img.shields.io/github/actions/workflow/status/feitiantech/postquantum-webauthn-platform/ci-python.yml?label=CI&logo=github)](https://github.com/feitiantech/postquantum-webauthn-platform/actions/workflows/ci-python.yml)
[![Build](https://img.shields.io/github/actions/workflow/status/feitiantech/postquantum-webauthn-platform/ci-docker.yml?label=Build&logo=docker)](https://github.com/feitiantech/postquantum-webauthn-platform/actions/workflows/ci-docker.yml)
[![Python Test Coverage](https://img.shields.io/badge/Python%20Coverage-88%25-brightgreen?logo=python)](#testing)
[![Frontend Test Coverage](https://img.shields.io/badge/Frontend%20Coverage-64.33%25-yellow?logo=javascript)](#testing)
[![Commit Activity](https://img.shields.io/github/commit-activity/m/feitiantech/postquantum-webauthn-platform?label=Commit%20Activity&logo=github)](https://github.com/feitiantech/postquantum-webauthn-platform/pulse)

**Google Cloud Deployment (Full FIDO MDS):** https://webauthnlab.tech (A few seconds of cold start is expected)

**Server Deployment (Limited FIDO MDS Update):** [webauthndev.ftsafe.com](https://webauthndev.ftsafe.com) (Currently unavailable due to server issues)

This project provides an end-to-end platform for exploring WebAuthn user flows secured by post-quantum cryptography. The hosted demo and local setup instructions help you register authenticators, run authentication processes, and compare PQC signature suites in a realistic WebAuthn environment. A decoder is integrated for decoding attestation objects, WebAuthn CBOR responses, authenticator metadata, and related structures. A FIDO MDS explorer is also included for direct retrieval of authenticator metadata and root certificate verification.

## Local Setup

### Scope

- Uses the same repo `Dockerfile` as deployment.
- Includes the app, the local `fido2/` library copy, prebuilt `liboqs`, and PQC support used in production images.
- Supports ML-DSA 44/65/87 PQC algorithms bundled by the current container build.

### Supported Platforms

- Windows 10/11 (64-bit)
- macOS (Intel or Apple Silicon)

A modern browser with WebAuthn support is required:

- Edge
- Chrome
- Safari
- Firefox

### 1. Prerequisites

- **Git**: https://git-scm.com/
- **Docker Desktop / Docker Engine** with Docker Compose (`docker compose`) available locally

### 2. Clone the Repository

```bash
git clone https://github.com/FeitianTech/postquantum-webauthn-platform.git
cd postquantum-webauthn-platform
```

### 3. Start the Local Stack

```bash
docker compose up -d
```

Open the platform at `http://localhost:8000`.

Because localhost is treated as a secure context by modern browsers, this Docker Compose workflow does not require the older `mkcert` certificate setup.

### 4. Useful Docker Compose Commands

```bash
docker compose logs -f
docker compose down
```

To rebuild after local source changes that affect the image:

```bash
docker compose up -d --build
```

### Flask Session Secret Persistence

The included Compose configuration mounts `./instance` to `/app/instance`, so `session-secret.key` is persisted across restarts automatically. Delete `instance/session-secret.key` if you want to rotate the secret.

## Quickstart

```bash
git clone https://github.com/FeitianTech/postquantum-webauthn-platform.git
cd postquantum-webauthn-platform
docker compose up -d
```

Then open `http://localhost:8000` in your browser.

## Testing

The repository has both Python and frontend test entry points:

```bash
npm install
npm run test:frontend
npm run test:frontend:coverage
npm run test:python
npm run test:python:coverage
```

Frontend tests run with Vitest + jsdom and collect coverage across `frontend/static/**/*.js`, with uncovered modules included in the report output. Coverage reports are written to `coverage/frontend/`.
