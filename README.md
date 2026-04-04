# FIDO2/WebAuthn Test Platform and Developer Tools

[![CI](https://img.shields.io/github/actions/workflow/status/feitiantech/postquantum-webauthn-platform/ci-python.yml?label=CI\&logo=github)](https://github.com/feitiantech/postquantum-webauthn-platform/actions/workflows/ci-python.yml)
[![Build](https://img.shields.io/github/actions/workflow/status/feitiantech/postquantum-webauthn-platform/ci-docker.yml?label=Build\&logo=docker)](https://github.com/feitiantech/postquantum-webauthn-platform/actions/workflows/ci-docker.yml)
[![Python combined coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Ffeitiantech%2Fpostquantum-webauthn-platform%2Fmain%2F.github%2Fbadges%2Fpython-coverage.json)](#testing)
[![Frontend combined coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Ffeitiantech%2Fpostquantum-webauthn-platform%2Fmain%2F.github%2Fbadges%2Ffrontend-coverage.json)](#testing)

---

## Overview

This project provides an end-to-end platform for testing and exploring WebAuthn user flows with support for Post-Quantum Cryptography algorithms.

A **codec** is integrated for:

* Encoding and decoding attestation objects
* Parsing WebAuthn CBOR responses
* Processing authenticator metadata
* Handling related WebAuthn structures

A **FIDO MDS explorer** is included for:

* Direct retrieval of authenticator metadata
* Root certificate verification

For PQC support, the following algorithms are available:

* **ML-DSA 44**
* **ML-DSA 65**
* **ML-DSA 87**

---

## Deployments

| Environment                 | Description             | URL                                                        |
| --------------------------- | ----------------------- | ---------------------------------------------------------- |
| **Google Cloud Deployment** | Full FIDO MDS Support   | https://webauthnlab.tech                                   |
| **Server Deployment**       | Limited FIDO MDS Update | https://webauthndev.ftsafe.com *(Temporarily Unavailable)* |

---

## Local Setup

### Prerequisites

Ensure the following are available locally:

* **Docker Desktop** or **Docker Engine**
* **Docker Compose** (`docker compose`)
* A modern browser with WebAuthn support (Edge, Chrome, Safari, Firefox, etc.)

---

### Step 1 — Clone the Repository

```bash
git clone https://github.com/FeitianTech/postquantum-webauthn-platform.git
cd postquantum-webauthn-platform
```

---

### Step 2 — Start the Local Stack

Run the following command:

```bash
docker compose up -d
```

---

### Step 3 — Access the Platform

Open the following address in your browser:

```text
http://localhost:8000
```
