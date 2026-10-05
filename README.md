# FIDO2/WebAuthn Test Platform and Developer Tools

[![CI](https://img.shields.io/github/actions/workflow/status/feitiantech/postquantum-webauthn-platform/ci-python.yml?label=CI\&logo=github)](https://github.com/feitiantech/postquantum-webauthn-platform/actions/workflows/ci-python.yml)
[![Build](https://img.shields.io/github/actions/workflow/status/feitiantech/postquantum-webauthn-platform/ci-docker.yml?label=Build\&logo=docker)](https://github.com/feitiantech/postquantum-webauthn-platform/actions/workflows/ci-docker.yml)

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

---

### Step 4 — Load the FIDO Metadata

The MDS explorer is empty until the container has a metadata snapshot. This
downloads the FIDO Alliance's BLOB, verifies it against the pinned trust root and
writes the snapshot into `./instance/mds-snapshot`, which the running server reads
at once and keeps across restarts:

```bash
docker compose exec webauthn python tools/update_mds_snapshot.py
```

Run it again to take a newer BLOB. [docs/MDS_SNAPSHOT.md](docs/MDS_SNAPSHOT.md)
has the whole picture.

---

## License

Copyright 2025-2026 FEITIAN Technologies Co., Ltd., under the [Apache License 2.0](LICENSE).

The Geist font in `web/src/fonts` is under the SIL Open Font License
([OFL.txt](web/src/fonts/OFL.txt)), and the test vectors copied from python-fido2
(`tests/app/python_fido2_vectors.py`) keep its BSD licence there.
