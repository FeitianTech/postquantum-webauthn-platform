# PostQuantum WebAuthn Platform — Project Wiki

> A complete reference and developer guide for the **PostQuantum WebAuthn Test Platform**, integrating PQC algorithms via liboqs and python-fido2.

---

<style>
  .nav-buttons {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 0.6rem;
    margin: 0 auto 1.25rem;
    max-width: 960px;
  }

  .nav-button {
    border: 1px solid #2b6cb0;
    border-radius: 999px;
    color: #2b6cb0;
    font-weight: 600;
    padding: 0.5rem 1.1rem;
    text-decoration: none;
    background: linear-gradient(135deg, rgba(43,108,176,0.12), rgba(66,153,225,0.08));
    transition: transform 0.15s ease, box-shadow 0.15s ease;
    box-shadow: 0 2px 6px rgba(43,108,176,0.15);
  }

  .nav-button:hover,
  .nav-button:focus {
    transform: translateY(-1px);
    box-shadow: 0 6px 12px rgba(43,108,176,0.25);
  }
</style>

<div class="nav-buttons">
  <a class="nav-button" href="#-overview">Overview</a>
  <a class="nav-button" href="#-key-features">Key Features</a>
  <a class="nav-button" href="#-architecture">Architecture</a>
  <a class="nav-button" href="#-repository-layout">Repository Layout</a>
  <a class="nav-button" href="#-prerequisites">Prerequisites</a>
  <a class="nav-button" href="#-webauthn-flow">WebAuthn Flow</a>
  <a class="nav-button" href="#-pqc-verification-logic">PQC Verification Logic</a>
  <a class="nav-button" href="#-fido-mds--metadata-handling">FIDO MDS</a>
  <a class="nav-button" href="#-testing">Testing</a>
  <a class="nav-button" href="#-cicd">CI/CD</a>
</div>

---

## 📘 Overview

The **PostQuantum WebAuthn Platform** is a full-stack demonstration and testing framework designed to extend FIDO2/WebAuthn with **Post-Quantum Cryptography (PQC)**. It focuses on end-to-end flows (registration, authentication, attestation) that use PQ signature algorithms such as ML-DSA, powered by the [liboqs](https://openquantumsafe.org) library.

Developed in Python using **Flask** and **python-fido2**, it enables developers, researchers, and hardware teams to validate PQ-enabled authenticators, certificate chains, and attestation logic in preparation for a post-quantum future.

---

## 🧩 Key Features

* 🔐 **Post-Quantum Signature Verification** using liboqs (ML-DSA-44/65/87)
* 🧠 **PQ Certificate Parsing & Chain Validation** implemented in `server/server/pqc.py`
* 🧾 **WebAuthn Registration & Authentication** demo endpoints served from `server/server/routes/`
* 🗄️ **FIDO MDS (Metadata Service)** downloader, verifier, and local cache utilities in `server/server/metadata.py`
* 🧰 **Configurable Environment** via `.env` variables, `render.yaml`, and `server/server/config.py`
* 🔄 **CI/CD Pipeline** (syntax check, pytest, Docker build, Dependabot auto-merge)
* 🧪 **Customizable Trust Policy** for PQ attestation, including metadata bootstrap helpers

---

## 🏗️ Architecture

```text
Browser (WebAuthn API)
   │
   └──▶ Flask Relying Party Server
           ├── python-fido2 (CTAP/WebAuthn logic overrides)
           ├── liboqs (PQC signature backend)
           ├── PQ Certificate Verifier (server/server/pqc.py)
           ├── FIDO MDS Updater & Cache (server/server/metadata.py)
           ├── Decoder utilities (server/server/decoder/)
           └── Persistent storage hooks (server/server/storage.py)
```

---

## 📁 Repository Layout

```
postquantum-webauthn-platform/
├── COPYING*                 # Licensing references (APL, MPL, etc.)
├── README.adoc              # Public getting-started guide
├── docs/
│   └── wiki/                # Internal wiki (this page)
├── fido2/                   # Vendored python-fido2 with PQC extensions
├── prebuilt_liboqs/         # Optional precompiled liboqs bundles
├── requirements.txt         # Runtime dependencies for local venvs
├── server/
│   ├── poetry.lock
│   ├── pyproject.toml
│   └── server/
│       ├── __init__.py
│       ├── app.py           # Flask entry point (TLS enabled)
│       ├── attachments.py   # Binary helpers for attestation artifacts
│       ├── attestation.py   # Higher-level attestation helpers
│       ├── config.py        # Application factory & configuration
│       ├── metadata.py      # Metadata service caching utilities
│       ├── pqc.py           # PQ certificate & signature verification
│       ├── routes/          # simple, general, advanced demo flows
│       ├── decoder/         # CBOR/WebAuthn decoding helpers
│       ├── static/          # Front-end assets (JS/CSS)
│       └── storage.py       # In-memory credential persistence
├── tests/                   # Pytest suites for PQ + WebAuthn flows
├── .github/
│   ├── CODEOWNERS
│   ├── dependabot.yml
│   └── workflows/
│       └── ci.yml           # CI pipeline entrypoint
├── Dockerfile               # Multi-stage container build
├── render.yaml              # Render deployment descriptor & cron job
└── pyproject.toml           # Root dev tooling configuration
```

---

## ⚙️ Prerequisites

| Component | Version / Notes | Details |
| --------- | ---------------- | ------- |
| Python    | 3.11 – 3.12      | Required for the Flask relying party and tests |
| liboqs    | Latest mainline  | Use bundled binaries (Linux) or build from source |
| liboqs-python (`oqs`) | Matches liboqs ABI | Provides ML-DSA bindings consumed by `server/server/pqc.py` |
| mkcert    | Latest           | Generates the `demo.ftsafe.demo` TLS cert for localhost |
| Docker    | Optional         | For container builds and deployment |
| pytest    | ≥7.0             | Executes regression suites under `tests/` |
| Poetry    | Optional         | Alternative dependency management for the server package |

---

## 🔏 WebAuthn Flow

### Registration

1. `/register/options` → Generates challenge via `routes.simple`
2. Client → `navigator.credentials.create()` executed by demo front-end assets in `server/server/static/`
3. `/register/verify` → Validates attestation:
   * Parses `clientDataJSON` & `attestationObject`
   * Verifies PQ certificate chain with `liboqs`
   * Confirms root trust via metadata or local list
   * Stores credential using `storage.py`

### Authentication

1. `/authenticate/options` → Issues challenge
2. Client → `navigator.credentials.get()`
3. `/authenticate/verify` → Checks PQ signature & updates `signCount`

Advanced flows under `routes.advanced` demonstrate attestation object decoding, authenticator metadata inspection, and error-path handling.

---

## 🧮 PQC Verification Logic

### Custom Verifier Flow

* Extract attestation certificate → Determine OID → Select ML-DSA parameter set
* Use `oqs.Signature` with the chosen algorithm to verify signatures
* Enforce chain trust manually (no native x509 helpers)
* Confirm issuer against trusted roots or metadata policies defined in `metadata.py`

### Root Validation

* Maintain a **trusted root CA list** for PQC in metadata cache
* Validate ML-DSA signature using issuer public key
* Enforce metadata requirement for PQ authenticators (configurable strict/permissive modes)
* Log verification results through the standard Flask logger for auditability

---

## 🧾 FIDO MDS & Metadata Handling

* `server/server/metadata.py` exposes `ensure_metadata_bootstrapped` used at startup
* Startup executes `ensure_metadata_bootstrapped()` (wired via `routes.general`) to download and cache the latest signed blob
* Verified payload entries merge with local overrides stored in `.mds_cache`
* Cached entries feed PQC trust decisions, attestation display data, and policy prompts

Manual refresh:

```bash
python - <<'PY'
from server.server.routes.general import ensure_metadata_bootstrapped
ensure_metadata_bootstrapped(skip_if_reloader_parent=False)
PY
```

For air-gapped testing, place signed metadata JSON files inside `.mds_cache` and disable remote fetch via environment configuration.

---

## 🧪 Testing

### Run all tests

```bash
pytest -q
```

### Syntax check

```bash
python -m compileall server/server fido2
```

### Import check

```bash
python - <<'PY'
import importlib
for module in [
    "server.server.app",
    "server.server.metadata",
    "server.server.routes.simple",
    "server.server.pqc",
]:
    importlib.import_module(module)
print("Import check passed.")
PY
```

Additional PQ regression coverage lives in `tests/test_mldsa_registration_authentication.py` to validate ML-DSA signature interoperability across certificate chains.

---

## ⚙️ CI/CD

### CI workflow (`.github/workflows/ci.yml`)

* Runs syntax + pytest checks
* Builds Docker image targeting deployment parity
* Triggers Dependabot auto-merge after CI passes
* Publishes metadata cache artifacts for downstream validation

### Dependabot Auto-Merge

Allows automatic merging of dependency PRs if CI succeeds. Repository maintainers should monitor for liboqs or python-fido2 updates that introduce PQ-breaking changes.

---

> 🧑‍💻 **Maintainer:** @rainzhang05
> 📅 **Last Updated:** October 2025
