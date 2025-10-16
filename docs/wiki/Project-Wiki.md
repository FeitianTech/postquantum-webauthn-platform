# PostQuantum WebAuthn Platform — Project Wiki

> A complete reference and developer guide for the **PostQuantum WebAuthn Test Platform**, integrating PQC algorithms via liboqs and python-fido2.

---

<p align="center">
  <a href="#-overview"><button>Overview</button></a>
  <a href="#-key-features"><button>Key Features</button></a>
  <a href="#-architecture"><button>Architecture</button></a>
  <a href="#-repository-layout"><button>Repository Layout</button></a>
  <a href="#-prerequisites"><button>Prerequisites</button></a>
  <a href="#-quick-start"><button>Quick Start</button></a>
  <a href="#-configuration"><button>Configuration</button></a>
  <a href="#-docker-deployment"><button>Docker Deployment</button></a>
  <a href="#-render-deployment"><button>Render Deployment</button></a>
  <a href="#-webauthn-flow"><button>WebAuthn Flow</button></a>
  <a href="#-pqc-verification-logic"><button>PQC Verification Logic</button></a>
  <a href="#-fido-mds--metadata-handling"><button>FIDO MDS</button></a>
  <a href="#-testing"><button>Testing</button></a>
  <a href="#-cicd"><button>CI/CD</button></a>
  <a href="#-troubleshooting"><button>Troubleshooting</button></a>
  <a href="#-security-notes"><button>Security Notes</button></a>
  <a href="#-roadmap"><button>Roadmap</button></a>
  <a href="#-glossary"><button>Glossary</button></a>
</p>

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
├── COPYING*, LICENSE docs
├── README.adoc                 # Public getting-started guide
├── docs/
│   └── wiki/                   # Internal wiki (this page)
├── fido2/                      # Vendored python-fido2 with PQC extensions
├── prebuilt_liboqs/            # Optional precompiled liboqs bundles
├── requirements.txt            # Runtime dependencies
├── server/
│   ├── pyproject.toml          # Poetry configuration for the Flask app
│   ├── poetry.lock
│   └── server/
│       ├── app.py              # Flask entry point (TLS enabled)
│       ├── config.py           # Application factory & configuration
│       ├── metadata.py         # Metadata service caching utilities
│       ├── pqc.py              # PQ certificate & signature verification
│       ├── routes/             # simple, general, advanced demo flows
│       ├── decoder/            # CBOR/WebAuthn decoding helpers
│       ├── static/             # Front-end assets (JS/CSS)
│       └── storage.py          # In-memory credential persistence
├── tests/                      # Pytest suites covering PQ and WebAuthn flows
├── Dockerfile                  # Multi-stage container build
├── render.yaml                 # Render deployment descriptor & cron job
└── pyproject.toml              # Root dev tooling configuration
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

## 🚀 Quick Start

```bash
git clone https://github.com/<your-username>/postquantum-webauthn-platform.git
cd postquantum-webauthn-platform
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install ".[pqc]"
```

1. **Prepare TLS for localhost**
   * Install [mkcert](https://github.com/FiloSottile/mkcert) and run `mkcert demo.ftsafe.demo` in the project root.
   * Add `127.0.0.1 demo.ftsafe.demo` to your `/etc/hosts` (or `C:\Windows\System32\drivers\etc\hosts`).

2. **Launch the relying party**

```bash
python -m server.server.app
```

3. **Open the demo** at [https://demo.ftsafe.demo:5000](https://demo.ftsafe.demo:5000) (modern browsers require HTTPS for WebAuthn).

> 💡 **Tip:** Windows developers should run inside **WSL** to avoid path issues with liboqs and Python SDKs. When using WSL, store certificates in the Linux filesystem so Flask can load them.

---

## 🧱 Configuration

| Variable              | Description                       | Example / Default |
| --------------------- | --------------------------------- | ----------------- |
| `RP_ID`               | Relying Party ID                  | `demo.ftsafe.demo` |
| `RP_NAME`             | User-facing display name          | `PQ WebAuthn Demo` |
| `ORIGIN`              | Allowed origin URL                | `https://demo.ftsafe.demo:5000` |
| `MDS_METADATA_URL`    | Remote FIDO metadata endpoint     | FIDO Alliance MDS v3 |
| `MDS_CACHE_DIR`       | Metadata cache directory          | `.mds_cache` |
| `LIBOQS_INSTALL_PATH` | Path to liboqs shared libraries   | `/opt/liboqs` or project `prebuilt_liboqs` |
| `PQ_ATTESTATION_MODE` | Trust policy (strict / permissive)| `strict` |
| `FLASK_ENV`           | Flask environment                 | `development` |

Configuration can be supplied via environment variables, `.env` files consumed by `server/server/config.py`, or Render deployment secrets. `config.py` merges defaults, environment overrides, and Render-specific settings.

---

## 🐳 Docker Deployment

```bash
docker build -t pqc-webauthn .
docker run --rm -p 5000:5000 \
  -v "$(pwd)/demo.ftsafe.demo.pem:/app/demo.ftsafe.demo.pem" \
  -v "$(pwd)/demo.ftsafe.demo-key.pem:/app/demo.ftsafe.demo-key.pem" \
  pqc-webauthn
```

The Dockerfile supports **prebuilt** or **source-built** liboqs. To use prebuilt bundles, populate:

```
prebuilt_liboqs/
└── linux-x86_64/
    ├── include/
    └── lib/
        └── liboqs.so
```

Set `LIBOQS_INSTALL_PATH=/app/prebuilt_liboqs/linux-x86_64` at runtime if needed. For platforms without prebuilt archives, the Dockerfile builds liboqs from source during the image build.

---

## 🌐 Render Deployment

Example Render `cronJobs` section in `render.yaml`:

```yaml
cronJobs:
  - name: pqc-mdscache-refresh
    schedule: "0 18 * * *"   # 2 AM Beijing = 18:00 previous day UTC
    runtime: docker
    dockerfilePath: ./Dockerfile
    dockerContext: .
    dockerCommand:
      - python
      - -c
      - >-
          from server.server.routes.general import ensure_metadata_bootstrapped;
          ensure_metadata_bootstrapped(skip_if_reloader_parent=False)
```

When deploying the web service:

* Inject `RP_ID`, `ORIGIN`, and certificate paths through Render environment variables.
* Mount TLS materials via Render secrets or persistent disks.
* Schedule the metadata cron job to keep PQ attestation roots up-to-date.

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

## 🧠 Troubleshooting

| Issue                      | Cause                          | Fix |
| -------------------------- | ------------------------------ | --- |
| `pytest not found`         | venv not active                | `pip install pytest` or `source .venv/bin/activate` |
| `favicon not loading`      | Wrong static path              | Adjust `<link rel="icon">` in `server/server/templates/base.html` |
| `liboqs missing`           | Shared libs not discoverable   | Set `LIBOQS_INSTALL_PATH` or update `LD_LIBRARY_PATH`/`PATH` |
| `Invalid SDK`              | WSL path mismatch              | Rebuild venv inside WSL & reinstall `oqs` |
| `CERTIFICATE_VERIFY_FAILED`| Missing mkcert root trust      | Run `mkcert -install` and regenerate certificates |
| `Host mismatch`            | RP ID not matching origin      | Align `RP_ID` / `ORIGIN` environment values |

---

## 🔒 Security Notes

* Always **fail closed** if metadata is missing for PQ devices
* Verify issuer trust **explicitly**, not just signature validity
* Keep liboqs and liboqs-python updated (algorithm implementations evolve)
* Enforce CBOR canonicalization for WebAuthn spec compliance
* Rotate TLS certificates regularly and secure private keys in deployment environments

---

## 🧭 Roadmap

* [ ] Add SPHINCS+, Falcon PQ signature support
* [ ] Integrate SQLite credential storage
* [ ] Add React front-end for WebAuthn demo
* [ ] Support multiple MDS sources and offline bundles
* [ ] Add PKI visualization dashboard & certificate diff tooling
* [ ] Provide hardware authenticator interoperability matrix

---

## 📖 Glossary

| Term         | Description                                                |
| ------------ | ---------------------------------------------------------- |
| **WebAuthn** | Standard for passwordless authentication using public keys |
| **CTAP**     | Client-to-Authenticator Protocol                           |
| **MDSv3**    | FIDO Metadata Service version 3                            |
| **ML-DSA**   | PQ signature algorithm (a variant of Dilithium)            |
| **liboqs**   | Open Quantum Safe cryptographic library                    |
| **RP ID**    | Relying Party identifier used for WebAuthn requests        |

---

> 🧑‍💻 **Maintainer:** @rainzhang05
> 📅 **Last Updated:** October 2025
