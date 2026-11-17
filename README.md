# FIDO2/WebAuthn Test Platform and Developer Tools

[![CI](https://img.shields.io/github/actions/workflow/status/feitiantech/postquantum-webauthn-platform/ci-python.yml?label=CI\&logo=github)](https://github.com/feitiantech/postquantum-webauthn-platform/actions/workflows/ci-python.yml)
[![Build](https://img.shields.io/github/actions/workflow/status/feitiantech/postquantum-webauthn-platform/ci-docker.yml?label=Build\&logo=docker)](https://github.com/feitiantech/postquantum-webauthn-platform/actions/workflows/ci-docker.yml)

---

## Overview

A FIDO2/WebAuthn test platform and developer tool. It runs real WebAuthn
ceremonies in your browser against its own relying party, verifies them on the
server with [python-fido2](https://github.com/Yubico/python-fido2), and shows what
every part of a credential holds, post-quantum (ML-DSA) credentials included.

* **Simple Authentication**: register a credential under a username and sign in
  with it, with fixed settings: a cross-platform authenticator (a security key or a
  phone), no user verification and no attestation asked for. The server checks
  every ceremony: one that does not hold (a bad signature, or a challenge, origin
  or RP ID that does not match) is refused, and any other finding is a warning
  beside the result.
* **Saved credentials**, which both tabs share: each registration is kept in the
  browser and listed in both tabs. A credential's details show its properties and
  the attestation's checks (signature, root, RP ID hash, AAGUID match) with what
  the FIDO Metadata Service says of the authenticator, its user, AAGUID,
  authenticator data and public key, and its registration: the attestation's
  findings in words, each certificate, and every part the Codec can decode.
  Deleting one removes it from the server and the browser, and a browser with
  WebAuthn's Signal API is told it is gone.
* **Advanced Authentication**: registration and authentication requests with every
  option, set in a form or written as the request's JSON beside it, each following
  the other: the user, challenge, timeout, authenticator attachment, resident key,
  user verification, attestation, algorithms, hints, credentials to exclude or
  allow (fake ones too), and the credProps, minPinLength, credProtect, largeBlob
  and prf extensions; the JSON can name the RP ID too. The result lists every
  finding as an error, and opens each part of the browser's response in the Codec.
  An authentication can use any saved credential, the Simple tab's too.
* **Codec**: decode JSON (a PublicKeyCredential, clientDataJSON), CBOR (an
  attestation object; a CTAP makeCredential, getAssertion or getInfo message),
  authenticator data, or X.509 certificates, given as JSON, PEM, hex, base64 or
  base64url; each value is shown with what it means and what the decoder found. It
  shows what was sent and never repairs it. Encode writes a value as JSON, CBOR,
  EDN, a COSE key, DER or PEM.
* **FIDO MDS Authenticators**: every authenticator in the FIDO Alliance's Metadata
  Service, from a snapshot of its BLOB verified against the FIDO root and the
  chain's CRLs, checked for a newer BLOB twice a day. Filter, sort and resize the
  table; open an entry's statement, status reports, certificates and raw JSON, the
  credentials saved for its AAGUID, and Try in Advanced, which sets up an Advanced
  registration with what the statement says the authenticator takes. Manage
  Metadata uploads statements of your own: they are listed in front of the FIDO
  ones, and registrations are checked against them, with a warning that they are
  not FIDO's.
* **Analyze Browser**: which browser this is, and what it says about WebAuthn
  (secure context, the API, passkey autofill, the JSON methods,
  `getClientCapabilities()`, a built-in authenticator, a phone over hybrid), with
  where each answer came from, or that it cannot be known; and a report to copy.

Registrations offer their algorithms in this order: **ML-DSA-44**, **ML-DSA-65**
and **ML-DSA-87** (FIPS 204; COSE -48, -49, -50), then EdDSA, ES256, RS256 and
ES384. The Simple tab offers these; the Advanced form ticks them by default and
lists further classical ones to choose.

Flask serves the API and the UI, a Next.js static export; no Node runs in
production.

---

## Deployments

| Environment                 | Description             | URL                                                        |
| --------------------------- | ----------------------- | ---------------------------------------------------------- |
| **Google Cloud Deployment** | Full FIDO MDS Support   | https://webauthndev.com                                    |
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

Open the following address in your browser on the same machine (the port is
published on `127.0.0.1` only):

```text
http://localhost:8000
```

---

### Step 4 — Load the FIDO Metadata

The MDS explorer is empty until the container has a metadata snapshot. This
downloads the FIDO Alliance's BLOB, verifies it against the pinned trust root and
writes the snapshot into the compose volume `instance` (the container's
`/app/instance/mds-snapshot`), which the running server reads at once and keeps
across restarts:

```bash
docker compose exec webauthn python tools/update_mds_snapshot.py
```

Run it again to take a newer BLOB. The container runs as an unprivileged user
that owns only that volume; a `./instance` folder an earlier compose file mounted
is no longer read. [docs/MDS_SNAPSHOT.md](docs/MDS_SNAPSHOT.md)
has the whole picture.

---

## License

Copyright 2025-2026 FEITIAN Technologies Co., Ltd., under the [Apache License 2.0](LICENSE).

The Geist font in `web/src/fonts` is under the SIL Open Font License
([OFL.txt](web/src/fonts/OFL.txt)), and the test vectors copied from python-fido2
(`tests/app/python_fido2_vectors.py`) keep its BSD licence there.
