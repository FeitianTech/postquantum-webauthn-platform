# FIDO2/WebAuthn Test Platform and Developer Tools

[![CI](https://img.shields.io/github/actions/workflow/status/feitiantech/postquantum-webauthn-platform/ci-python.yml?label=CI\&logo=github)](https://github.com/feitiantech/postquantum-webauthn-platform/actions/workflows/ci-python.yml)
[![Build](https://img.shields.io/github/actions/workflow/status/feitiantech/postquantum-webauthn-platform/ci-docker.yml?label=Build\&logo=docker)](https://github.com/feitiantech/postquantum-webauthn-platform/actions/workflows/ci-docker.yml)

A FIDO2/WebAuthn test platform and developer tool, live at
<https://webauthndev.com>. It runs real WebAuthn ceremonies in your browser
against its own relying party, verifies them on the server with
[python-fido2](https://github.com/Yubico/python-fido2), and shows what every part
of a credential holds, post-quantum (ML-DSA) credentials included.

## What it does

* **Simple Authentication**: register and sign in under a username, with fixed
  settings.
* **Advanced Authentication**: every registration and authentication option, in
  a form or as the request's JSON.
* **Saved credentials**: kept in your browser and shared by both tabs, each with
  its attestation, certificates and what FIDO's metadata says of it.
* **Codec**: decode WebAuthn JSON, CBOR, CTAP messages, authenticator data and
  X.509 certificates, shown as sent; encode JSON or EDN back into bytes.
* **FIDO MDS Authenticators**: every authenticator in the FIDO Metadata Service,
  from a verified snapshot checked twice a day for a newer one, and statements of
  your own.
* **Analyze Browser**: what this browser says about WebAuthn, and where each
  answer came from.

Registrations offer ML-DSA-44, ML-DSA-65 and ML-DSA-87 (FIPS 204) first, then
EdDSA, ES256, RS256 and ES384. Flask serves the API and a Next.js static export
of the UI. [docs/FEATURES.md](docs/FEATURES.md) describes each section.

## Run it locally

You need Docker with Compose, and a browser with WebAuthn's JSON methods (Chrome
or Edge 129, Firefox 119, Safari 18.4 or later).

```bash
git clone https://github.com/FeitianTech/postquantum-webauthn-platform.git
cd postquantum-webauthn-platform
docker compose up -d
docker compose exec webauthn python tools/update_mds_snapshot.py
```

Open <http://localhost:8000> on the same machine (the port is published on
`127.0.0.1` only). The MDS explorer is empty until the last command has loaded
the FIDO metadata; run it again to take a newer BLOB
([docs/MDS_SNAPSHOT.md](docs/MDS_SNAPSHOT.md)).

## Documentation

* [docs/FEATURES.md](docs/FEATURES.md): what each section of the site does.
* [deploy/README.md](deploy/README.md): the Cloud Run service, how a push to
  `main` is checked and deployed, and
  [every setting the server reads](deploy/README.md#environment-variables).
* [docs/DESIGN.md](docs/DESIGN.md): the UI's design, security and serving rules.
* [docs/STORAGE.md](docs/STORAGE.md): what the server keeps for a visitor, its
  limits, how long it keeps it, and the credential log.
* [docs/DECODER.md](docs/DECODER.md): the Codec's decoder and encoder.
* [docs/MDS_SNAPSHOT.md](docs/MDS_SNAPSHOT.md): the FIDO MDS snapshot: where it
  comes from, how it is verified, published and served.
* [AGENTS.md](AGENTS.md): developing: the code's map, running without Docker, the
  tests and the rules every change keeps.
* [SECURITY.md](SECURITY.md): reporting a vulnerability.

## License

Copyright 2025-2026 FEITIAN Technologies Co., Ltd., under the [Apache License 2.0](LICENSE).

The Geist font in `web/src/fonts` is under the SIL Open Font License
([OFL.txt](web/src/fonts/OFL.txt)), and the test vectors copied from python-fido2
(`tests/app/python_fido2_vectors.py`) keep its BSD licence there.
