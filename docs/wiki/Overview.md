# Post-Quantum WebAuthn Platform Wiki

Welcome to the internal wiki for the Post-Quantum WebAuthn Test Platform. This documentation complements the public README and provides deeper insight into the system architecture, setup workflows, and development practices that keep the demo server and companion tooling running smoothly.

The project delivers an end-to-end environment for experimenting with WebAuthn flows backed by classical and post-quantum signature suites. It includes a hosted demo, local server, credential decoder, and a FIDO Metadata Service (MDS) explorer that help developers inspect authenticator behaviour under different algorithms.【F:README.adoc†L5-L7】

## How to Use the Wiki

* Start with the [Setup](Setup.md) guide when provisioning a new development machine.
* Review [Architecture](Architecture.md) for a tour of backend modules and frontend assets.
* Dive into [Post-Quantum Support](Post-Quantum.md) to understand how ML-DSA algorithms are enabled through liboqs.
* Consult [Metadata & Storage](Metadata-and-Storage.md) when debugging cached MDS blobs or credential persistence.
* Visit [Testing](Testing.md) to learn how automated checks validate the platform.

Each page links back to relevant source code so you can jump directly from documentation to implementation.
