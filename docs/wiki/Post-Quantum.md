# Post-Quantum Support

The platform is designed to compare classical WebAuthn algorithms with ML-DSA signatures delivered via the Open Quantum Safe (OQS) project.

## Available Algorithms

`server/server/pqc.py` maps COSE algorithm identifiers to the ML-DSA variants (`ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87`) exposed by liboqs. Helper functions detect which mechanisms are enabled in the local bindings, log selection decisions, and render friendly labels for UI display or diagnostics.【F:server/server/pqc.py†L1-L156】 When the bindings are missing or incomplete, the module returns actionable error messages so operators can rebuild liboqs with the necessary options.

## Installing liboqs

Follow the setup guide to build the C `liboqs` library, install the `liboqs-python` wrapper, and verify that the enabled signature list includes the ML-DSA algorithms you intend to test.【F:README.adoc†L95-L167】 The optional `python-fido2-webauthn-test[pqc]` extra referenced by the detection helper pulls in the Python bindings so the server can exercise these algorithms during registration and authentication flows.【F:server/server/pqc.py†L45-L77】

## Frontend Surfacing

The advanced registration tab exposes algorithm selection and displays the negotiated COSE identifiers. The backend logs whether a PQC or classical algorithm was chosen, allowing you to cross-reference console output with the UI when debugging ceremony outcomes.【F:server/server/pqc.py†L131-L147】 Use the metadata explorer and decoder tabs to inspect attestation objects and confirm that the attestation statement references the expected ML-DSA suite.
