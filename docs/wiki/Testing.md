# Testing

The repository ships with an extensive pytest suite covering FIDO2 libraries, authenticator transports, and post-quantum extensions.

## Test Layout

The `tests` package contains modules for CTAP1/CTAP2 behaviours, COSE handling, metadata parsing, device transports (HID/PCSC), and WebAuthn ceremonies. Specialized suites validate ML-DSA registration/authentication flows to ensure PQC support stays functional.【F:tests/test_ctap2.py†L1-L118】【F:tests/test_mldsa_registration_authentication.py†L1-L117】

## Running Tests

From the repository root, activate your virtual environment and execute:

```bash
pytest
```

To focus on PQC coverage you can target the ML-DSA module:

```bash
pytest tests/test_mldsa_registration_authentication.py
```

Tests rely on the python-fido2 fixtures bundled with the project. Some hardware-specific suites (HID/PCSC) may require connected devices or additional drivers; skip them locally if you lack the equipment.
