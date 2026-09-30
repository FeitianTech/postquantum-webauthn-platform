from __future__ import annotations

from server.app.webauthn.attestation import (
    certificate_names as attestation_certificate_names,
)


def test_attestation_helper_residual_branches(monkeypatch, certificate_public_keys, attestation_module):
    assert attestation_certificate_names._derive_certificate_algorithm_info("not-a-mapping") == ""
    assert (
        attestation_certificate_names._derive_certificate_algorithm_info(
            {"algorithm": "ecdsa", "hash": "sha-256"}
        )
        == "ECDSA_SHA256"
    )
    assert (
        attestation_certificate_names._derive_certificate_algorithm_info({"algorithm": "ed25519"})
        == "ED25519_SHA512"
    )
    assert (
        attestation_certificate_names._derive_certificate_algorithm_info({"algorithm": "ed448"})
        == "ED448_SHAKE256"
    )
