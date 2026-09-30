"""An ML-DSA attestation is verified as any other: fido2's full packed verification.

A PQC fallback once re-ran a bare signature check when that failed, and on
success set ``signature_valid = True`` and cleared the errors, though it skipped
the packed certificate policy checks (Subject OU, AAGUID extension match, Basic
Constraints). There is no fallback now, and no separate PQC result: what fido2
refuses is invalid, with its errors.
"""
from __future__ import annotations

import pytest

from .ceremony_helpers import (
    ORIGIN,
    RP_ID,
    Authenticator,
    attestation_object,
    b64u,
    client_data,
)

MLDSA44_ALG = -48


@pytest.fixture
def attestation_module():
    return pytest.importorskip("server.app.webauthn.attestation")


def _packed_registration_response(authenticator, *, challenge, attestation_alg):
    """A packed attestation whose signature cannot verify.

    The attestation statement claims a PQC algorithm while the credential key
    is a classical one, so the PQC fallback is genuinely attempted and
    genuinely fails -- no stubbing involved.
    """

    data = client_data(challenge=challenge, ceremony_type="webauthn.create")
    auth_data = authenticator.authenticator_data(rp_id=RP_ID)
    att_obj = attestation_object(
        auth_data,
        fmt="packed",
        att_stmt={"alg": attestation_alg, "sig": b"\x00" * 64},
    )
    return {
        "id": b64u(authenticator.credential_id),
        "rawId": b64u(authenticator.credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64u(data),
            "attestationObject": b64u(att_obj),
        },
        "clientExtensionResults": {},
    }


def test_an_mldsa_attestation_that_does_not_verify_is_invalid_with_its_errors(attestation_module):

    authenticator = Authenticator()
    challenge = b"\x61" * 32

    response = _packed_registration_response(
        authenticator, challenge=challenge, attestation_alg=MLDSA44_ALG
    )

    result = attestation_module.perform_attestation_checks(
        response,
        {"challenge": challenge},
        None,
        None,
        ORIGIN,
        RP_ID,
    )

    assert result["signature_valid"] is False
    assert "pqc_signature_valid" not in result
    assert result["errors"], "attestation errors must not be cleared"
    joined = "\n".join(result["errors"])
    assert "attestation" in joined


def test_a_classical_attestation_that_does_not_verify_is_invalid_with_its_errors(attestation_module):

    authenticator = Authenticator()
    challenge = b"\x63" * 32

    response = _packed_registration_response(
        authenticator, challenge=challenge, attestation_alg=-7
    )
    result = attestation_module.perform_attestation_checks(
        response,
        {"challenge": challenge},
        None,
        None,
        ORIGIN,
        RP_ID,
    )

    assert result["signature_valid"] is False
    assert result["errors"]


def _mldsa_basic_attestation_response(authenticator, *, challenge, signing_key=None):
    """A packed basic attestation with a genuine ML-DSA-44 signature.

    The x5c certificate is a real ML-DSA-44 certificate, but it lacks the
    packed-attestation policy extensions (Basic Constraints etc.), so full
    packed verification genuinely fails although the signature itself verifies.
    """

    import datetime
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import mldsa
    from cryptography.x509.oid import NameOID

    certificate_key = mldsa.MLDSA44PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "No policy extensions")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(certificate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(certificate_key, None)
    )

    data = client_data(challenge=challenge, ceremony_type="webauthn.create")
    auth_data = authenticator.authenticator_data(rp_id=RP_ID)
    signer = signing_key or certificate_key
    signature = signer.sign(auth_data + hashlib.sha256(data).digest())
    att_obj = attestation_object(
        auth_data,
        fmt="packed",
        att_stmt={
            "alg": MLDSA44_ALG,
            "sig": signature,
            "x5c": [certificate.public_bytes(serialization.Encoding.DER)],
        },
    )
    return {
        "id": b64u(authenticator.credential_id),
        "rawId": b64u(authenticator.credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64u(data),
            "attestationObject": b64u(att_obj),
        },
        "clientExtensionResults": {},
    }


def test_a_good_signature_does_not_rescue_a_certificate_packed_refuses(attestation_module):
    """The laundering case itself, driven with real ML-DSA crypto: the signature
    is genuine, the certificate fails the packed policy checks."""

    authenticator = Authenticator()
    challenge = b"\x64" * 32
    response = _mldsa_basic_attestation_response(authenticator, challenge=challenge)

    result = attestation_module.perform_attestation_checks(
        response,
        {"challenge": challenge},
        None,
        None,
        ORIGIN,
        RP_ID,
    )

    assert result["signature_valid"] is False
    assert result["errors"]


def test_a_signature_from_another_mldsa_key_is_invalid(attestation_module):

    from cryptography.hazmat.primitives.asymmetric import mldsa

    authenticator = Authenticator()
    challenge = b"\x65" * 32
    response = _mldsa_basic_attestation_response(
        authenticator,
        challenge=challenge,
        signing_key=mldsa.MLDSA44PrivateKey.generate(),
    )

    result = attestation_module.perform_attestation_checks(
        response,
        {"challenge": challenge},
        None,
        None,
        ORIGIN,
        RP_ID,
    )

    assert result["signature_valid"] is False
    assert result["errors"]
