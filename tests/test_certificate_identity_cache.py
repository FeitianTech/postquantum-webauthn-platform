import base64
import json
from pathlib import Path

from fido2.attestation import base as attestation_base


def _load_feitian_root_certificate_bytes() -> bytes:
    metadata_path = Path("examples/server/server/static/feitian-pqc.json")
    metadata = json.loads(metadata_path.read_text())
    return base64.b64decode(metadata["attestationRootCertificates"][0])


def _mutate_signature_oid(cert_der: bytes) -> bytes:
    """Return *cert_der* with the TBSCertificate signature OID rewritten to RSA."""

    oid_mldsa = bytes.fromhex("0609608648016503040311")
    oid_rsa = bytes.fromhex("06092a864886f70d01010b")
    idx = cert_der.find(oid_mldsa)
    assert idx >= 0, "expected ML-DSA OID to be present in certificate"
    mutated = bytearray(cert_der)
    mutated[idx : idx + len(oid_mldsa)] = oid_rsa
    return bytes(mutated)


def test_identity_cache_prefers_ml_dsa_signature():
    original_der = _load_feitian_root_certificate_bytes()
    mutated_der = _mutate_signature_oid(original_der)

    attestation_base._PARSED_CERTIFICATE_CACHE.clear()
    attestation_base._PARSED_CERTIFICATE_IDENTITIES.clear()

    mutated_parsed = attestation_base._get_parsed_certificate(mutated_der)
    assert (
        mutated_parsed.signature_algorithm_oid
        == "1.2.840.113549.1.1.11"
    )
    assert (
        mutated_parsed.subject_public_key_algorithm_oid
        == "2.16.840.1.101.3.4.3.17"
    )

    original_parsed = attestation_base._get_parsed_certificate(original_der)
    assert original_parsed.signature_algorithm_oid == "2.16.840.1.101.3.4.3.17"
    assert (
        original_parsed.subject_public_key_algorithm_oid
        == "2.16.840.1.101.3.4.3.17"
    )

    mutated_again = attestation_base._get_parsed_certificate(mutated_der)
    assert mutated_again.signature_algorithm_oid == "2.16.840.1.101.3.4.3.17"
    assert (
        mutated_again.subject_public_key_algorithm_oid
        == "2.16.840.1.101.3.4.3.17"
    )

    attestation_base._PARSED_CERTIFICATE_CACHE.clear()
    attestation_base._PARSED_CERTIFICATE_IDENTITIES.clear()
