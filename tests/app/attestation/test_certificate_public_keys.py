"""``webauthn.attestation.certificate_public_keys``: how the certificate views describe a public key."""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import dsa

from server.app.webauthn.attestation import (
    certificate_public_keys as attestation_certificate_public_keys,
)


def test_a_key_type_the_views_do_not_describe_is_named_by_its_class():
    key = dsa.generate_private_key(key_size=1024).public_key()

    info = attestation_certificate_public_keys._serialize_public_key_info(key)

    assert info["type"] == info["algorithm"]["name"] == type(key).__name__
    assert info["keySize"] == 1024
    assert info["subjectPublicKeyInfoBase64"]


# ``mldsa.extract_certificate_public_key_info`` gives no parameters and no key bytes
# for a key cryptography will not load; a direct call gives the helpers them.


def test_an_unloadable_keys_parameters_and_wrapped_key_are_described_when_known():
    parsed = {
        "algorithm_name": "ML-DSA",
        "algorithm_oid": "2.16.840.1.101.3.4.3.18",
        "ml_dsa_parameter_set": "ML-DSA-65",
        "ml_dsa_parameter_details": {"claimed_nist_level": 3, "signature_length": 3309},
        "algorithm_parameters": b"\x05\x00",
        "subject_public_key": b"\x01\x02",
        "wrapped_subject_public_key": b"\x04\x02\x01\x02",
    }
    info = {"type": "ML-DSA"}

    algorithm, _details, parameter_set = attestation_certificate_public_keys._unknown_key_algorithm(parsed)
    key_size = attestation_certificate_public_keys._unknown_key_material(parsed, info)
    summary = dict(attestation_certificate_public_keys._unknown_key_summary(info, algorithm, key_size))

    assert parameter_set == "ML-DSA-65"
    assert algorithm["parametersHex"] == "0500"
    assert (key_size, info["publicKeyHex"]) == (16, "01:02")
    assert info["wrappedPublicKeyHexLines"] == ["04:02:01:02"]
    assert summary["Wrapped Public Key (hex)"] == ["04:02:01:02"]
    assert summary["Claimed NIST level"] == 3
