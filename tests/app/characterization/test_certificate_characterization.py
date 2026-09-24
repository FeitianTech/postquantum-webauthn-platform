"""Certificate serialisation and attestation-detail extraction are unchanged.

``serialize_attestation_certificate`` runs over every byte-stable certificate
the tests have (device captures and the deterministic ones ``material.py``
builds), and ``extract_attestation_details`` over captured attestation objects
and a few malformed ones. Output is compared with ``sort_keys=False``: the
decoder dumps these without sorting, so key order is behaviour too.
"""
from __future__ import annotations

from fido2 import cbor

from ..security.ceremony_helpers import b64u, client_data
from . import harness, material


def test_certificate_serialisation_matches_its_golden_record():
    from server.app.webauthn import attestation

    certificates = {**material.captured_certificates(), **material.generated_certificates()}
    record = {
        name: harness.json_safe(attestation.serialize_attestation_certificate(der))
        for name, der in certificates.items()
    }
    record["empty-input"] = harness.json_safe(attestation.serialize_attestation_certificate(b""))
    harness.check_golden("certificates.json", record)


def _registration_response(attestation_object: bytes, **response_extra) -> dict:
    return {
        "id": b64u(b"\x42" * 16),
        "rawId": b64u(b"\x42" * 16),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64u(client_data(challenge=b"\x01" * 32, ceremony_type="webauthn.create")),
            "attestationObject": b64u(attestation_object),
            **response_extra,
        },
        "clientExtensionResults": {"credProps": {"rk": True}, "largeBlob": {"supported": True}},
    }


def test_attestation_details_match_their_golden_record():
    from server.app.webauthn import attestation

    leaf = material.attestation_leaf_certificate(bytes(16))
    auth_data = material.Authenticator("details").authenticator_data()
    odd_chain = cbor.encode({"fmt": "packed", "attStmt": {"alg": -7, "sig": b"\x00", "x5c": [leaf, b"\x30\x00", 5]}, "authData": auth_data})
    inputs = {name: _registration_response(obj) for name, obj in material.captured_attestation_objects().items()}
    inputs["odd-x5c-entries"] = _registration_response(odd_chain)
    inputs["not-cbor"] = _registration_response(b"\xff\xfe")
    inputs["not-a-dict"] = ["not", "a", "dict"]
    inputs["no-response"] = {"id": "x", "type": "public-key"}
    record = {name: harness.json_safe(attestation.extract_attestation_details(value)) for name, value in inputs.items()}
    harness.check_golden("attestation-details.json", record)


def test_certificate_helpers_match_their_golden_record():
    import base64

    from fido2.utils import ByteBuffer
    from server.app.webauthn import attestation

    der = material.generated_certificates()["generated-ec-p256"]
    mldsa_der = material.generated_certificates()["generated-ml-dsa-44"]
    pem = "-----BEGIN CERTIFICATE-----\n" + base64.b64encode(der).decode() + "\n-----END CERTIFICATE-----"
    coerce_inputs = {
        "none": None, "empty": "", "blank": "   ", "bytes": der[:8], "bytearray": bytearray(der[:8]),
        "memoryview": memoryview(der[:8]), "bytebuffer": ByteBuffer(der[:8]),
        "base64": base64.b64encode(der[:9]).decode(), "base64url": base64.urlsafe_b64encode(b"\xfb\xff" * 4).decode(),
        "not-base64": "@@@@", "raw-hex": {"raw": der[:8].hex()}, "raw-not-hex": {"raw": "zz"},
        "der-base64": {"derBase64": base64.b64encode(der[:8]).decode()},
        "der_base64": {"der_base64": base64.b64encode(der[:8]).decode()}, "pem": {"pem": pem},
        "bad-pem": {"pem": "-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----"},
        "empty-mapping": {}, "int": 5, "list": [1, 2], "object": object(),
    }
    record = {"coerce": {}}
    for name, value in coerce_inputs.items():
        try:
            record["coerce"][name] = harness.json_safe(attestation._coerce_attestation_certificate_bytes(value))
        except Exception as exc:
            record["coerce"][name] = f"raises {type(exc).__name__}: {exc}"
    error = ValueError("unparsable for the test")
    for name, cert in {"ec": der, "ml-dsa": mldsa_der, "truncated": der[:40], "garbage": b"\x01\x02"}.items():
        record[f"unknown-key/{name}"] = harness.json_safe(attestation._build_unknown_public_key_info(cert, error))
        record[f"fallback/{name}"] = harness.json_safe(attestation._serialize_attestation_certificate_fallback(cert, error))
    names = ["", "  ", "ecdsa-with-SHA256", "RSASSA-PSS", "sha256WithRSAEncryption", "ed25519", "Ed448",
             "dsa-with-sha1", "ML-DSA-44", "some thing-else"]
    record["normalise"] = {name: attestation._normalise_signature_algorithm_name(name) for name in names}
    record["hash"] = {repr(value): attestation._format_hash_value(value) for value in (None, "", " ", "sha-256", "SHA384", "shake-256", "md5")}
    record["component"] = {repr(value): attestation._format_algorithm_component(value) for value in (None, "", "\u2014", " RSA PSS ", 5)}
    signature_infos = [
        "not-a-mapping", {}, {"algorithm": "ecdsa-with-SHA256", "hash": {"name": "sha256"}},
        {"algorithm": {"name": "sha256WithRSAEncryption"}, "hash": "sha-256"}, {"algorithm": "ed25519"},
        {"algorithm": "Ed448", "hash": ""}, {"algorithm": "ML-DSA-65"}, {"algorithm": "sha1", "hash": "sha1"},
        {"algorithm": 5, "hash": {"name": None}},
    ]
    record["algorithm-info"] = [attestation._derive_certificate_algorithm_info(info) for info in signature_infos]
    harness.check_golden("certificate-helpers.json", record)
