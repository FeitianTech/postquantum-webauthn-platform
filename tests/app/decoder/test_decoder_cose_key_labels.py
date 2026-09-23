"""The decoder names a credential's COSE algorithm from the one shared table.

``server.app.webauthn.pqc.describe_algorithm`` is the mapping the registration
and authentication routes already report; the decoder used to keep a second
table of its own that had -35/-36/-37 shifted by one and no ML-DSA entries.
"""
from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, rsa

from fido2 import cbor
from fido2.cose import ES256, ES384, ES512, MLDSA44, MLDSA65, MLDSA87, PS256
from fido2.webauthn import Aaguid, AttestedCredentialData, AuthenticatorData
from server.app.decoder.decode import binary
from server.app.webauthn import pqc


def _attestation_object_hex(cose_key) -> str:
    credential = AttestedCredentialData.create(Aaguid(b"\x00" * 16), b"\x01\x02", cose_key)
    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        1,
        credential,
    )
    return cbor.encode({"fmt": "none", "authData": bytes(auth_data), "attStmt": {}}).hex()


def _decoded_public_key(client, cose_key) -> dict:
    response = client.post("/api/decode", json={"payload": _attestation_object_hex(cose_key)})
    assert response.status_code == 200
    return response.get_json()["data"]["authenticatorData"]["credential"]["publicKey"]


@pytest.mark.parametrize(
    ("alg", "expected"),
    [
        (-35, "ES384 (ECDSA)"),
        (-36, "ES512 (ECDSA)"),
        (-37, "PS256 (RSA-PSS)"),
        (-47, "ES256K (ECDSA)"),
    ],
)
def test_p384_p521_rsa_pss_and_secp256k1_carry_their_own_names(alg, expected):
    assert binary._resolve_cose_algorithm({3: alg}) == expected


@pytest.mark.parametrize(
    ("alg", "parameter_set"),
    [(-48, "ML-DSA-44"), (-49, "ML-DSA-65"), (-50, "ML-DSA-87")],
)
def test_ml_dsa_algorithms_are_named_not_shown_as_bare_numbers(alg, parameter_set):
    assert binary._resolve_cose_algorithm({3: alg}) == f"{parameter_set} (PQC)"
    assert binary._resolve_cose_algorithm({}, {"publicKeyAlgorithm": alg}) == f"{parameter_set} (PQC)"


@pytest.mark.parametrize(
    "alg", [-7, -8, -9, -19, -35, -36, -37, -38, -39, -47, -48, -49, -50, -51, -52, -53, -257, -258, -259, -65535, -999]
)
def test_every_algorithm_label_comes_from_describe_algorithm(alg):
    assert binary._resolve_cose_algorithm({3: alg}) == pqc.describe_algorithm(alg)
    assert binary._resolve_cose_algorithm({"3": str(alg)}) == pqc.describe_algorithm(alg)


def test_the_decoder_keeps_no_algorithm_table_of_its_own():
    assert not hasattr(binary, "_COSE_ALG_LABELS")


@pytest.mark.parametrize(
    ("make_key", "expected"),
    [
        (lambda: ES256.from_cryptography_key(ec.generate_private_key(ec.SECP256R1()).public_key()), "ES256 (ECDSA)"),
        (lambda: ES384.from_cryptography_key(ec.generate_private_key(ec.SECP384R1()).public_key()), "ES384 (ECDSA)"),
        (lambda: ES512.from_cryptography_key(ec.generate_private_key(ec.SECP521R1()).public_key()), "ES512 (ECDSA)"),
        (
            lambda: PS256.from_cryptography_key(rsa.generate_private_key(65537, 2048).public_key()),
            "PS256 (RSA-PSS)",
        ),
        (lambda: MLDSA44.from_cryptography_key(mldsa.MLDSA44PrivateKey.generate().public_key()), "ML-DSA-44 (PQC)"),
        (lambda: MLDSA65.from_cryptography_key(mldsa.MLDSA65PrivateKey.generate().public_key()), "ML-DSA-65 (PQC)"),
        (lambda: MLDSA87.from_cryptography_key(mldsa.MLDSA87PrivateKey.generate().public_key()), "ML-DSA-87 (PQC)"),
    ],
)
def test_api_decode_names_the_credential_algorithm(client, make_key, expected):
    assert _decoded_public_key(client, make_key())["alg"] == expected


# ---------------------------------------------------------------------------
# COSE key types. ML-DSA keys are kty 7 (AKP) with the public key at label -1;
# the decoder names every key type and the parameter that sizes it.


def test_api_decode_describes_an_ml_dsa_akp_key(client):
    for key_class, private_class, parameter_set, length in (
        (MLDSA44, mldsa.MLDSA44PrivateKey, "ML-DSA-44", 1312),
        (MLDSA65, mldsa.MLDSA65PrivateKey, "ML-DSA-65", 1952),
        (MLDSA87, mldsa.MLDSA87PrivateKey, "ML-DSA-87", 2592),
    ):
        public_key = _decoded_public_key(
            client, key_class.from_cryptography_key(private_class.generate().public_key())
        )
        assert public_key["keyType"] == "AKP (7)"
        assert public_key["parameterSet"] == parameter_set
        assert public_key["publicKeyBytes"] == length
        assert "publicKeyBytesExpected" not in public_key


def test_api_decode_describes_ec2_and_rsa_keys_the_same_way(client):
    p256 = _decoded_public_key(client, ES256.from_cryptography_key(ec.generate_private_key(ec.SECP256R1()).public_key()))
    assert (p256["keyType"], p256["curve"]) == ("EC2 (2)", "P-256 (1)")

    p384 = _decoded_public_key(client, ES384.from_cryptography_key(ec.generate_private_key(ec.SECP384R1()).public_key()))
    assert (p384["keyType"], p384["curve"]) == ("EC2 (2)", "P-384 (2)")

    rsa_key = _decoded_public_key(client, PS256.from_cryptography_key(rsa.generate_private_key(65537, 2048).public_key()))
    assert (rsa_key["keyType"], rsa_key["modulusBits"]) == ("RSA (3)", 2048)


def test_an_akp_key_of_the_wrong_length_says_what_fips_204_expects():
    described = binary._describe_cose_key({1: 7, 3: -48, -1: b"\x00" * 100})
    assert described == {
        "keyType": "AKP (7)",
        "parameterSet": "ML-DSA-44",
        "publicKeyBytes": 100,
        "publicKeyBytesExpected": 1312,
    }


def test_an_akp_key_reads_json_safe_string_labels_and_base64url_values():
    described = binary._describe_cose_key({"1": 7, "3": -49, "-1": "AAEC"})
    assert described["parameterSet"] == "ML-DSA-65"
    assert described["publicKeyBytes"] == 3


def test_an_akp_key_without_an_ml_dsa_algorithm_names_no_parameter_set():
    described = binary._describe_cose_key({1: 7, 3: -7, -1: b"\x01\x02"})
    assert described == {"keyType": "AKP (7)", "publicKeyBytes": 2}


def test_okp_keys_and_unregistered_values_are_named_without_guessing():
    assert binary._describe_cose_key({1: 1, 3: -8, -1: 6, -2: b"\x00" * 32}) == {
        "keyType": "OKP (1)",
        "curve": "Ed25519 (6)",
    }
    assert binary._describe_cose_key({1: 2, -1: 99}) == {"keyType": "EC2 (2)", "curve": "COSE crv 99"}
    assert binary._describe_cose_key({1: 42}) == {"keyType": "COSE kty 42"}
    assert binary._describe_cose_key({3: -7}) == {}
    assert binary._describe_cose_key("not a key") == {}


def test_key_parameters_of_the_wrong_type_are_left_undescribed():
    assert binary._describe_cose_key({1: True}) == {}
    assert binary._describe_cose_key({1: "seven"}) == {}
    assert binary._describe_cose_key({1: "7", 3: "-48", -1: 5}) == {"keyType": "AKP (7)", "parameterSet": "ML-DSA-44"}
    assert binary._describe_cose_key({1: 3, -1: None}) == {"keyType": "RSA (3)"}
