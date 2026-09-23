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
