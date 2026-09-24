"""The COSE registries the decoder and the encoder share.

Read off the IANA "CBOR Object Signing and Encryption (COSE)" registries
(https://www.iana.org/assignments/cose): "COSE Key Types" and "COSE Elliptic
Curves". COSE algorithm names are not kept here: ``webauthn/pqc.py``'s
``describe_algorithm`` is the one place that names them.
"""
from __future__ import annotations

# "COSE Key Types". 7 is AKP, the algorithm key pair type ML-DSA keys use: the
# parameter set comes from alg (3), the key from pub (-1).
KEY_TYPES: dict[int, str] = {
    1: "OKP",
    2: "EC2",
    3: "RSA",
    4: "Symmetric",
    5: "HSS-LMS",
    6: "WalnutDSA",
    7: "AKP",
}

# "COSE Elliptic Curves".
CURVES: dict[int, str] = {
    1: "P-256",
    2: "P-384",
    3: "P-521",
    4: "X25519",
    5: "X448",
    6: "Ed25519",
    7: "Ed448",
    8: "secp256k1",
}
