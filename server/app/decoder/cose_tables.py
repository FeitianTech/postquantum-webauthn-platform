"""The COSE registries the decoder and the encoder share.

Read off the IANA "CBOR Object Signing and Encryption (COSE)" registries
(https://www.iana.org/assignments/cose): "COSE Key Types" and "COSE Elliptic
Curves". COSE algorithm names are not kept here: ``webauthn/pqc.py``'s
``describe_algorithm`` is the one place that names them.
"""
from __future__ import annotations

# "COSE Key Types". 7 is AKP (RFC 9964), the algorithm key pair type ML-DSA keys
# use: the parameter set comes from alg (3), the key from pub (-1).
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

# Key parameters, label -> (name, CBOR type). Common to every key type: RFC 9052
# section 7.1, Table 4 ("Key Map Labels").
COMMON_PARAMETERS: dict[int, tuple[str, str]] = {
    1: ("kty", "int / tstr"),
    2: ("kid", "bstr"),
    3: ("alg", "int / tstr"),
    4: ("key_ops", "[+ (int / tstr)]"),
    5: ("Base IV", "bstr"),
}

# Per key type, from "COSE Key Type Parameters".
KEY_TYPE_PARAMETERS: dict[int, dict[int, tuple[str, str]]] = {
    # OKP: RFC 9053 section 7.2, Table 20.
    1: {-1: ("crv", "int / tstr"), -2: ("x", "bstr"), -4: ("d", "bstr")},
    # EC2: RFC 9053 section 7.1.1, Table 19.
    2: {-1: ("crv", "int / tstr"), -2: ("x", "bstr"), -3: ("y", "bstr / bool"), -4: ("d", "bstr")},
    # RSA: RFC 8230 section 4, Table 4. -9 (other) is an array of maps, one per
    # extra prime; -10 to -12 are that map's labels.
    3: {
        -1: ("n", "bstr"),
        -2: ("e", "bstr"),
        -3: ("d", "bstr"),
        -4: ("p", "bstr"),
        -5: ("q", "bstr"),
        -6: ("dP", "bstr"),
        -7: ("dQ", "bstr"),
        -8: ("qInv", "bstr"),
        -9: ("other", "[+ COSE_KeyOtherPrimes]"),
        -10: ("r_i", "bstr"),
        -11: ("d_i", "bstr"),
        -12: ("t_i", "bstr"),
    },
    # Symmetric: RFC 9053 section 7.3, Table 21.
    4: {-1: ("k", "bstr")},
    # AKP, the algorithm key pair type ML-DSA keys use: RFC 9964, as IANA lists it.
    7: {-1: ("pub", "bstr"), -2: ("priv", "bstr")},
}
