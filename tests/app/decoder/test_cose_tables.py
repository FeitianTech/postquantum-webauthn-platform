"""One set of COSE registries, read by the decoder and the encoder alike."""
from __future__ import annotations

from server.app.decoder import cose_tables
from server.app.decoder.decode import binary


def test_the_iana_cose_key_types_and_curves():
    # IANA "COSE Key Types" and "COSE Elliptic Curves".
    assert cose_tables.KEY_TYPES == {
        1: "OKP",
        2: "EC2",
        3: "RSA",
        4: "Symmetric",
        5: "HSS-LMS",
        6: "WalnutDSA",
        7: "AKP",
    }
    assert cose_tables.CURVES == {
        1: "P-256",
        2: "P-384",
        3: "P-521",
        4: "X25519",
        5: "X448",
        6: "Ed25519",
        7: "Ed448",
        8: "secp256k1",
    }


def test_the_decoder_reads_the_shared_registries_not_a_copy():
    assert binary._COSE_KEY_TYPES is cose_tables.KEY_TYPES
    assert binary._COSE_CURVES is cose_tables.CURVES
