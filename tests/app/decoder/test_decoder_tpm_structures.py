"""certInfo and pubArea are read field by field, with bounds checks and located errors.

The real vector is the Windows Hello TPM attestation from
tests/fido2/attestation/test_attestation.py:95 (certInfo 161 bytes, pubArea
310 bytes). WebAuthn L3 section 8.3 says what they are: a TPMS_ATTEST and a
TPMT_PUBLIC, from TPM 2.0 Part 2.
"""
from __future__ import annotations

import cbor2
import pytest

from server.app.decoder.decode import tpm_structures
from tests.app.decoder.real_vectors import (
    TPM_WINDOWS_HELLO_ATT_STMT,
    TPM_WINDOWS_HELLO_AUTH_DATA,
)

_CERT_INFO = TPM_WINDOWS_HELLO_ATT_STMT["certInfo"]
_PUB_AREA = TPM_WINDOWS_HELLO_ATT_STMT["pubArea"]


def test_the_real_cert_info_is_a_tpms_attest_of_type_certify():
    view = tpm_structures.read_tpms_attest(_CERT_INFO)

    assert "error" not in view and "trailing" not in view
    assert view["magic"] == {"value": "0xff544347", "meaning": "TPM_GENERATED_VALUE"}
    assert view["type"] == {"value": "0x8017", "meaning": "TPM_ST_ATTEST_CERTIFY"}
    assert view["qualifiedSigner"]["nameAlg"]["meaning"] == "TPM_ALG_SHA256"
    assert view["qualifiedSigner"]["digest"] == "68cec627cc6411099a1f809fde4379f649aa170c7072d1adf230de439efc8081"
    # alg -65535 is RS1, so extraData is a 20-byte SHA-1 digest.
    assert view["extraData"]["size"] == 20
    assert view["extraData"]["hex"] == "f7c8b0cdeb31328648130a19733d6fff16e76e13"
    assert view["clockInfo"] == {
        "clock": 16900969987,
        "resetCount": 1148115141,
        "restartCount": 1789354125,
        "safe": True,
    }
    assert view["firmwareVersion"]["hex"] == "0xa6ea5651ee67a8a2"
    attested = view["attested"]
    assert attested["name"]["digest"] == "df681917e18529c61e1b85a1e7952f3201eb59c609ed5d8e217e5de76b228bbd"
    assert attested["qualifiedName"]["nameAlg"]["meaning"] == "TPM_ALG_SHA256"


def test_the_real_pub_area_is_the_credentials_rsa_key():
    view = tpm_structures.read_tpmt_public(_PUB_AREA)

    assert "error" not in view and "trailing" not in view
    assert view["type"]["meaning"] == "TPM_ALG_RSA"
    assert view["nameAlg"]["meaning"] == "TPM_ALG_SHA256"
    assert view["objectAttributes"] == {
        "value": "0x00060472",
        "set": ["fixedTPM", "fixedParent", "sensitiveDataOrigin", "userWithAuth", "noDA", "decrypt", "sign"],
    }
    assert view["authPolicy"]["size"] == 32
    parameters = view["parameters"]
    assert parameters["symmetric"]["meaning"] == "TPM_ALG_NULL"
    assert parameters["scheme"]["meaning"] == "TPM_ALG_NULL"
    assert parameters["keyBits"] == 2048
    assert parameters["exponent"] == {"value": 0, "meaning": "0: the default exponent, 65537"}
    # The modulus is the one in the credential public key of the same attestation.
    id_length = int.from_bytes(TPM_WINDOWS_HELLO_AUTH_DATA[53:55], "big")
    cose_key = cbor2.loads(TPM_WINDOWS_HELLO_AUTH_DATA[55 + id_length :])
    assert view["unique"]["n"] == cose_key[-1].hex()


@pytest.mark.parametrize(
    ("read", "data"),
    [(tpm_structures.read_tpms_attest, _CERT_INFO), (tpm_structures.read_tpmt_public, _PUB_AREA)],
)
def test_every_truncation_is_located_and_never_raises(read, data):
    for length in range(len(data)):
        view = read(data[:length])
        error = view["error"]
        assert 0 <= error["offset"] <= length
        assert error["field"].split(".")[0] in ("certInfo", "pubArea")
        assert "remain at offset" in error["message"]


def test_a_truncated_field_names_itself_and_keeps_what_came_before():
    view = tpm_structures.read_tpms_attest(_CERT_INFO[:50])

    assert view["error"] == {
        "offset": 44,
        "field": "certInfo.extraData",
        "message": "certInfo.extraData needs 20 byte(s); 6 remain at offset 44",
    }
    assert view["qualifiedSigner"]["size"] == 34
    assert "clockInfo" not in view


def test_bytes_after_a_structure_are_reported():
    view = tpm_structures.read_tpmt_public(_PUB_AREA + b"\xaa\xbb")

    assert view["trailing"] == {"offset": 310, "length": 2, "hex": "aabb", "note": "bytes after the pubArea structure"}


def test_values_are_named_not_required():
    data = bytearray(_CERT_INFO)
    data[0:4] = b"\x00\x00\x00\x00"  # magic
    data[4:6] = b"\x80\x18"  # TPM_ST_ATTEST_QUOTE
    data[4 + 2 + 2 + 34 + 2 + 20 + 8 + 4 + 4] = 7  # clockInfo.safe

    view = tpm_structures.read_tpms_attest(bytes(data))

    assert view["magic"]["meaning"] == "not TPM_GENERATED_VALUE (0xff544347)"
    assert view["type"]["meaning"] == "TPM_ST_ATTEST_QUOTE"
    assert view["clockInfo"]["safe"] == "0x07 (a TPMI_YES_NO is 0 or 1)"
    assert view["attested"]["note"] == "not decoded: type is not TPM_ST_ATTEST_CERTIFY"


def _ecc_pub_area(*, symmetric: bytes, scheme: bytes, kdf: bytes) -> bytes:
    return (
        b"\x00\x23"  # TPM_ALG_ECC
        + b"\x00\x0b"  # nameAlg SHA256
        + (0x00040072 | 0x00080000).to_bytes(4, "big")  # sign, ..., and a bit fido2 does not name
        + b"\x00\x00"  # empty authPolicy
        + symmetric
        + scheme
        + b"\x00\x03"  # TPM_ECC_NIST_P256
        + kdf
        + b"\x00\x20" + bytes(32)
        + b"\x00\x20" + bytes(range(32))
    )


def test_an_ecc_pub_area_with_schemes_that_carry_details():
    data = _ecc_pub_area(
        symmetric=b"\x00\x06" + b"\x00\x80" + b"\x00\x43",  # AES, 128 bits, CFB
        scheme=b"\x00\x1a" + b"\x00\x0b" + b"\x00\x01",  # ECDAA, SHA256, count 1
        kdf=b"\x00\x20" + b"\x00\x0b",  # KDF1_SP800_56A, SHA256
    )

    view = tpm_structures.read_tpmt_public(data)
    parameters = view["parameters"]

    assert "error" not in view and "trailing" not in view
    assert parameters["symmetric"] == {
        "value": "0x0006",
        "meaning": "TPM_ALG_AES",
        "keyBits": 128,
        "mode": {"value": "0x0043", "meaning": "TPM_ALG_CFB"},
    }
    assert parameters["scheme"]["meaning"] == "TPM_ALG_ECDAA"
    assert parameters["scheme"]["count"] == 1
    assert parameters["curveID"]["meaning"] == "TPM_ECC_NIST_P256"
    assert parameters["kdf"]["hashAlg"]["meaning"] == "TPM_ALG_SHA256"
    assert view["unique"]["y"] == bytes(range(32)).hex()
    assert view["objectAttributes"]["otherBits"] == "0x00080000"


def test_an_ecdsa_scheme_carries_only_its_hash():
    data = _ecc_pub_area(symmetric=b"\x00\x10", scheme=b"\x00\x18\x00\x0b", kdf=b"\x00\x10")

    view = tpm_structures.read_tpmt_public(data)

    assert view["parameters"]["scheme"] == {
        "value": "0x0018",
        "meaning": "TPM_ALG_ECDSA",
        "hashAlg": {"value": "0x000b", "meaning": "TPM_ALG_SHA256"},
    }


def test_a_key_type_it_does_not_read_is_shown_as_hex():
    view = tpm_structures.read_tpmt_public(b"\x00\x08\x00\x0b" + bytes(4) + b"\x00\x00" + b"\xde\xad")

    assert view["type"]["meaning"] == "TPM_ALG_KEYEDHASH"
    assert view["parametersAndUnique"]["hex"] == "dead"


def test_a_four_byte_name_is_a_handle_and_unknown_values_are_said_to_be():
    name = tpm_structures._name(b"\x81\x00\x00\x01")
    assert name["handle"] == "0x81000001"
    assert tpm_structures._named(0x9999, tpm_structures.ALGORITHMS)["meaning"] == "not a value this decoder names"
