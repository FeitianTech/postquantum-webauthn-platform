"""Read the TPM structures in a "tpm" attestation statement, field by field.

WebAuthn L3 section 8.3 names them, with the sections of [TPMv2-Part2] (TPM 2.0
Library, Part 2: Structures) that define them:

* certInfo is a TPMS_ATTEST (section 10.12.8), whose attested member is a
  TPMS_CERTIFY_INFO (section 10.12.3) when its type is TPM_ST_ATTEST_CERTIFY;
* pubArea is a TPMT_PUBLIC (section 12.2.4).

Every read is bounds-checked. Bytes that run out are reported with the offset
(counted from the start of that structure) and the field that needed them, and
what was read before is kept; nothing raises, nothing is guessed. Values are
shown and named, never checked: magic and type are named, not required.

The numbers come from fido2's TPM attestation verifier (``fido2.attestation.tpm``)
where it has them, so the decoder names a value the way the verifier reads it;
the rest of TPM_ALG_ID, TPM_ST and TPM_ECC_CURVE is added from Part 2
(revision 01.38, the one fido2 cites), sections 6.3, 6.9 and 6.4.
"""
from __future__ import annotations

from typing import Any

from fido2.attestation.tpm import (
    ATTRIBUTES,
    TPM_ALG_NULL,
    TPM_GENERATED_VALUE,
    TPM_ST_ATTEST_CERTIFY,
    TpmAlgAsym,
    TpmAlgHash,
    TpmEccCurve,
    TpmiAlgKdf,
    TpmRsaScheme,
)

# TPM_ALG_ID, Part 2 section 6.3: fido2's values, then the rest of the table.
ALGORITHMS: dict[int, str] = {
    **{int(alg): f"TPM_ALG_{alg.name}" for alg in (*TpmAlgAsym, *TpmAlgHash, *TpmRsaScheme, *TpmiAlgKdf)},
    TPM_ALG_NULL: "TPM_ALG_NULL",
    0x0003: "TPM_ALG_TDES",
    0x0005: "TPM_ALG_HMAC",
    0x0006: "TPM_ALG_AES",
    0x0007: "TPM_ALG_MGF1",
    0x0008: "TPM_ALG_KEYEDHASH",
    0x000A: "TPM_ALG_XOR",
    0x0012: "TPM_ALG_SM3_256",
    0x0013: "TPM_ALG_SM4",
    0x0018: "TPM_ALG_ECDSA",
    0x0019: "TPM_ALG_ECDH",
    0x001A: "TPM_ALG_ECDAA",
    0x001B: "TPM_ALG_SM2",
    0x001C: "TPM_ALG_ECSCHNORR",
    0x001D: "TPM_ALG_ECMQV",
    0x0025: "TPM_ALG_SYMCIPHER",
    0x0026: "TPM_ALG_CAMELLIA",
    0x0027: "TPM_ALG_SHA3_256",
    0x0028: "TPM_ALG_SHA3_384",
    0x0029: "TPM_ALG_SHA3_512",
    0x0040: "TPM_ALG_CTR",
    0x0041: "TPM_ALG_OFB",
    0x0042: "TPM_ALG_CBC",
    0x0043: "TPM_ALG_CFB",
    0x0044: "TPM_ALG_ECB",
}

# TPM_ST, Part 2 section 6.9: the attestation structure tags.
ATTEST_TYPES: dict[int, str] = {
    0x8014: "TPM_ST_ATTEST_NV",
    0x8015: "TPM_ST_ATTEST_COMMAND_AUDIT",
    0x8016: "TPM_ST_ATTEST_SESSION_AUDIT",
    int.from_bytes(TPM_ST_ATTEST_CERTIFY, "big"): "TPM_ST_ATTEST_CERTIFY",
    0x8018: "TPM_ST_ATTEST_QUOTE",
    0x8019: "TPM_ST_ATTEST_TIME",
    0x801A: "TPM_ST_ATTEST_CREATION",
}

# TPM_ECC_CURVE, Part 2 section 6.4.
CURVES: dict[int, str] = {int(curve): f"TPM_ECC_{curve.name}" for curve in TpmEccCurve}

# TPMA_OBJECT, Part 2 section 8.3: the bits fido2 names, by their Part 2 names.
OBJECT_ATTRIBUTES: dict[int, str] = {
    ATTRIBUTES.FIXED_TPM: "fixedTPM",
    ATTRIBUTES.ST_CLEAR: "stClear",
    ATTRIBUTES.FIXED_PARENT: "fixedParent",
    ATTRIBUTES.SENSITIVE_DATA_ORIGIN: "sensitiveDataOrigin",
    ATTRIBUTES.USER_WITH_AUTH: "userWithAuth",
    ATTRIBUTES.ADMIN_WITH_POLICY: "adminWithPolicy",
    ATTRIBUTES.NO_DA: "noDA",
    ATTRIBUTES.ENCRYPTED_DUPLICATION: "encryptedDuplication",
    ATTRIBUTES.RESTRICTED: "restricted",
    ATTRIBUTES.DECRYPT: "decrypt",
    ATTRIBUTES.SIGN_ENCRYPT: "sign",
}

_GENERATED_VALUE = int.from_bytes(TPM_GENERATED_VALUE, "big")
_ECDAA = 0x001A


class _Truncated(Exception):
    def __init__(self, field: str, needed: int, remaining: int, offset: int) -> None:
        super().__init__(field)
        self.field, self.needed, self.remaining, self.offset = field, needed, remaining, offset


class _Reader:
    """Big-endian reads that never run past the end of ``data``."""

    def __init__(self, data: bytes, structure: str) -> None:
        self.data, self.structure, self.offset = data, structure, 0

    def take(self, count: int, field: str) -> bytes:
        remaining = len(self.data) - self.offset
        if count > remaining:
            raise _Truncated(f"{self.structure}.{field}", count, remaining, self.offset)
        chunk = self.data[self.offset : self.offset + count]
        self.offset += count
        return chunk

    def uint(self, size: int, field: str) -> int:
        return int.from_bytes(self.take(size, field), "big")

    def sized(self, field: str) -> bytes:
        """A TPM2B: a UINT16 size, then that many bytes."""

        return self.take(self.uint(2, f"{field}.size"), field)

    def rest(self) -> bytes:
        chunk = self.data[self.offset :]
        self.offset = len(self.data)
        return chunk


def _named(value: int, names: dict[int, str], width: int = 4) -> dict[str, Any]:
    name = names.get(value)
    return {"value": f"0x{value:0{width}x}", "meaning": name or "not a value this decoder names"}


def _algorithm(reader: _Reader, field: str) -> tuple[int, dict[str, Any]]:
    value = reader.uint(2, field)
    return value, _named(value, ALGORITHMS)


def _name(data: bytes) -> dict[str, Any]:
    """A TPM2B_NAME's content: a 4-byte handle, or a nameAlg and its digest (TPMU_NAME)."""

    view: dict[str, Any] = {"size": len(data), "hex": data.hex()}
    if len(data) == 4:
        view["handle"] = f"0x{data.hex()}"
    elif len(data) > 2:
        view["nameAlg"] = _named(int.from_bytes(data[:2], "big"), ALGORITHMS)
        view["digest"] = data[2:].hex()
    return view


def _finish(view: dict[str, Any], reader: _Reader, read) -> dict[str, Any]:
    try:
        read(reader, view)
    except _Truncated as exc:
        view["error"] = {
            "offset": exc.offset,
            "field": exc.field,
            "message": f"{exc.field} needs {exc.needed} byte(s); {exc.remaining} remain at offset {exc.offset}",
        }
        return view
    trailing = reader.rest()
    if trailing:
        view["trailing"] = {
            "offset": len(reader.data) - len(trailing),
            "length": len(trailing),
            "hex": trailing.hex(),
            "note": f"bytes after the {reader.structure.split('.')[-1]} structure",
        }
    return view


# -- TPMS_ATTEST --------------------------------------------------------------


def read_tpms_attest(data: bytes, structure: str = "certInfo") -> dict[str, Any]:
    return _finish({"structure": "TPMS_ATTEST ([TPMv2-Part2] section 10.12.8)"}, _Reader(data, structure), _attest)


def _attest(reader: _Reader, view: dict[str, Any]) -> None:
    magic = reader.uint(4, "magic")
    view["magic"] = {
        "value": f"0x{magic:08x}",
        "meaning": "TPM_GENERATED_VALUE" if magic == _GENERATED_VALUE else "not TPM_GENERATED_VALUE (0xff544347)",
    }
    attest_type = reader.uint(2, "type")
    view["type"] = _named(attest_type, ATTEST_TYPES)
    view["qualifiedSigner"] = _name(reader.sized("qualifiedSigner"))
    extra_data = reader.sized("extraData")
    view["extraData"] = {
        "size": len(extra_data),
        "hex": extra_data.hex(),
        "note": "WebAuthn L3 section 8.3: the hash of authenticatorData || clientDataHash under alg; not checked",
    }
    view["clockInfo"] = clock = {}
    clock["clock"] = reader.uint(8, "clockInfo.clock")
    clock["resetCount"] = reader.uint(4, "clockInfo.resetCount")
    clock["restartCount"] = reader.uint(4, "clockInfo.restartCount")
    safe = reader.uint(1, "clockInfo.safe")
    clock["safe"] = {0: False, 1: True}.get(safe, f"0x{safe:02x} (a TPMI_YES_NO is 0 or 1)")
    firmware = reader.uint(8, "firmwareVersion")
    view["firmwareVersion"] = {"value": firmware, "hex": f"0x{firmware:016x}"}
    if attest_type == int.from_bytes(TPM_ST_ATTEST_CERTIFY, "big"):
        view["attested"] = {
            "structure": "TPMS_CERTIFY_INFO ([TPMv2-Part2] section 10.12.3)",
            "name": _name(reader.sized("attested.name")),
            "qualifiedName": _name(reader.sized("attested.qualifiedName")),
            "note": "WebAuthn L3 section 8.3: name is pubArea's Name under its nameAlg; not checked",
        }
    else:
        rest = reader.rest()
        view["attested"] = {"hex": rest.hex(), "note": "not decoded: type is not TPM_ST_ATTEST_CERTIFY"}


# -- TPMT_PUBLIC --------------------------------------------------------------


def read_tpmt_public(data: bytes, structure: str = "pubArea") -> dict[str, Any]:
    return _finish({"structure": "TPMT_PUBLIC ([TPMv2-Part2] section 12.2.4)"}, _Reader(data, structure), _public)


def _public(reader: _Reader, view: dict[str, Any]) -> None:
    key_type, view["type"] = _algorithm(reader, "type")
    _name_alg, view["nameAlg"] = _algorithm(reader, "nameAlg")
    attributes = reader.uint(4, "objectAttributes")
    known = sum(OBJECT_ATTRIBUTES)
    view["objectAttributes"] = {
        "value": f"0x{attributes:08x}",
        "set": [name for bit, name in OBJECT_ATTRIBUTES.items() if attributes & bit],
    }
    if attributes & ~known:
        view["objectAttributes"]["otherBits"] = f"0x{attributes & ~known:08x}"
    policy = reader.sized("authPolicy")
    view["authPolicy"] = {"size": len(policy), "hex": policy.hex()}
    if key_type == TpmAlgAsym.RSA:
        view["parameters"] = _rsa_parameters(reader)
        modulus = reader.sized("unique")
        view["unique"] = {"structure": "TPM2B_PUBLIC_KEY_RSA", "size": len(modulus), "n": modulus.hex()}
    elif key_type == TpmAlgAsym.ECC:
        view["parameters"] = _ecc_parameters(reader)
        x = reader.sized("unique.x")
        y = reader.sized("unique.y")
        view["unique"] = {"structure": "TPMS_ECC_POINT", "x": x.hex(), "y": y.hex()}
    else:
        rest = reader.rest()
        view["parametersAndUnique"] = {"hex": rest.hex(), "note": "not decoded: type is neither TPM_ALG_RSA nor TPM_ALG_ECC"}


def _symmetric(reader: _Reader) -> dict[str, Any]:
    algorithm, view = _algorithm(reader, "parameters.symmetric.algorithm")
    if algorithm != TPM_ALG_NULL:
        view["keyBits"] = reader.uint(2, "parameters.symmetric.keyBits")
        _mode, view["mode"] = _algorithm(reader, "parameters.symmetric.mode")
    return view


def _scheme(reader: _Reader, field: str) -> dict[str, Any]:
    scheme, view = _algorithm(reader, f"parameters.{field}.scheme")
    if scheme != TPM_ALG_NULL:
        _hash, view["hashAlg"] = _algorithm(reader, f"parameters.{field}.details.hashAlg")
        if scheme == _ECDAA:
            view["count"] = reader.uint(2, f"parameters.{field}.details.count")
    return view


def _rsa_parameters(reader: _Reader) -> dict[str, Any]:
    view: dict[str, Any] = {"structure": "TPMS_RSA_PARMS"}
    view["symmetric"] = _symmetric(reader)
    view["scheme"] = _scheme(reader, "scheme")
    view["keyBits"] = reader.uint(2, "parameters.keyBits")
    exponent = reader.uint(4, "parameters.exponent")
    view["exponent"] = {"value": exponent}
    if exponent == 0:
        view["exponent"]["meaning"] = "0: the default exponent, 65537"
    return view


def _ecc_parameters(reader: _Reader) -> dict[str, Any]:
    view: dict[str, Any] = {"structure": "TPMS_ECC_PARMS"}
    view["symmetric"] = _symmetric(reader)
    view["scheme"] = _scheme(reader, "scheme")
    view["curveID"] = _named(reader.uint(2, "parameters.curveID"), CURVES)
    view["kdf"] = _scheme(reader, "kdf")
    return view
