from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from fido2.attestation.base import InvalidData, InvalidSignature
from fido2.attestation.tpm import (
    ATTRIBUTES,
    TPM_ALG_NULL,
    TPM_GENERATED_VALUE,
    TPM_ST_ATTEST_CERTIFY,
    TpmiAlgKdf,
    TpmAlgAsym,
    TpmAlgHash,
    TpmAttestation,
    TpmAttestationFormat,
    TpmEccCurve,
    TpmPublicFormat,
    TpmRsaScheme,
    TpmsEccParms,
    TpmsRsaParms,
)
from fido2.utils import ByteBuffer


def _build_attestation_blob(*, safe_value: int) -> bytes:
    return b"".join(
        [
            TPM_GENERATED_VALUE,
            TPM_ST_ATTEST_CERTIFY,
            struct.pack("!H", 0),  # name length
            struct.pack("!H", 0),  # data length
            struct.pack("!Q", 0),  # clock
            struct.pack("!L", 0),  # resetCount
            struct.pack("!L", 0),  # restartCount
            struct.pack("B", safe_value),
            struct.pack("!Q", 1),  # firmwareVersion
            struct.pack("!H", 0),  # attested.name length
            struct.pack("!H", 0),  # attested.qualified_name length
        ]
    )


def _build_tpm_public_rsa_blob(*, attributes: int, modulus: bytes, exponent: int) -> bytes:
    return b"".join(
        [
            struct.pack("!H", int(TpmAlgAsym.RSA)),
            struct.pack("!H", int(TpmAlgHash.SHA256)),
            struct.pack("!L", attributes),
            struct.pack("!H", 0),  # auth_policy length
            struct.pack("!H", TPM_ALG_NULL),  # symmetric
            struct.pack("!H", TPM_ALG_NULL),  # scheme
            struct.pack("!H", len(modulus) * 8),  # key_bits
            struct.pack("!L", exponent),
            struct.pack("!H", len(modulus)),
            modulus,
        ]
    )


def _build_tpm_public_ecc_blob(*, attributes: int, x_bytes: bytes, y_bytes: bytes) -> bytes:
    return b"".join(
        [
            struct.pack("!H", int(TpmAlgAsym.ECC)),
            struct.pack("!H", int(TpmAlgHash.SHA256)),
            struct.pack("!L", attributes),
            struct.pack("!H", 0),  # auth_policy length
            struct.pack("!H", TPM_ALG_NULL),  # symmetric
            struct.pack("!H", TPM_ALG_NULL),  # scheme
            struct.pack("!H", int(TpmEccCurve.NIST_P256)),
            struct.pack("!H", int(TpmiAlgKdf.NULL)),
            struct.pack("!H", len(x_bytes)),
            x_bytes,
            struct.pack("!H", len(y_bytes)),
            y_bytes,
        ]
    )


def test_tpm_hash_algorithm_dispatch_and_defensive_unknown_self():
    assert isinstance(TpmAlgHash.SHA1._hash_alg(), hashes.SHA1)
    assert isinstance(TpmAlgHash.SHA256._hash_alg(), hashes.SHA256)
    assert isinstance(TpmAlgHash.SHA384._hash_alg(), hashes.SHA384)
    assert isinstance(TpmAlgHash.SHA512._hash_alg(), hashes.SHA512)

    with pytest.raises(NotImplementedError):
        TpmAlgHash._hash_alg(object())  # type: ignore[arg-type]


def test_tpm_attestation_parser_rejects_invalid_safe_boolean_value():
    with pytest.raises(ValueError, match="invalid value 0x2 for boolean"):
        TpmAttestationFormat.parse(_build_attestation_blob(safe_value=2))


@pytest.mark.parametrize(
    "attributes,scheme,error_pattern",
    [
        (
            int(ATTRIBUTES.SIGN_ENCRYPT),
            int(TpmRsaScheme.OAEP),
            "unrestricted signing key",
        ),
        (
            int(ATTRIBUTES.RESTRICTED | ATTRIBUTES.SIGN_ENCRYPT),
            int(TpmRsaScheme.RSAES),
            "restricted signing key",
        ),
        (
            int(ATTRIBUTES.DECRYPT),
            int(TpmRsaScheme.RSASSA),
            "unrestricted decryption key",
        ),
        (
            int(ATTRIBUTES.RESTRICTED | ATTRIBUTES.DECRYPT),
            int(TpmRsaScheme.RSAPSS),
            "restricted decryption key",
        ),
    ],
)
def test_tpms_rsa_parms_rejects_schemes_not_allowed_for_key_usage(
    attributes: int,
    scheme: int,
    error_pattern: str,
):
    reader = ByteBuffer(struct.pack("!HHHL", TPM_ALG_NULL, scheme, 2048, 65537))
    with pytest.raises(ValueError, match=error_pattern):
        TpmsRsaParms.parse(reader, attributes)


def test_tpms_rsa_parms_requires_null_symmetric_for_non_restricted_decryption_keys():
    reader = ByteBuffer(
        struct.pack(
            "!HHHL",
            0x0001,
            int(TpmRsaScheme.RSASSA),
            2048,
            65537,
        )
    )

    with pytest.raises(ValueError, match="symmetric is expected to be NULL"):
        TpmsRsaParms.parse(reader, int(ATTRIBUTES.SIGN_ENCRYPT))


def test_tpms_rsa_parms_defaults_zero_exponent_to_65537():
    reader = ByteBuffer(
        struct.pack(
            "!HHHL",
            TPM_ALG_NULL,
            TPM_ALG_NULL,
            2048,
            0,
        )
    )

    parsed = TpmsRsaParms.parse(reader, int(ATTRIBUTES.SIGN_ENCRYPT))
    assert parsed.key_bits == 2048
    assert parsed.exponent == 65537


def test_tpm_ecc_curve_conversion_accepts_nist_and_rejects_unsupported_values():
    assert isinstance(TpmEccCurve.NIST_P256.to_curve(), ec.SECP256R1)

    with pytest.raises(ValueError, match="No such curve"):
        TpmEccCurve.NONE.to_curve()

    with pytest.raises(ValueError, match="curve is not supported"):
        TpmEccCurve.BN_P256.to_curve()


def test_tpms_ecc_parms_enforces_null_symmetric_and_scheme():
    bad_symmetric = ByteBuffer(
        struct.pack("!HHHH", 0x0001, TPM_ALG_NULL, int(TpmEccCurve.NIST_P256), int(TpmiAlgKdf.NULL))
    )
    with pytest.raises(ValueError, match="symmetric is expected to be NULL"):
        TpmsEccParms.parse(bad_symmetric)

    bad_scheme = ByteBuffer(
        struct.pack("!HHHH", TPM_ALG_NULL, 0x0001, int(TpmEccCurve.NIST_P256), int(TpmiAlgKdf.NULL))
    )
    with pytest.raises(ValueError, match="scheme is expected to be NULL"):
        TpmsEccParms.parse(bad_scheme)

    good = ByteBuffer(
        struct.pack(
            "!HHHH",
            TPM_ALG_NULL,
            TPM_ALG_NULL,
            int(TpmEccCurve.NIST_P256),
            int(TpmiAlgKdf.NULL),
        )
    )
    parsed = TpmsEccParms.parse(good)
    assert parsed.curve_id == TpmEccCurve.NIST_P256
    assert parsed.kdf == TpmiAlgKdf.NULL


def test_tpm_public_format_rsa_round_trip_public_key_and_name_prefix():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    public_numbers = private_key.public_key().public_numbers()
    modulus = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")

    payload = _build_tpm_public_rsa_blob(
        attributes=int(ATTRIBUTES.SIGN_ENCRYPT),
        modulus=modulus,
        exponent=public_numbers.e,
    )
    parsed = TpmPublicFormat.parse(payload)

    rebuilt = parsed.public_key()
    assert isinstance(rebuilt, rsa.RSAPublicKey)
    assert rebuilt.public_numbers() == public_numbers

    name = parsed.name()
    assert name[:2] == struct.pack("!H", int(TpmAlgHash.SHA256))
    assert len(name) == 34


def test_tpm_public_format_ecc_round_trip_and_invalid_structural_inputs():
    ecc_private_key = ec.generate_private_key(ec.SECP256R1())
    ecc_numbers = ecc_private_key.public_key().public_numbers()
    x_bytes = ecc_numbers.x.to_bytes(32, "big")
    y_bytes = ecc_numbers.y.to_bytes(32, "big")

    ecc_payload = _build_tpm_public_ecc_blob(attributes=0, x_bytes=x_bytes, y_bytes=y_bytes)
    parsed = TpmPublicFormat.parse(ecc_payload)
    rebuilt = parsed.public_key()
    assert isinstance(rebuilt, ec.EllipticCurvePublicKey)
    assert rebuilt.public_numbers().x == ecc_numbers.x
    assert rebuilt.public_numbers().y == ecc_numbers.y

    invalid_attributes_payload = _build_tpm_public_rsa_blob(
        attributes=1,
        modulus=b"\x11\x33\x55\x77",
        exponent=65537,
    )
    with pytest.raises(ValueError, match="attributes is not formated correctly"):
        TpmPublicFormat.parse(invalid_attributes_payload)

    with pytest.raises(ValueError, match="there should not be any data left in buffer"):
        TpmPublicFormat.parse(ecc_payload + b"\x00")


def test_tpm_attestation_verify_rejects_ecdaa_statements():
    with pytest.raises(NotImplementedError, match="ECDAA not implemented"):
        TpmAttestation().verify({"ecdaaKeyId": b"unsupported"}, None, b"client")


def test_tpm_attestation_verify_wraps_pubarea_parsing_errors(monkeypatch):
    import fido2.attestation.tpm as tpm_module

    class _FakeCertificate:
        def public_key(self):
            return object()

    class _FakeVerifierKey:
        _HASH_ALG = hashes.SHA256()

        def verify(self, *_args, **_kwargs):
            return None

    class _FakeAlgFactory:
        def from_cryptography_key(self, _public_key):
            return _FakeVerifierKey()

    class _FakeCoseKey:
        @staticmethod
        def for_alg(_alg):
            return _FakeAlgFactory()

    monkeypatch.setattr(
        tpm_module.x509,
        "load_der_x509_certificate",
        lambda *_args, **_kwargs: _FakeCertificate(),
    )
    monkeypatch.setattr(tpm_module, "_validate_tpm_cert", lambda _cert: None)
    monkeypatch.setattr(tpm_module, "CoseKey", _FakeCoseKey)
    monkeypatch.setattr(
        tpm_module.TpmPublicFormat,
        "parse",
        staticmethod(lambda _pub_area: (_ for _ in ()).throw(ValueError("bad pubArea"))),
    )

    statement = {
        "alg": -7,
        "x5c": [b"certificate-der"],
        "certInfo": b"cert-info",
        "pubArea": b"bad-pub-area",
        "sig": b"signature",
    }

    with pytest.raises(InvalidData, match="unable to parse pubArea"):
        TpmAttestation().verify(statement, object(), b"client")


def test_tpm_attestation_verify_rejects_pubarea_mismatch(monkeypatch):
    import fido2.attestation.tpm as tpm_module

    class _FakeCertificate:
        def public_key(self):
            return object()

    class _FakeVerifierKey:
        _HASH_ALG = hashes.SHA256()

        def verify(self, *_args, **_kwargs):
            return None

    class _FakeAlgFactory:
        def from_cryptography_key(self, _public_key):
            return _FakeVerifierKey()

    class _FakeCoseKey:
        @staticmethod
        def for_alg(_alg):
            return _FakeAlgFactory()

    class _FakePubArea:
        def public_key(self):
            return object()

        def name(self):
            return b"ignored"

    class _CredentialPublicKey:
        def from_cryptography_key(self, _public_key):
            return {"unexpected": True}

    class _CredentialData:
        public_key = _CredentialPublicKey()

    class _AuthData:
        credential_data = _CredentialData()

        def __add__(self, other):
            return b"auth" + bytes(other)

    monkeypatch.setattr(
        tpm_module.x509,
        "load_der_x509_certificate",
        lambda *_args, **_kwargs: _FakeCertificate(),
    )
    monkeypatch.setattr(tpm_module, "_validate_tpm_cert", lambda _cert: None)
    monkeypatch.setattr(tpm_module, "CoseKey", _FakeCoseKey)
    monkeypatch.setattr(
        tpm_module.TpmPublicFormat,
        "parse",
        staticmethod(lambda _pub_area: _FakePubArea()),
    )

    statement = {
        "alg": -7,
        "x5c": [b"certificate-der"],
        "certInfo": b"cert-info",
        "pubArea": b"pub-area",
        "sig": b"signature",
    }

    with pytest.raises(InvalidSignature, match="pubArea does not match"):
        TpmAttestation().verify(statement, _AuthData(), b"client")


def test_tpm_attestation_verify_maps_signature_failures_to_invalid_signature(monkeypatch):
    import fido2.attestation.tpm as tpm_module

    class _FakeCertificate:
        def public_key(self):
            return object()

    class _FakeVerifierKey:
        _HASH_ALG = hashes.SHA256()

        def verify(self, *_args, **_kwargs):
            raise tpm_module._InvalidSignature()

    class _FakeAlgFactory:
        def from_cryptography_key(self, _public_key):
            return _FakeVerifierKey()

    class _FakeCoseKey:
        @staticmethod
        def for_alg(_alg):
            return _FakeAlgFactory()

    marker = object()

    class _CredentialPublicKey:
        def from_cryptography_key(self, _public_key):
            return marker

        def __eq__(self, other):
            return other is marker

    class _CredentialData:
        public_key = _CredentialPublicKey()

    class _AuthData:
        credential_data = _CredentialData()

        def __add__(self, other):
            return b"auth-data" + bytes(other)

    class _FakePubArea:
        def public_key(self):
            return object()

        def name(self):
            return b"pub-area-name"

    auth_data = _AuthData()
    client_data_hash = b"client-hash"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(auth_data + client_data_hash)
    expected_data = digest.finalize()
    fake_tpm_attestation = SimpleNamespace(
        data=expected_data,
        attested=SimpleNamespace(name=b"pub-area-name"),
    )

    monkeypatch.setattr(
        tpm_module.x509,
        "load_der_x509_certificate",
        lambda *_args, **_kwargs: _FakeCertificate(),
    )
    monkeypatch.setattr(tpm_module, "_validate_tpm_cert", lambda _cert: None)
    monkeypatch.setattr(tpm_module, "CoseKey", _FakeCoseKey)
    monkeypatch.setattr(
        tpm_module.TpmPublicFormat,
        "parse",
        staticmethod(lambda _pub_area: _FakePubArea()),
    )
    monkeypatch.setattr(
        tpm_module.TpmAttestationFormat,
        "parse",
        staticmethod(lambda _cert_info: fake_tpm_attestation),
    )

    statement = {
        "alg": -7,
        "x5c": [b"certificate-der"],
        "certInfo": b"cert-info",
        "pubArea": b"pub-area",
        "sig": b"signature",
    }

    with pytest.raises(InvalidSignature, match="signature of certInfo does not match"):
        TpmAttestation().verify(statement, auth_data, client_data_hash)