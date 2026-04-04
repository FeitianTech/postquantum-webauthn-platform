from __future__ import annotations

from types import SimpleNamespace

import pytest

from fido2 import cose


def _der_sequence(content: bytes) -> bytes:
    return bytes([0x30, len(content)]) + content


def test_extract_subject_public_key_from_spki_error_branches():
    with pytest.raises(ValueError, match="Empty SubjectPublicKeyInfo"):
        cose._extract_subject_public_key_from_spki(b"")

    with pytest.raises(ValueError, match="length exceeds"):
        cose._extract_subject_public_key_from_spki(b"\x30\x82\x01\x00")

    with pytest.raises(ValueError, match="AlgorithmIdentifier must be present"):
        cose._extract_subject_public_key_from_spki(b"\x30\x00")

    with pytest.raises(ValueError, match="AlgorithmIdentifier overruns"):
        cose._extract_subject_public_key_from_spki(b"\x30\x03\x30\x02\x00")

    with pytest.raises(ValueError, match="must contain a BIT STRING"):
        cose._extract_subject_public_key_from_spki(b"\x30\x04\x30\x00\x05\x00")

    with pytest.raises(ValueError, match="BIT STRING overruns"):
        cose._extract_subject_public_key_from_spki(b"\x30\x05\x30\x00\x03\x02\x00")

    with pytest.raises(ValueError, match="BIT STRING is empty"):
        cose._extract_subject_public_key_from_spki(b"\x30\x04\x30\x00\x03\x00")

    with pytest.raises(ValueError, match="BIT STRING padding"):
        cose._extract_subject_public_key_from_spki(b"\x30\x06\x30\x00\x03\x02\x01\xff")


def test_find_mldsa_der_candidate_depth_truncation_and_bitstring_recursion():
    assert cose._find_mldsa_der_candidate(memoryview(b"\x04\x01A"), 0, 3, 1, depth=0) is None
    assert cose._find_mldsa_der_candidate(memoryview(b""), 0, 1, 1) is None
    assert cose._find_mldsa_der_candidate(memoryview(b"\x04\x82\x01"), 0, 3, 1) is None
    assert cose._find_mldsa_der_candidate(memoryview(b"\x04\x02A"), 0, 3, 1) is None

    candidate = cose._find_mldsa_der_candidate(
        memoryview(b"\x03\x04\x00\x04\x01A"),
        0,
        6,
        1,
    )
    assert candidate == b"A"


def test_unwrap_mldsa_subject_public_key_sequence_and_parameter_set_branches(monkeypatch):
    assert cose._unwrap_mldsa_subject_public_key(b"") == (b"", None)

    unwrapped, original = cose._unwrap_mldsa_subject_public_key(b"\x30\x06\x04\x04ABCD")
    assert unwrapped == b"ABCD"
    assert original == b"\x30\x06\x04\x04ABCD"

    malformed, wrapped = cose._unwrap_mldsa_subject_public_key(b"\x30\x82")
    assert malformed == b"\x30\x82"
    assert wrapped is None

    monkeypatch.setattr(
        cose,
        "_get_mldsa_parameter_details",
        lambda _parameter_set: {"public_key_length": 4},
        raising=False,
    )
    monkeypatch.setattr(
        cose,
        "_find_mldsa_der_candidate",
        lambda _view, _start, _end, _expected: b"WXYZ",
        raising=False,
    )

    candidate, wrapped_candidate = cose._unwrap_mldsa_subject_public_key(
        b"not-four-bytes",
        "ML-DSA-65",
    )
    assert candidate == b"WXYZ"
    assert wrapped_candidate == b"not-four-bytes"


def test_parse_der_integer_and_spki_algorithm_error_branches():
    with pytest.raises(ValueError, match="cannot be negative"):
        cose._parse_der_integer(memoryview(b"\x02\x01\x80"), 0)

    with pytest.raises(ValueError, match="Non-canonical"):
        cose._parse_der_integer(memoryview(b"\x02\x02\x00\x7f"), 0)

    with pytest.raises(ValueError, match="SEQUENCE"):
        cose._parse_spki_algorithm_info(b"\x31\x00")

    with pytest.raises(ValueError, match="length exceeds"):
        cose._parse_spki_algorithm_info(b"\x30\x82\x01\x00")

    with pytest.raises(ValueError, match="missing AlgorithmIdentifier"):
        cose._parse_spki_algorithm_info(b"\x30\x00")

    with pytest.raises(ValueError, match="AlgorithmIdentifier overruns"):
        cose._parse_spki_algorithm_info(b"\x30\x03\x30\x02\x00")

    oid, params = cose._parse_spki_algorithm_info(b"\x30\x05\x30\x03\x06\x01\x2a")
    assert oid == "1.2"
    assert params is None


def test_get_mldsa_parameter_details_and_oid_name_fallback_branches(monkeypatch):
    class _FakeSignature:
        def __init__(self, details):
            self.details = details

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    fake_module_pk_only = SimpleNamespace(
        Signature=lambda _name: _FakeSignature({"length_public_key": 111, "length_signature": 0})
    )
    monkeypatch.setattr(cose, "_get_optional_oqs", lambda: fake_module_pk_only, raising=False)

    only_pk = cose._get_mldsa_parameter_details("CUSTOM")
    assert only_pk["public_key_length"] == 111
    assert "signature_length" not in only_pk

    fake_module_sig_only = SimpleNamespace(
        Signature=lambda _name: _FakeSignature({"length_public_key": 0, "length_signature": 222})
    )
    monkeypatch.setattr(cose, "_get_optional_oqs", lambda: fake_module_sig_only, raising=False)

    only_sig = cose._get_mldsa_parameter_details("CUSTOM")
    assert only_sig["signature_length"] == 222
    assert "public_key_length" not in only_sig

    assert cose.describe_mldsa_oid(None) is None

    monkeypatch.setattr(
        cose,
        "describe_mldsa_oid",
        lambda _oid: {"display": " ", "mlDsaParameterSet": " ", "name": "FallbackName"},
        raising=False,
    )
    assert cose.describe_mldsa_oid_name("2.16.840.1.101.3.4.3.18") == "FallbackName"

    monkeypatch.setattr(
        cose,
        "describe_mldsa_oid",
        lambda _oid: {"display": " ", "mlDsaParameterSet": " ", "name": " "},
        raising=False,
    )
    assert cose.describe_mldsa_oid_name("2.16.840.1.101.3.4.3.18") is None


def test_extract_certificate_signature_info_error_branches():
    with pytest.raises(ValueError, match="length exceeds"):
        cose.extract_certificate_signature_info(b"\x30\x82\x01\x00")

    with pytest.raises(ValueError, match="missing TBSCertificate"):
        cose.extract_certificate_signature_info(b"\x30\x02\x05\x00")

    with pytest.raises(ValueError, match="TBSCertificate overruns"):
        cose.extract_certificate_signature_info(b"\x30\x04\x30\x04\x00\x00")

    with pytest.raises(ValueError, match="missing signatureAlgorithm"):
        cose.extract_certificate_signature_info(b"\x30\x05\x30\x03\x02\x01\x01")

    with pytest.raises(ValueError, match="signatureAlgorithm overruns"):
        cose.extract_certificate_signature_info(b"\x30\x07\x30\x00\x30\x05\x00\x00\x00")

    with pytest.raises(ValueError, match="missing signatureValue"):
        cose.extract_certificate_signature_info(b"\x30\x08\x30\x00\x30\x03\x06\x01\x2a\x05")

    with pytest.raises(ValueError, match="signatureValue overruns"):
        cose.extract_certificate_signature_info(b"\x30\x0a\x30\x00\x30\x03\x06\x01\x2a\x03\x05\x00")

    with pytest.raises(ValueError, match="signatureValue is empty"):
        cose.extract_certificate_signature_info(b"\x30\x09\x30\x00\x30\x03\x06\x01\x2a\x03\x00")

    with pytest.raises(ValueError, match="unused bits"):
        cose.extract_certificate_signature_info(b"\x30\x0a\x30\x00\x30\x03\x06\x01\x2a\x03\x01\x01")


def test_locate_subject_public_key_info_error_branches_and_version_optional_path():
    with pytest.raises(ValueError, match="SEQUENCE"):
        cose._locate_subject_public_key_info_from_tbs(memoryview(b"\x31\x00"))

    with pytest.raises(ValueError, match="missing TBSCertificate"):
        cose._locate_subject_public_key_info_from_tbs(memoryview(b"\x30\x02\x05\x00"))

    with pytest.raises(ValueError, match="TBSCertificate overruns"):
        cose._locate_subject_public_key_info_from_tbs(memoryview(b"\x30\x04\x30\x04\x00\x00"))

    no_spki_tbs = b"\x30\x11\x30\x0f" + (b"\x02\x01\x01" * 5)
    with pytest.raises(ValueError, match="missing subjectPublicKeyInfo"):
        cose._locate_subject_public_key_info_from_tbs(memoryview(no_spki_tbs))


def test_scan_certificate_for_subject_public_key_info_continue_branches():
    with pytest.raises(ValueError, match="Unable to locate"):
        cose._scan_certificate_for_subject_public_key_info(memoryview(b"\x30\x82\x01"))

    with pytest.raises(ValueError, match="Unable to locate"):
        cose._scan_certificate_for_subject_public_key_info(memoryview(_der_sequence(b"\x00")))

    with pytest.raises(ValueError, match="Unable to locate"):
        cose._scan_certificate_for_subject_public_key_info(memoryview(b"\x30\x03\x30\x82\x01"))

    with pytest.raises(ValueError, match="Unable to locate"):
        cose._scan_certificate_for_subject_public_key_info(memoryview(b"\x30\x04\x30\x04\x06\x01"))

    with pytest.raises(ValueError, match="Unable to locate"):
        cose._scan_certificate_for_subject_public_key_info(memoryview(_der_sequence(_der_sequence(b"\x05"))))

    with pytest.raises(ValueError, match="Unable to locate"):
        cose._scan_certificate_for_subject_public_key_info(memoryview(_der_sequence(_der_sequence(b"\x06\x01\x2a") + b"\x05\x00")))

    with pytest.raises(ValueError, match="Unable to locate"):
        cose._scan_certificate_for_subject_public_key_info(memoryview(_der_sequence(_der_sequence(b"\x06\x01\x2a") + b"\x03\x82\x01")))

    with pytest.raises(ValueError, match="Unable to locate"):
        cose._scan_certificate_for_subject_public_key_info(memoryview(_der_sequence(_der_sequence(b"\x06\x01\x2a") + b"\x03\x05\x00")))

    with pytest.raises(ValueError, match="Unable to locate"):
        cose._scan_certificate_for_subject_public_key_info(memoryview(_der_sequence(_der_sequence(b"\x06\x01\x2a") + b"\x03\x02\x01\xaa")))

    with pytest.raises(ValueError, match="Unable to locate"):
        cose._scan_certificate_for_subject_public_key_info(memoryview(_der_sequence(_der_sequence(b"\x06\x01\x2a") + b"\x03\x01\x00")))

    with_params = _der_sequence(_der_sequence(b"\x06\x01\x2a\x05\x00") + b"\x03\x02\x00\xaa")
    spki_der, oid, params, payload = cose._scan_certificate_for_subject_public_key_info(memoryview(with_params))
    assert spki_der == with_params
    assert oid == "1.2"
    assert params == b"\x05\x00"
    assert payload == b"\xaa"


def test_coerce_mldsa_public_key_bytes_spki_and_public_bytes_attempt_branches(monkeypatch):
    monkeypatch.setattr(
        cose,
        "_unwrap_mldsa_subject_public_key",
        lambda payload, _parameter_set=None: (payload, None),
        raising=False,
    )

    monkeypatch.setattr(
        cose,
        "_extract_subject_public_key_from_spki",
        lambda _spki: (_ for _ in ()).throw(ValueError("bad-spki")),
        raising=False,
    )
    assert cose._coerce_mldsa_public_key_bytes(b"\x30\x00") == b"\x30\x00"

    class _PublicKeyOnlyRaw:
        def public_bytes(self, encoding, fmt):
            if encoding is cose.serialization.Encoding.Raw:
                return b"raw-pub"
            return b""

    assert cose._coerce_mldsa_public_key_bytes(_PublicKeyOnlyRaw()) == b"raw-pub"

    def _extractor(data):
        if data == b"bad-der":
            raise ValueError("bad")
        return b"ok-spki"

    monkeypatch.setattr(cose, "_extract_subject_public_key_from_spki", _extractor, raising=False)

    class _PublicKeyAttempts:
        def public_bytes(self, encoding, fmt):
            if encoding is cose.serialization.Encoding.Raw:
                return b""
            if encoding is cose.serialization.Encoding.DER:
                return b"bad-der"
            return b"good-pem"

    assert cose._coerce_mldsa_public_key_bytes(_PublicKeyAttempts()) == b"ok-spki"

    class _PublicKeyEmpty:
        def public_bytes(self, _encoding, _fmt):
            return b""

    with pytest.raises(TypeError, match="Unable to coerce"):
        cose._coerce_mldsa_public_key_bytes(_PublicKeyEmpty())


def test_cosekey_iter_subclasses_duplicate_path_and_debug_with_context(capsys):
    class _A(cose.CoseKey):
        ALGORITHM = 90001

    class _B(_A):
        ALGORITHM = 90002

    class _C(_A):
        ALGORITHM = 90003

    class _D(_B, _C):
        ALGORITHM = 90004

    iterated = list(cose.CoseKey._iter_subclasses())
    assert _D in iterated

    key = cose.CoseKey({})
    key.set_assertion_debug_data(b"auth", b"client")
    key._log_signature_debug("ALG", b"message", b"signature", b"public")
    output = capsys.readouterr().out
    assert "Authenticator Data (hex):" in output
    assert "61757468" in output
    assert "Client Data JSON (hex):" in output


@pytest.mark.parametrize(
    "cls,name",
    [
        (cose.MLDSA87, "ML-DSA-87"),
        (cose.MLDSA65, "ML-DSA-65"),
        (cose.MLDSA44, "ML-DSA-44"),
    ],
)
def test_mldsa_verify_success_paths(monkeypatch, cls, name):
    class _Verifier:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def verify(self, _message, _signature, _public_key):
            return True

    fake_oqs = SimpleNamespace(Signature=lambda mechanism: _Verifier())
    monkeypatch.setattr(cose, "_require_oqs", lambda: fake_oqs, raising=False)
    monkeypatch.setattr(cose, "_coerce_mldsa_public_key_bytes", lambda _value, _ps: b"public", raising=False)

    key = cls({1: 7, 3: cls.ALGORITHM, -1: b"pk"})
    key.verify(b"message", b"signature")
