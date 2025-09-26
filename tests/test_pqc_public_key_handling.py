import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization


_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

for _module_name in [name for name in list(sys.modules) if name == "fido2" or name.startswith("fido2.")]:
    del sys.modules[_module_name]

import fido2.cose as cose_module  # noqa: E402
import fido2.attestation.packed as packed_module  # noqa: E402
from fido2.cose import MLDSA44, MLDSA65, MLDSA87  # noqa: E402
from types import SimpleNamespace  # noqa: E402


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _encode_oid(oid: str) -> bytes:
    components = [int(part) for part in oid.split(".")]
    if len(components) < 2:
        raise ValueError("OID must have at least two components")
    first = components[0] * 40 + components[1]
    encoded = [first]
    for value in components[2:]:
        if value == 0:
            encoded.append(0)
            continue
        base128 = []
        while value:
            base128.append(0x80 | (value & 0x7F))
            value >>= 7
        base128[0] &= 0x7F
        encoded.extend(reversed(base128))
    body = bytes(encoded)
    return b"\x06" + _encode_length(len(body)) + body


def _encode_sequence(*elements: bytes) -> bytes:
    body = b"".join(elements)
    return b"\x30" + _encode_length(len(body)) + body


def _encode_set(*elements: bytes) -> bytes:
    body = b"".join(elements)
    return b"\x31" + _encode_length(len(body)) + body


def _encode_integer(value: int) -> bytes:
    encoded = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big", signed=False)
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return b"\x02" + _encode_length(len(encoded)) + encoded


def _encode_utf8_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return b"\x0c" + _encode_length(len(encoded)) + encoded


def _encode_utctime(value: str) -> bytes:
    return b"\x17" + _encode_length(len(value)) + value.encode("ascii")


def _build_name(common_name: str) -> bytes:
    cn = _encode_sequence(_encode_oid("2.5.4.3"), _encode_utf8_string(common_name))
    return _encode_sequence(_encode_set(cn))


def _build_spki(raw_key: bytes, algorithm_oid: str = "1.2.3") -> bytes:
    """Construct a minimal SubjectPublicKeyInfo wrapper for a raw key."""

    oid = _encode_oid(algorithm_oid)
    null_params = b"\x05\x00"
    algorithm = _encode_sequence(oid, null_params)
    bit_string = b"\x03" + _encode_length(len(raw_key) + 1) + b"\x00" + raw_key
    return _encode_sequence(algorithm, bit_string)


def _build_certificate(spki: bytes) -> bytes:
    version = b"\xa0" + _encode_length(len(_encode_integer(2))) + _encode_integer(2)
    serial = _encode_integer(1)
    signature_algo = _encode_sequence(_encode_oid("1.2.840.10045.4.3.2"), b"\x05\x00")
    name = _build_name("Test")
    validity = _encode_sequence(
        _encode_utctime("240101000000Z"),
        _encode_utctime("260101000000Z"),
    )
    tbs = _encode_sequence(version, serial, signature_algo, name, validity, name, spki)
    signature_value = b"\x03\x02\x00\x00"
    return _encode_sequence(tbs, signature_algo, signature_value)

def test_mldsa_from_cryptography_key_accepts_raw_public_bytes():
    raw_key = b"\x01\x02\x03"

    class DummyKey:
        def public_bytes(self, encoding, fmt):
            if encoding is serialization.Encoding.Raw and fmt is serialization.PublicFormat.Raw:
                return raw_key
            raise ValueError("unexpected encoding")

    cose_key = MLDSA87.from_cryptography_key(DummyKey())
    assert cose_key[-1] == raw_key


def test_mldsa_from_cryptography_key_extracts_from_spki():
    raw_key = b"raw-public-key"
    spki = _build_spki(raw_key)

    class DummyKey:
        def public_bytes(self, encoding, fmt):
            if encoding is serialization.Encoding.DER and fmt is serialization.PublicFormat.SubjectPublicKeyInfo:
                return spki
            raise ValueError("unsupported encoding")

    cose_key = MLDSA65.from_cryptography_key(DummyKey())
    assert cose_key[-1] == raw_key


def test_mldsa_verify_coerces_dynamic_public_key_bytes(monkeypatch):
    raw_key = b"coerced-public-key"
    spki = _build_spki(raw_key)

    class DummyKey:
        def public_bytes(self, encoding, fmt):
            if encoding is serialization.Encoding.DER and fmt is serialization.PublicFormat.SubjectPublicKeyInfo:
                return spki
            raise ValueError("unsupported encoding")

    verify_calls: list[tuple[bytes, bytes, bytes]] = []

    class FakeSignature:
        def __init__(self, algorithm: str):
            assert algorithm == "ML-DSA-44"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
            verify_calls.append((message, signature, public_key))
            return True

    class FakeOQS:
        Signature = FakeSignature

    monkeypatch.setattr(cose_module, "oqs", FakeOQS)
    monkeypatch.setattr(cose_module, "_oqs_import_error", None)

    cose_key = MLDSA44({1: 7, 3: -48, -1: DummyKey()})
    cose_key.verify(b"msg", b"sig")

    assert verify_calls == [(b"msg", b"sig", raw_key)]


def test_extract_certificate_public_key_info_parses_mldsa_certificate():
    raw_key = b"ml-dsa-public-key"
    spki = _build_spki(raw_key, algorithm_oid="2.16.840.1.101.3.4.3.17")
    cert = _build_certificate(spki)

    info = cose_module.extract_certificate_public_key_info(cert)

    assert info["algorithm_oid"] == "2.16.840.1.101.3.4.3.17"
    assert info["ml_dsa_parameter_set"] == "ML-DSA-44"
    assert info["subject_public_key"] == raw_key


def test_packed_attestation_falls_back_to_parsed_certificate_bytes(monkeypatch):
    raw_key = b"certificate-public-key"
    spki = _build_spki(raw_key, algorithm_oid="2.16.840.1.101.3.4.3.17")
    cert_der = _build_certificate(spki)

    class FakeCert:
        def __init__(self):
            self.extensions = []
            self.subject = SimpleNamespace(
                get_attributes_for_oid=lambda oid: [SimpleNamespace(value="Test")]
            )

        def public_key(self):
            raise packed_module.UnsupportedAlgorithm("unsupported")

    monkeypatch.setattr(packed_module, "_validate_packed_cert", lambda cert, aaguid: None)
    monkeypatch.setattr(
        packed_module.x509,
        "load_der_x509_certificate",
        lambda data, backend=None: FakeCert(),
    )

    def fake_extract(data):
        assert data == cert_der
        return {
            "subject_public_key": raw_key,
            "algorithm_oid": "2.16.840.1.101.3.4.3.17",
            "ml_dsa_parameter_set": "ML-DSA-44",
        }

    monkeypatch.setattr(packed_module, "extract_certificate_public_key_info", fake_extract)

    verify_calls: list[tuple[bytes, bytes, bytes]] = []

    def fake_verify(self, message, signature):
        verify_calls.append((self.get(-1), message, signature))

    monkeypatch.setattr(cose_module.MLDSA44, "verify", fake_verify, raising=False)

    class DummyCredentialData:
        aaguid = b"\x00" * 16

    class DummyAuthData:
        credential_data = DummyCredentialData()

        def __bytes__(self):
            return b"auth-data"

        def __add__(self, other):
            return bytes(self) + other

    attestation = packed_module.PackedAttestation()
    statement = {"alg": -48, "sig": b"sig", "x5c": [cert_der]}

    result = attestation.verify(statement, DummyAuthData(), b"hash")

    assert verify_calls == [(raw_key, b"auth-data" + b"hash", b"sig")]
    assert result.attestation_type == packed_module.AttestationType.BASIC
