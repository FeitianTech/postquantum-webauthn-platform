import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization


_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

for _module_name in [name for name in list(sys.modules) if name == "fido2" or name.startswith("fido2.")]:
    del sys.modules[_module_name]

import fido2.cose as cose_module  # noqa: E402
from fido2.cose import MLDSA44, MLDSA65, MLDSA87  # noqa: E402


def _build_spki(raw_key: bytes) -> bytes:
    """Construct a minimal SubjectPublicKeyInfo wrapper for a raw key."""

    def _encode_length(length: int) -> bytes:
        if length < 0x80:
            return bytes([length])
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(encoded)]) + encoded

    # Use an arbitrary OID (1.2.3) with a NULL parameters field.
    oid = b"\x06\x02\x2a\x03"
    null_params = b"\x05\x00"
    algorithm = b"\x30" + _encode_length(len(oid) + len(null_params)) + oid + null_params
    bit_string = b"\x03" + _encode_length(len(raw_key) + 1) + b"\x00" + raw_key
    spki_body = algorithm + bit_string
    return b"\x30" + _encode_length(len(spki_body)) + spki_body

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
