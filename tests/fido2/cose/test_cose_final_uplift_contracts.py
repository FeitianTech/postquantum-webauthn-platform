from __future__ import annotations

from types import SimpleNamespace

import pytest

from fido2 import cose
from tests.pqc import mldsa_helpers


def _der_sequence(content: bytes) -> bytes:
    return bytes([0x30, len(content)]) + content


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


def test_cosekey_iter_subclasses_duplicate_path_and_no_debug_dump(capsys):
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

    # The assertion-context capture and the signature debug dump are gone: they
    # printed authenticatorData, clientDataJSON (which carries the ceremony
    # challenge), the signature and the public key to stdout on every ML-DSA
    # verification, unconditionally.
    key = cose.CoseKey({})
    for removed in (
        "set_assertion_debug_data",
        "_consume_assertion_debug_data",
        "_log_signature_debug",
        "_assertion_debug_context",
    ):
        assert not hasattr(key, removed), f"{removed} should have been removed"
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "cls,name",
    [
        (cose.MLDSA87, "ML-DSA-87"),
        (cose.MLDSA65, "ML-DSA-65"),
        (cose.MLDSA44, "ML-DSA-44"),
    ],
)
def test_mldsa_verify_success_paths(cls, name):
    key = mldsa_helpers.cose_key(name)
    assert isinstance(key, cls)
    key.verify(b"message", mldsa_helpers.sign(name, b"message"))

    # The same key accepts a SubjectPublicKeyInfo encoding of itself.
    spki_key = cls({1: 7, 3: cls.ALGORITHM, -1: mldsa_helpers.spki_der(name)})
    spki_key.verify(b"message", mldsa_helpers.sign(name, b"message"))
