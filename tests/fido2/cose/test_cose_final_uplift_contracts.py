from __future__ import annotations

from types import SimpleNamespace

import pytest

from fido2 import cose
from tests.pqc import mldsa_helpers


def _der_sequence(content: bytes) -> bytes:
    return bytes([0x30, len(content)]) + content


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
