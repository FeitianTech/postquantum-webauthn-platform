"""Regression tests: ML-DSA verification must not leak ceremony material.

``CoseKey._log_signature_debug`` used to ``print()`` authenticatorData,
clientDataJSON (which carries the ceremony challenge), the signature and the
public key on *every* ML-DSA verification -- several KB per authentication,
straight into stdout with no flag and no log level.  ``Fido2Server`` mirrored
the same two values at ``INFO``.
"""
from __future__ import annotations

import logging

import pytest

from fido2 import cose
from tests.pqc import mldsa_helpers

_SECRET_MARKERS = (
    "Verification Debug",
    "Authenticator Data",
    "Client Data JSON",
    "Public Key (hex)",
    "Signature (hex)",
)


@pytest.mark.parametrize("cls", [cose.MLDSA87, cose.MLDSA65, cose.MLDSA44])
def test_mldsa_verify_writes_nothing_to_stdout(cls, capsys, caplog):
    authenticator_data = b"\x01\x02authenticator data"
    client_data_json = b'{"challenge":"S3CR3T-CHALLENGE","type":"webauthn.get"}'
    parameter_set = {
        cose.MLDSA44: "ML-DSA-44",
        cose.MLDSA65: "ML-DSA-65",
        cose.MLDSA87: "ML-DSA-87",
    }[cls]
    message = authenticator_data + client_data_json
    signature = mldsa_helpers.sign(parameter_set, message)

    key = mldsa_helpers.cose_key(parameter_set)
    with caplog.at_level(logging.DEBUG):
        key.verify(message, signature)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""

    combined = captured.out + captured.err + caplog.text
    assert "S3CR3T-CHALLENGE" not in combined
    assert client_data_json.hex() not in combined
    assert signature.hex() not in combined
    for marker in _SECRET_MARKERS:
        assert marker not in combined


@pytest.mark.parametrize("cls", [cose.MLDSA87, cose.MLDSA65, cose.MLDSA44])
def test_mldsa_keys_expose_no_debug_capture_hooks(cls):
    key = cls({1: 7, 3: cls.ALGORITHM, -1: b"pk"})
    for removed in (
        "set_assertion_debug_data",
        "_consume_assertion_debug_data",
        "_log_signature_debug",
        "_assertion_debug_context",
    ):
        assert not hasattr(key, removed), f"{removed} should have been removed"


@pytest.mark.parametrize("cls", [cose.MLDSA87, cose.MLDSA65, cose.MLDSA44])
def test_mldsa_keys_declare_no_prehash_algorithm(cls):
    # ML-DSA signs the message directly (pure mode); the inherited SHA-256
    # ``_HASH_ALG`` was copy-paste from the ECDSA/RSA keys and never used.
    assert not hasattr(cls, "_HASH_ALG")


def test_cose_module_no_longer_prints(capsys):
    import inspect

    source = inspect.getsource(cose)
    assert "print(" not in source
    assert "binascii" not in source
    assert capsys.readouterr().out == ""
