"""Every CBOR byte the decoder reads goes through ``cbor_parser``.

The vendored ``fido2.cbor`` reads all of major type 7 as a boolean without
consuming a float's payload, and cuts a short byte string off without saying
so; cbor2 accepts what CTAP forbids. Neither is used on decoder input, directly
or through fido2's ``AttestationObject`` / ``AuthenticatorData`` /
``AttestedCredentialData``, which decode with ``fido2.cbor``.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

DECODE_PACKAGE = Path(__file__).resolve().parents[3] / "server" / "app" / "decoder" / "decode"
FIDO2_DECODING_CLASSES = {"AttestationObject", "AuthenticatorData", "AttestedCredentialData", "CollectedClientData"}
# CollectedClientData parses JSON, not CBOR; it is the one fido2 class allowed.
ALLOWED_CALLS = {"CollectedClientData"}


def _modules() -> list[Path]:
    modules = sorted(DECODE_PACKAGE.glob("*.py"))
    assert modules, DECODE_PACKAGE
    return modules


def _imported_modules(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


@pytest.mark.parametrize("module", _modules(), ids=lambda path: path.name)
def test_no_decoder_module_imports_fido2_cbor_or_cbor2(module):
    imported = _imported_modules(ast.parse(module.read_text()))

    assert not {name for name in imported if name == "fido2.cbor" or name.startswith("fido2.cbor.")}
    assert not {name for name in imported if name == "cbor2" or name.startswith("cbor2.")}


@pytest.mark.parametrize("module", _modules(), ids=lambda path: path.name)
def test_no_decoder_module_constructs_a_fido2_class_that_decodes_cbor(module):
    calls = {
        node.func.id if isinstance(node.func, ast.Name) else node.func.attr
        for node in ast.walk(ast.parse(module.read_text()))
        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute))
    }

    assert not (calls & FIDO2_DECODING_CLASSES) - ALLOWED_CALLS
