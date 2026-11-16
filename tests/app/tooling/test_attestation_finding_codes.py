"""Every attestation and assertion finding the checks write is a code, and the shared list holds each one.

A finding is a code (``trust_path_missing``) or a code and its reason after ": "
(``webauthn/attestation/error_codes.py``). The checks write each one as a
constant: an argument of ``append`` or ``error_codes.with_reason``, or what
``error_codes`` returns. This reads those modules as source, so a sentence written
where a code belongs, or a code the page has no sentence for, fails here:
``tests/fixtures/attestation-finding-codes.json`` lists the codes, and the page's
table of sentences is held to the same list (``web/src/logic/shared/attestation-findings.js``).
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

from server.app.webauthn.attestation import error_codes

_REPO = Path(__file__).resolve().parents[3]
_WEBAUTHN = _REPO / "server" / "app" / "webauthn"
_CHECK_MODULES = (
    "attestation/checks",
    "attestation/response_checks",
    "attestation/public_key_checks",
    "attestation/statement_checks",
    "attestation/classical",
    "attestation/evaluation",
    "attestation/metadata_checks",
    "attestation/error_codes",
    "assertion_checks",
)
_CODES = json.loads((_REPO / "tests" / "fixtures" / "attestation-finding-codes.json").read_text(encoding="utf-8"))["codes"]


def _leading_text(node: ast.expr) -> str | None:
    """The text a string constant holds, or the text an f-string starts with; else None."""

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and node.values and isinstance(node.values[0], ast.Constant):
        return str(node.values[0].value)
    return None


def _written(source: str, *, returned: bool) -> list[str]:
    """The findings ``source`` writes as constants: what it appends or gives ``with_reason``, and with ``returned`` what it returns."""

    found = []
    for node in ast.walk(ast.parse(source)):
        text = None
        if isinstance(node, ast.Call) and node.args:
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if name in ("append", "with_reason"):
                text = _leading_text(node.args[0])
        elif returned and isinstance(node, ast.Return) and node.value is not None:
            text = _leading_text(node.value)
        if text is not None:
            found.append(text)
    return found


def _findings() -> dict[str, list[str]]:
    return {
        name: _written((_WEBAUTHN / f"{name}.py").read_text(encoding="utf-8"), returned=name.endswith("error_codes"))
        for name in _CHECK_MODULES
    }


def _is_code(text: str) -> bool:
    """Words of lower-case ASCII letters joined by underscores, two at least."""

    words = text.split("_")
    return len(words) > 1 and all(word.isascii() and word.isalpha() and word.islower() for word in words)


def test_every_finding_the_checks_write_is_a_code():
    written = [(module, finding) for module, findings in _findings().items() for finding in findings]
    assert len(written) > 25
    assert [f"{module}: {finding!r}" for module, finding in written if not _is_code(error_codes.error_code(finding))] == []


def test_the_checks_write_exactly_the_listed_codes():
    codes = {error_codes.error_code(finding) for findings in _findings().values() for finding in findings}
    assert codes == set(_CODES)
    assert error_codes.INTEGRITY_ERRORS <= codes
    assert _CODES == sorted(set(_CODES))


def test_the_reader_finds_appended_returned_and_reasoned_findings():
    source = (
        "def check(errors, exc, cert):\n"
        "    errors.append('plain_code')\n"
        "    errors.append(with_reason('reasoned_code', exc))\n"
        "    errors.append(f'subject_code: {cert}')\n"
        "    errors.append(error_codes.chain_error(exc))\n"
        "    return 'returned_code'\n"
    )
    assert sorted(_written(source, returned=False)) == ["plain_code", "reasoned_code", "subject_code: "]
    assert sorted(_written(source, returned=True)) == ["plain_code", "reasoned_code", "returned_code", "subject_code: "]


def test_a_sentence_is_no_code():
    assert _is_code("metadata_entry_missing")
    assert not _is_code("No root found for Authenticator")
    assert not _is_code("metadata")
    assert not _is_code("Metadata_entry")
    assert not _is_code("metadata__entry")
