"""``webauthn.attestation.error_codes``: how an attestation check's finding is written."""
from __future__ import annotations

import pytest
from fido2.attestation import InvalidData, InvalidSignature, UnsupportedType

from server.app.webauthn.attestation import error_codes


def test_a_finding_gives_the_exceptions_message_after_its_code():
    assert error_codes.with_reason("cose_key_error", KeyError(3)) == "cose_key_error: 3"


@pytest.mark.parametrize("exc", [InvalidSignature(), ValueError(""), ValueError("  ")])
def test_an_exception_without_a_message_gives_the_bare_code(exc):
    assert error_codes.with_reason("attestation_invalid", exc) == "attestation_invalid"


@pytest.mark.parametrize(
    ("exc", "finding"),
    [
        (UnsupportedType(None, "compound"), 'unsupported_attestation: Attestation format "compound" is not supported'),
        (InvalidSignature(), "attestation_invalid"),
        (InvalidData("Nonce does not match!"), "attestation_invalid: Nonce does not match!"),
        (TypeError("not bytes"), "attestation_error: not bytes"),
    ],
)
def test_a_statement_fido2_refuses_is_named_for_why(exc, finding):
    assert error_codes.statement_error(exc) == finding


@pytest.mark.parametrize(
    ("exc", "finding"),
    [
        (InvalidSignature(), "certificate_chain_invalid"),
        (ValueError("error parsing asn1 value"), "certificate_chain_unreadable: error parsing asn1 value"),
    ],
)
def test_a_chain_that_does_not_verify_is_named_for_why(exc, finding):
    assert error_codes.chain_error(exc) == finding
