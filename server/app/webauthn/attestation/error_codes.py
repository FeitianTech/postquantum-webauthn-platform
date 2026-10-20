"""The codes the attestation checks report: a code alone, or a code and its reason.

An error or warning is a code (``trust_path_missing``), or a code and the
message of the exception behind it, after ": " (``cose_key_error: …``). An
exception without a message gives the bare code, so no finding is empty and
none ends in ": ".
"""
from __future__ import annotations

from fido2.attestation import InvalidData, InvalidSignature, UnsupportedType


def with_reason(code: str, exc: BaseException) -> str:
    """``code``, followed by ``exc``'s message when it has one."""

    return f"{code}: {exc}" if str(exc).strip() else code


def statement_error(exc: Exception) -> str:
    """The code of an attestation statement fido2 refused: a format it does not read, a statement that does not verify, or another failure."""

    if isinstance(exc, UnsupportedType):
        return with_reason("unsupported_attestation", exc)
    if isinstance(exc, (InvalidSignature, InvalidData)):
        return with_reason("attestation_invalid", exc)
    return with_reason("attestation_error", exc)


def chain_error(exc: Exception) -> str:
    """The code of a certificate chain that did not verify: one certificate not issued by the next, or one that does not read."""

    if isinstance(exc, InvalidSignature):
        return "certificate_chain_invalid"
    return with_reason("certificate_chain_unreadable", exc)
