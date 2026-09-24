"""The metadata entry's AAGUID is reported beside the credential's, never compared with it.

``aaguid_match`` is WebAuthn L3 section 8.2.1's check: the id-fido-gen-ce-aaguid
extension of the attestation certificate against authData's AAGUID. The
metadata entry adds nothing to compare: it was looked up by the credential's
AAGUID whenever the credential has one, and by certificate chain only when it
has none (fido-u2f's is zero by definition) -- where a comparison would flag
every legitimate registration.
"""
from __future__ import annotations

import types
import uuid

from server.app.webauthn.attestation import checks

_ENTRY_AAGUID = uuid.UUID("f8a011f3-8c0a-4d15-8006-17111f9edc7d")


def _finalize(credential_aaguid: bytes, certificate_aaguid: bytes, source: str) -> dict:
    entry = types.SimpleNamespace(aaguid=_ENTRY_AAGUID, metadata_statement=types.SimpleNamespace(description="Model"))
    results = {"authenticator_data": {"algorithm": -7}, "errors": [], "warnings": []}
    checks._finalize_metadata_results(
        results,
        metadata_entry=entry,
        metadata_lookup_source=source,
        verifier=None,
        credential_aaguid_bytes=credential_aaguid,
        certificate_aaguid_bytes=certificate_aaguid,
        root_check_details=None,
        root_valid=None,
    )
    return results


def test_an_entry_found_by_chain_for_a_zero_aaguid_credential_is_not_a_mismatch():
    results = _finalize(b"", b"", "chain")

    assert results["errors"] == []
    assert results["aaguid_match"] is None
    assert results["metadata"]["aaguid"] == str(_ENTRY_AAGUID)
    assert results["metadata"]["source"] == "chain"


def test_aaguid_match_compares_the_certificate_with_authenticator_data_only():
    other = uuid.uuid4().bytes

    assert _finalize(_ENTRY_AAGUID.bytes, _ENTRY_AAGUID.bytes, "aaguid")["aaguid_match"] is True
    assert _finalize(_ENTRY_AAGUID.bytes, other, "aaguid")["aaguid_match"] is False
