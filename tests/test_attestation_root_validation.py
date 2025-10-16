"""Regression tests for attestation root validation helpers."""

from datetime import datetime, timezone

from server.server import attestation


class DummyAttestationObject:
    """Minimal attestation object carrying an attestation statement."""

    def __init__(self, att_stmt=None):
        self.att_stmt = att_stmt or {}


class DummyVerifier:
    """Verifier double that can be configured to return metadata entries."""

    def __init__(self, entry=None):
        self._entry = entry
        self.calls = []

    def find_entry_by_aaguid(self, aaguid):  # pragma: no cover - simple passthrough
        self.calls.append(aaguid)
        return self._entry


def test_resolve_root_validity_requires_trust_anchor():
    """Root validity should only be true when a trusted anchor succeeds."""

    assert (
        attestation._resolve_root_validity(
            {"trusted_ca": True, "chain": True, "fido_mds": None}
        )
        is True
    )
    assert (
        attestation._resolve_root_validity(
            {"trusted_ca": False, "chain": True, "fido_mds": None}
        )
        is None
    )


def test_pqc_root_checks_without_metadata_are_not_attempted():
    """When metadata is missing, root checks should remain unavailable."""

    now = datetime.now(timezone.utc)
    outcome = attestation._evaluate_mldsa_attestation_root(
        DummyAttestationObject(),
        b"".rjust(16, b"\x00"),
        DummyVerifier(entry=None),
        now,
    )

    assert outcome["metadata_entry"] is None
    assert outcome["root_valid"] is None
    assert outcome["checks"]["chain"] is None
    assert outcome["checks"]["fido_mds"] is None
    assert outcome["checks"]["trusted_ca"] is False
