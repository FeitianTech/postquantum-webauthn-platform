from __future__ import annotations

from types import SimpleNamespace

import fido2.mds3 as mds3_module
from fido2.mds3 import MdsAttestationVerifier, _last_lookup_source


def _entry(*, aaguid="device-aaguid", roots=None):
    return SimpleNamespace(
        aaguid=aaguid,
        status_reports=[],
        attestation_certificate_key_identifiers=[],
        metadata_statement=SimpleNamespace(attestation_root_certificates=list(roots or [])),
    )


def test_ca_lookup_handles_missing_entry_and_empty_roots(monkeypatch):
    verifier = MdsAttestationVerifier(SimpleNamespace(entries=[]), entry_filter=None)
    auth_data = SimpleNamespace(credential_data=SimpleNamespace(aaguid="missing"))
    attestation = SimpleNamespace(trust_path=[b"irrelevant"])

    assert verifier.ca_lookup(attestation, auth_data) is None
    assert _last_lookup_source.get() is None

    verifier_no_roots = MdsAttestationVerifier(
        SimpleNamespace(entries=[_entry(roots=[])]),
        entry_filter=None,
    )
    assert verifier_no_roots.ca_lookup(
        SimpleNamespace(trust_path=[b"unparseable-leaf"]),
        SimpleNamespace(credential_data=SimpleNamespace(aaguid="device-aaguid")),
    ) is None


def test_ca_lookup_skips_unparseable_roots_before_failing(monkeypatch):
    issuer_marker = object()

    class _Cert:
        def __init__(self, *, issuer=None, subject=None):
            self.issuer = issuer
            self.subject = subject

    def _load_der(der, _backend):
        if der == b"leaf-cert":
            return _Cert(issuer=issuer_marker)
        if der == b"bad-root":
            raise ValueError("bad der")
        return _Cert(subject=None)

    monkeypatch.setattr(
        mds3_module.x509,
        "load_der_x509_certificate",
        _load_der,
        raising=False,
    )

    verifier = MdsAttestationVerifier(
        SimpleNamespace(entries=[_entry(roots=[b"bad-root"])]),
        entry_filter=None,
    )
    auth_data = SimpleNamespace(credential_data=SimpleNamespace(aaguid="device-aaguid"))
    attestation = SimpleNamespace(trust_path=[b"leaf-cert"])

    assert verifier.ca_lookup(attestation, auth_data) is None
