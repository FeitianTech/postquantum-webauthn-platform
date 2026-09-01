from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from fido2.attestation.base import InvalidSignature, UntrustedAttestation, verify_x509_chain
from fido2.mds3 import (
    AuthenticatorStatus,
    MdsAttestationVerifier,
    StatusReport,
    _last_entry,
    _last_lookup_source,
    _verify_blob_certificate_chain,
    filter_attestation_key_compromised,
    parse_blob,
)
from fido2.utils import websafe_encode


def _b64url_json(value: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode("utf-8")).decode("ascii").rstrip("=")


def _minimal_payload() -> dict:
    return {
        "legalHeader": "demo",
        "no": 1,
        "nextUpdate": "2099-01-01",
        "entries": [
            {
                "statusReports": [{"status": "FIDO_CERTIFIED"}],
                "timeOfLastStatusChange": "2020-01-01",
            }
        ],
    }


def _build_blob(header: dict, payload: dict) -> bytes:
    return f"{_b64url_json(header)}.{_b64url_json(payload)}.AA".encode("ascii")


def _cert_der(*, subject_cn: str, issuer_cn: str, public_key, issuer_key) -> bytes:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(issuer_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _self_signed_der(common_name: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _cert_der(
        subject_cn=common_name,
        issuer_cn=common_name,
        public_key=key.public_key(),
        issuer_key=key,
    )


def _mds_transition_certs():
    legacy_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    current_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    return SimpleNamespace(
        leaf=_cert_der(
            subject_cn="mds.example.org",
            issuer_cn="Intermediate CA",
            public_key=leaf_key.public_key(),
            issuer_key=intermediate_key,
        ),
        intermediate=_cert_der(
            subject_cn="Intermediate CA",
            issuer_cn="Current Root R46",
            public_key=intermediate_key.public_key(),
            issuer_key=current_key,
        ),
        cross=_cert_der(
            subject_cn="Current Root R46",
            issuer_cn="Legacy Root R3",
            public_key=current_key.public_key(),
            issuer_key=legacy_key,
        ),
        current_root=_cert_der(
            subject_cn="Current Root R46",
            issuer_cn="Current Root R46",
            public_key=current_key.public_key(),
            issuer_key=current_key,
        ),
        legacy_root=_cert_der(
            subject_cn="Legacy Root R3",
            issuer_cn="Legacy Root R3",
            public_key=legacy_key.public_key(),
            issuer_key=legacy_key,
        ),
        unrelated=_self_signed_der("Unrelated Root"),
        leaf_key=leaf_key,
    )


def _build_signed_blob(header: dict, payload: dict, leaf_key) -> bytes:
    message = f"{_b64url_json(header)}.{_b64url_json(payload)}".encode("ascii")
    signature = leaf_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return message + b"." + websafe_encode(signature).encode("ascii")


def test_filter_attestation_key_compromised_branches():
    compromised = StatusReport(
        status=AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE,
        certificate=b"compromised-cert",
    )
    entry = SimpleNamespace(status_reports=[compromised])

    assert filter_attestation_key_compromised(entry, [b"compromised-cert"]) is False
    assert filter_attestation_key_compromised(entry, [b"different"]) is True


def test_find_entry_by_chain_returns_matching_entry():
    cert_der = _self_signed_der("mds-chain-match")
    cert = x509.load_der_x509_certificate(cert_der)
    ski = x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest

    entry = SimpleNamespace(
        aaguid=None,
        status_reports=[],
        attestation_certificate_key_identifiers=[ski],
        metadata_statement=None,
    )
    blob = SimpleNamespace(entries=[entry])
    verifier = MdsAttestationVerifier(blob, entry_filter=None)

    assert verifier.find_entry_by_chain([cert_der]) is entry


def test_ca_lookup_paths_cover_filter_metadata_and_root_selection(monkeypatch):
    matching_root = _self_signed_der("mds-root-match")
    mismatching_root = _self_signed_der("mds-root-other")

    entry_with_root = SimpleNamespace(
        aaguid="device-aaguid",
        status_reports=[],
        attestation_certificate_key_identifiers=[],
        metadata_statement=SimpleNamespace(attestation_root_certificates=[matching_root]),
    )
    blob = SimpleNamespace(entries=[entry_with_root])

    verifier_reject = MdsAttestationVerifier(
        blob,
        entry_filter=None,
        attestation_filter=lambda _entry, _chain: False,
    )

    auth_data = SimpleNamespace(credential_data=SimpleNamespace(aaguid="device-aaguid"))
    attestation_result = SimpleNamespace(trust_path=[matching_root])

    assert verifier_reject.ca_lookup(attestation_result, auth_data) is None
    assert _last_lookup_source.get() == "aaguid"

    entry_without_metadata = SimpleNamespace(
        aaguid="device-aaguid",
        status_reports=[],
        attestation_certificate_key_identifiers=[],
        metadata_statement=None,
    )
    verifier_no_metadata = MdsAttestationVerifier(
        SimpleNamespace(entries=[entry_without_metadata]),
        entry_filter=None,
        attestation_filter=lambda _entry, _chain: True,
    )
    assert verifier_no_metadata.ca_lookup(attestation_result, auth_data) is None

    verifier_match = MdsAttestationVerifier(blob, entry_filter=None)
    selected = verifier_match.ca_lookup(attestation_result, auth_data)
    assert selected == matching_root
    assert _last_entry.get() is entry_with_root

    entry_mismatch = SimpleNamespace(
        aaguid="device-aaguid",
        status_reports=[],
        attestation_certificate_key_identifiers=[],
        metadata_statement=SimpleNamespace(attestation_root_certificates=[mismatching_root]),
    )
    verifier_mismatch = MdsAttestationVerifier(SimpleNamespace(entries=[entry_mismatch]), entry_filter=None)
    assert verifier_mismatch.ca_lookup(attestation_result, auth_data) is None

    verifier_fallback = MdsAttestationVerifier(SimpleNamespace(entries=[entry_with_root]), entry_filter=None)
    bad_chain_result = SimpleNamespace(trust_path=[b"not-a-der-cert"])
    assert verifier_fallback.ca_lookup(bad_chain_result, auth_data) == matching_root

    chain_entry = SimpleNamespace(
        aaguid=None,
        status_reports=[],
        attestation_certificate_key_identifiers=[],
        metadata_statement=SimpleNamespace(attestation_root_certificates=[matching_root]),
    )
    verifier_chain_source = MdsAttestationVerifier(SimpleNamespace(entries=[chain_entry]), entry_filter=None)
    monkeypatch.setattr(
        verifier_chain_source,
        "find_entry_by_chain",
        lambda _chain: chain_entry,
        raising=False,
    )
    no_aaguid_auth_data = SimpleNamespace(credential_data=SimpleNamespace(aaguid=None))
    assert verifier_chain_source.ca_lookup(attestation_result, no_aaguid_auth_data) == matching_root
    assert _last_lookup_source.get() == "chain"


def test_find_entry_and_evaluate_attestation_helpers(monkeypatch):
    verifier = MdsAttestationVerifier(SimpleNamespace(entries=[]), entry_filter=None)

    def _mark_entry(_att_obj, _client_hash):
        _last_entry.set("entry-marker")

    monkeypatch.setattr(verifier, "verify_attestation", _mark_entry, raising=False)
    assert verifier.find_entry(object(), b"hash") == "entry-marker"

    monkeypatch.setattr(
        verifier,
        "verify_attestation",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(UntrustedAttestation()),
        raising=False,
    )
    assert verifier.find_entry(object(), b"hash") is None

    def _collect(_att_obj, _client_hash):
        _last_entry.set("evaluated-entry")
        _last_lookup_source.set("chain")
        return "trust-details"

    monkeypatch.setattr(verifier, "collect_trust_path_details", _collect, raising=False)
    evaluation = verifier.evaluate_attestation(object(), b"hash")
    assert evaluation.trust_path == "trust-details"
    assert evaluation.metadata_entry == "evaluated-entry"
    assert evaluation.metadata_lookup_source == "chain"


def test_parse_blob_without_trust_anchor_logs_warning(monkeypatch):
    import fido2.mds3 as mds3_module

    warnings = []
    monkeypatch.setattr(mds3_module.logger, "warn", lambda message: warnings.append(message), raising=False)

    blob = _build_blob({"alg": "ES256", "typ": "JWT"}, _minimal_payload())
    parsed = parse_blob(blob, None)

    assert parsed.no == 1
    assert warnings
    assert "without trust anchor" in warnings[0]


def test_parse_blob_trust_anchor_paths_cover_leaf_fallback_and_public_key_errors(monkeypatch):
    import fido2.mds3 as mds3_module

    captured = {}

    def _verify_chain(chain):
        captured["chain"] = chain

    class _LeafCert:
        def public_key(self):
            return object()

    class _CoseKey:
        def verify(self, message, signature):
            captured["verify"] = (message, signature)

    class _CoseClass:
        @staticmethod
        def from_cryptography_key(key):
            captured["crypto_key"] = key
            return _CoseKey()

    def _load_cert(der, _backend):
        captured["leaf_der"] = der
        return _LeafCert()

    monkeypatch.setattr(mds3_module, "verify_x509_chain", _verify_chain, raising=False)
    monkeypatch.setattr(mds3_module.x509, "load_der_x509_certificate", _load_cert, raising=False)
    monkeypatch.setattr(mds3_module.CoseKey, "for_name", lambda _alg: _CoseClass, raising=False)

    header_with_chain = {"alg": "ES256", "x5c": [base64.b64encode(b"leaf-cert").decode("ascii")]}
    parse_blob(_build_blob(header_with_chain, _minimal_payload()), b"trust-root")

    assert captured["chain"] == [b"leaf-cert", b"trust-root"]
    assert captured["leaf_der"] == b"leaf-cert"
    assert "verify" in captured

    captured.clear()
    header_without_chain = {"alg": "ES256"}
    parse_blob(_build_blob(header_without_chain, _minimal_payload()), b"trust-root")
    assert captured["chain"] == [b"trust-root"]
    assert captured["leaf_der"] == b"trust-root"

    class _UnsupportedLeafCert:
        def public_key(self):
            raise ValueError("unsupported")

    monkeypatch.setattr(
        mds3_module.x509,
        "load_der_x509_certificate",
        lambda *_args, **_kwargs: _UnsupportedLeafCert(),
        raising=False,
    )
    with pytest.raises(ValueError, match="does not expose a supported public key"):
        parse_blob(_build_blob({"alg": "ES256"}, _minimal_payload()), b"trust-root")


def test_verify_blob_certificate_chain_tries_prefixes_until_trust_root_matches(monkeypatch):
    import fido2.mds3 as mds3_module

    calls = []

    def _verify(chain):
        calls.append(list(chain))
        if len(chain) != 3:
            raise InvalidSignature("incomplete path")

    monkeypatch.setattr(mds3_module, "verify_x509_chain", _verify, raising=False)
    _verify_blob_certificate_chain([b"leaf", b"ca", b"cross"], b"root")
    assert calls == [
        [b"leaf", b"root"],
        [b"leaf", b"ca", b"root"],
    ]


def test_verify_blob_certificate_chain_raises_when_no_prefix_reaches_trust_root(monkeypatch):
    import fido2.mds3 as mds3_module

    monkeypatch.setattr(
        mds3_module,
        "verify_x509_chain",
        lambda _chain: (_ for _ in ()).throw(InvalidSignature("bad chain")),
        raising=False,
    )
    with pytest.raises(InvalidSignature, match="bad chain"):
        _verify_blob_certificate_chain([b"leaf", b"ca"], b"root")


def test_verify_blob_certificate_chain_accepts_mds_cross_certificate_topology():
    certs = _mds_transition_certs()
    chain = [certs.leaf, certs.intermediate, certs.cross]

    with pytest.raises(InvalidSignature):
        verify_x509_chain(chain + [certs.current_root])

    _verify_blob_certificate_chain(chain, certs.current_root)
    _verify_blob_certificate_chain(chain, certs.legacy_root)
    _verify_blob_certificate_chain([certs.leaf, certs.intermediate], certs.current_root)

    with pytest.raises(InvalidSignature):
        _verify_blob_certificate_chain(chain, certs.unrelated)


def test_parse_blob_accepts_extra_cross_certificate_in_x5c():
    certs = _mds_transition_certs()
    header = {
        "alg": "ES256",
        "x5c": [
            base64.b64encode(certs.leaf).decode("ascii"),
            base64.b64encode(certs.intermediate).decode("ascii"),
            base64.b64encode(certs.cross).decode("ascii"),
        ],
    }
    parsed = parse_blob(_build_signed_blob(header, _minimal_payload(), certs.leaf_key), certs.current_root)
    assert parsed.no == 1
