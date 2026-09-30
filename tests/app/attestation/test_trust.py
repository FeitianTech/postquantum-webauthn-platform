"""``webauthn.attestation.trust``: the operator's trusted CAs, and the certificates trust reads.

Its functions are the attestation package's own: ``checks`` and ``classical`` call
them across modules, so they are tested here directly.
"""
from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest
from cryptography import x509

from server.app.webauthn.attestation import trust as attestation_trust
from tests.app.characterization import material

AAGUID = bytes.fromhex("f8a011f38c0a4d15800617111f9edc7d")


def _certificate_with_aaguid_extension(value: bytes | None) -> bytes:
    extensions = [] if value is None else [(x509.UnrecognizedExtension(material.OID_AAGUID, value), False)]
    return material.certificate(
        material.ec_key("trust-test").public_key(), common_name="Trust Test", serial=0x7157, extensions=extensions
    )


@pytest.fixture
def trust_settings(make_app):
    """Run ``check`` in an app configured with the given subjects and fingerprints."""

    def _in_app(subjects, fingerprints, check):
        app = make_app(
            {"TRUSTED_ATTESTATION_CA_SUBJECTS": subjects, "TRUSTED_ATTESTATION_CA_FINGERPRINTS": fingerprints}
        )
        with app.app_context():
            return check()

    return _in_app


def test_trusted_cas_given_as_lists_are_read_as_sets(trust_settings):
    subjects, fingerprints = trust_settings(
        ["CN=Root A", "CN=Root B", ""],
        ("aa", "bb", None),
        lambda: (attestation_trust._trusted_ca_subjects(), attestation_trust._trusted_ca_fingerprints()),
    )

    assert subjects == {"CN=Root A", "CN=Root B"}
    assert fingerprints == {"AA", "BB"}


def test_a_trusted_ca_setting_of_another_kind_trusts_no_list(trust_settings):
    assert trust_settings("CN=Root", "AA", lambda: attestation_trust._trusted_ca_subjects()) is None
    assert trust_settings("CN=Root", "AA", lambda: attestation_trust._trusted_ca_fingerprints()) is None


def test_bytes_that_are_not_a_certificate_match_no_trusted_subject(trust_settings):
    trusted = trust_settings({"CN=Root"}, {"00" * 32}, lambda: attestation_trust._is_trusted_ca_certificate(b"junk"))

    assert trusted is False


def test_with_only_fingerprints_trusted_another_certificate_is_not(trust_settings):
    certificate = _certificate_with_aaguid_extension(None)
    fingerprint = hashlib.sha256(certificate).hexdigest().upper()

    assert trust_settings(None, {fingerprint}, lambda: attestation_trust._is_trusted_ca_certificate(certificate)) is True
    assert trust_settings(None, {"00" * 32}, lambda: attestation_trust._is_trusted_ca_certificate(certificate)) is False


def test_a_certificates_aaguid_is_its_extensions_octet_string():
    assert attestation_trust._extract_certificate_aaguid(material.attestation_leaf_certificate(AAGUID)) == AAGUID


def test_an_aaguid_extension_holding_sixteen_bare_bytes_is_read_as_they_are():
    assert attestation_trust._extract_certificate_aaguid(_certificate_with_aaguid_extension(AAGUID)) == AAGUID


def test_sixteen_bytes_that_are_a_shorter_octet_string_are_read_whole():
    value = b"\x04\x0e" + bytes(range(14))

    assert attestation_trust._extract_certificate_aaguid(_certificate_with_aaguid_extension(value)) == value


@pytest.mark.parametrize(
    "certificate",
    [
        b"",
        b"not a certificate",
        _certificate_with_aaguid_extension(None),
        _certificate_with_aaguid_extension(b"\x04\x05short"),  # an OCTET STRING of five bytes
        _certificate_with_aaguid_extension(b"short"),
    ],
)
def test_a_certificate_without_a_sixteen_byte_aaguid_extension_has_none(certificate):
    assert attestation_trust._extract_certificate_aaguid(certificate) == b""


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (b"\x30\x03", b"\x30\x03"),
        ("MAM=", b"\x30\x03"),
        # Not base64 (six characters), but hex.
        ("0a0b0c", b"\x0a\x0b\x0c"),
        ("zz", None),
        ("   ", None),
        (12345, None),
    ],
)
def test_certificate_bytes_are_read_from_bytes_base64_or_hex(value, expected):
    assert attestation_trust._coerce_certificate_bytes(value) == expected


@pytest.mark.parametrize(
    ("entry", "roots"),
    [
        ({"attestationRootCertificates": "AQID"}, [b"\x01\x02\x03"]),
        (SimpleNamespace(metadata_statement={"attestationRootCertificates": ["AQID", "zz"]}), [b"\x01\x02\x03"]),
        ({"other": "value"}, []),
        (None, []),
    ],
)
def test_metadata_roots_are_one_certificate_or_a_list_and_unreadable_ones_are_skipped(entry, roots):
    assert attestation_trust._collect_metadata_root_certificates(entry) == roots
