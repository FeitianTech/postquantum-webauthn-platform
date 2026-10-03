"""``mds.verifier``: the MDS metadata attestations are checked against, a visitor's uploads first.

The verifier finds the entry fido2's ``MdsAttestationVerifier`` over the merged
metadata (the uploads, then the packaged entries no upload hides) found, parsing
only the entry found.
"""
from __future__ import annotations

import copy
import json
from datetime import date, datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.mds3 import (
    MdsAttestationVerifier,
    MetadataBlobPayload,
    MetadataBlobPayloadEntry,
)
from fido2.webauthn import Aaguid
from flask import g

from server.app.mds import entries as mds_entries
from server.app.mds import files as mds_files
from server.app.mds import uploads as mds_uploads
from server.app.mds import verifier as mds_verifier

PACKAGED = "f1d0f1d0-0000-4000-8000-000000000001"
OTHER = "0badc0de-0000-4000-8000-000000000001"
DUPLICATED = "d0d0d0d0-0000-4000-8000-000000000001"
REVOKED_LAST = "e0e0e0e0-0000-4000-8000-000000000001"
STATEMENT_ONLY = "5a5a5a5a-0000-4000-8000-000000000001"


def _certificate(seed: int) -> bytes:
    key = ec.derive_private_key(seed, ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, f"Key {seed}")])
    built = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(seed)
        .not_valid_before(datetime(2026, 1, 1))
        .not_valid_after(datetime(2036, 1, 1))
        .sign(key, hashes.SHA256())
    )
    return built.public_bytes(serialization.Encoding.DER)


def _key_identifier(der: bytes) -> str:
    certificate = x509.load_der_x509_certificate(der)
    return x509.SubjectKeyIdentifier.from_public_key(certificate.public_key()).digest.hex()


SHARED_BY_PACKAGED, SHARED_WITH_UPLOAD, UPLOAD_ONLY = (_certificate(seed) for seed in (101, 102, 103))


def _raw(description: str, *, aaguid: str | None = None, statement_aaguid: str | None = None, revoked=False, key_ids=()):
    raw = {
        "statusReports": [{"status": "REVOKED" if revoked else "FIDO_CERTIFIED", "effectiveDate": "2026-01-01"}],
        "timeOfLastStatusChange": "2026-01-01",
        "metadataStatement": {
            **copy.deepcopy(mds_entries._METADATA_STATEMENT_REQUIRED_DEFAULTS),
            "description": description,
        },
    }
    if aaguid:
        raw["aaguid"] = aaguid
    if statement_aaguid or aaguid:
        raw["metadataStatement"]["aaguid"] = statement_aaguid or aaguid
    if key_ids:
        raw["attestationCertificateKeyIdentifiers"] = [_key_identifier(der) for der in key_ids]
    return raw


def _packaged(mds_fixture_snapshot) -> list[dict]:
    fixture = json.loads((mds_fixture_snapshot / mds_files.VERIFIED).read_text(encoding="utf-8"))["entries"]
    return [
        *fixture,
        _raw("duplicated, first", aaguid=DUPLICATED),
        _raw("duplicated, last", aaguid=DUPLICATED),
        _raw("kept", aaguid=REVOKED_LAST),
        _raw("revoked, last", aaguid=REVOKED_LAST, revoked=True),
        _raw("statement only", statement_aaguid=STATEMENT_ONLY),
        _raw("key identifier, first", key_ids=[SHARED_BY_PACKAGED]),
        _raw("key identifier, last", key_ids=[SHARED_BY_PACKAGED, SHARED_WITH_UPLOAD]),
    ]


def _uploads() -> list[MetadataBlobPayloadEntry]:
    raws = [
        {"aaguid": PACKAGED, "metadataStatement": {"description": "upload of the packaged AAGUID", "aaguid": PACKAGED}},
        {"aaguid": OTHER, "metadataStatement": {"description": "upload, first", "aaguid": OTHER}},
        {"aaguid": OTHER, "metadataStatement": {"description": "upload, second", "aaguid": OTHER}},
        {
            "aaguid": DUPLICATED,
            "metadataStatement": {"description": "revoked upload", "aaguid": DUPLICATED},
            "statusReports": [{"status": "REVOKED"}],
        },
        {"aaguid": REVOKED_LAST, "metadataStatement": {"description": "upload, its statement without an AAGUID"}},
        {"metadataStatement": {"description": "upload by key identifier"}, "attestationCertificateKeyIdentifiers": [
            _key_identifier(SHARED_WITH_UPLOAD), _key_identifier(UPLOAD_ONLY),
        ]},
    ]
    return [mds_entries.build_metadata_entry_components(raw)[0] for raw in raws]


def _reference(packaged: list[dict], uploads: list[MetadataBlobPayloadEntry]) -> MdsAttestationVerifier:
    """fido2's verifier over the metadata the verifier used to merge: every packaged entry parsed."""

    kept, seen = [], set()
    for entry in uploads:
        aaguid = mds_entries._extract_entry_aaguid(entry)
        if aaguid and aaguid in seen:
            continue
        if aaguid:
            seen.add(aaguid)
        kept.append(entry)
    base = [mds_entries.parse_entry(raw) for raw in packaged]
    base = [entry for entry in base if mds_entries._extract_entry_aaguid(entry) not in seen or not mds_entries._extract_entry_aaguid(entry)]
    return MdsAttestationVerifier(MetadataBlobPayload(legal_header="", no=0, next_update=date(2099, 1, 1), entries=tuple(kept + base)))


def _described(entry) -> str | None:
    return entry.metadata_statement.description if entry is not None else None


@pytest.mark.parametrize("with_uploads", [False, True])
def test_every_lookup_finds_what_fido2s_verifier_over_the_merged_metadata_found(mds_fixture_snapshot, with_uploads):
    packaged = _packaged(mds_fixture_snapshot)
    uploads = _uploads() if with_uploads else []
    reference = _reference(packaged, uploads)
    indexed = mds_verifier.IndexedVerifier(mds_verifier.PackagedEntries(packaged), uploads)
    aaguids = {raw.get("aaguid") or raw["metadataStatement"].get("aaguid") for raw in packaged} | {OTHER}

    for aaguid in sorted(filter(None, aaguids)):
        found = indexed.find_entry_by_aaguid(Aaguid.parse(aaguid))
        assert _described(found) == _described(reference.find_entry_by_aaguid(Aaguid.parse(aaguid))), aaguid
    for chain in ([SHARED_BY_PACKAGED], [SHARED_WITH_UPLOAD], [UPLOAD_ONLY], [_certificate(104), SHARED_WITH_UPLOAD], [_certificate(104)]):
        assert _described(indexed.find_entry_by_chain(chain)) == _described(reference.find_entry_by_chain(chain))


def test_the_rules_the_lookups_follow(mds_fixture_snapshot):
    indexed = mds_verifier.IndexedVerifier(mds_verifier.PackagedEntries(_packaged(mds_fixture_snapshot)), _uploads())
    by_aaguid = lambda aaguid: _described(indexed.find_entry_by_aaguid(Aaguid.parse(aaguid)))  # noqa: E731

    assert by_aaguid(PACKAGED) == "upload of the packaged AAGUID"
    assert by_aaguid(OTHER) == "upload, first"
    assert by_aaguid(DUPLICATED) is None  # hidden by a revoked upload
    assert by_aaguid(REVOKED_LAST) == "kept"  # the revoked one left out; the upload's statement hides nothing
    assert by_aaguid(STATEMENT_ONLY) is None
    assert _described(indexed.find_entry_by_chain([SHARED_WITH_UPLOAD])) == "key identifier, last"
    assert _described(indexed.find_entry_by_chain([UPLOAD_ONLY])) == "upload by key identifier"


def test_only_the_entry_found_is_parsed_and_it_is_parsed_once(mds_fixture_snapshot, monkeypatch):
    packaged = mds_verifier.PackagedEntries(_packaged(mds_fixture_snapshot))
    parsed = []
    original = MetadataBlobPayloadEntry.from_dict.__func__

    def counting(cls, raw):
        parsed.append(raw["metadataStatement"]["description"])
        return original(cls, raw)

    monkeypatch.setattr(MetadataBlobPayloadEntry, "from_dict", classmethod(counting))
    first = packaged.by_aaguid(Aaguid.parse(PACKAGED), frozenset())
    again = packaged.by_aaguid(Aaguid.parse(PACKAGED), frozenset())

    assert first is again
    assert parsed == ["Fixture Security Key L1"]
    assert packaged.holds(first) and not packaged.holds(copy.copy(first))


def _upload(aaguid: str, description: str):
    return mds_uploads.save_session_metadata_item({"aaguid": aaguid, "metadataStatement": {"description": description, "aaguid": aaguid}})


def test_the_snapshots_verifier_is_kept_for_its_file_and_trusts_its_entries(visitor, mds_fixture_snapshot):
    verifier = mds_verifier.get_mds_verifier()
    entry = verifier.find_entry_by_aaguid(Aaguid.parse(PACKAGED))

    assert mds_verifier.get_mds_verifier() is verifier
    assert _described(entry) == "Fixture Security Key L1"
    assert mds_verifier.metadata_entry_trust_anchor_status(entry) is True


def test_an_upload_takes_the_place_of_the_packaged_entry_with_its_aaguid(visitor, mds_fixture_snapshot):
    _upload(PACKAGED, "Uploaded")

    verifier = mds_verifier.get_mds_verifier()

    assert _described(verifier.find_entry_by_aaguid(Aaguid.parse(PACKAGED))) == "Uploaded"
    assert _described(verifier.find_entry_by_aaguid(Aaguid.parse("f1d0f1d0-0000-4000-8000-000000000002"))) is not None


def test_uploads_without_a_snapshot_are_metadata_of_their_own_the_newest_of_an_aaguid_found(visitor):
    _upload(OTHER, "Older")
    _upload(OTHER, "Newer")

    verifier = mds_verifier.get_mds_verifier()

    assert _described(verifier.find_entry_by_aaguid(Aaguid.parse(OTHER))) == "Newer"
    assert mds_verifier.get_mds_verifier() is not None


def test_without_a_snapshot_or_an_upload_there_is_no_verifier(visitor):
    assert mds_verifier.get_mds_verifier() is None


def test_the_verifier_holds_the_visitors_uploads_and_never_trusts_them(visitor):
    _upload(OTHER, "Uploaded")

    verifier = mds_verifier.get_mds_verifier()

    (entry,) = g._mds_session_entries
    assert verifier is not None
    assert mds_verifier.metadata_entry_trust_anchor_status(entry) is False
    assert mds_verifier.metadata_entry_trust_anchor_status(object()) is None
