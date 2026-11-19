"""``mds.verifier``: the MDS metadata attestations are checked against, a visitor's uploads first.

The verifier finds the entry fido2's ``MdsAttestationVerifier`` over the merged
metadata (the uploads, then the packaged entries no upload hides) found, parsing
only the entry found, and reading only the upload found.
"""
from __future__ import annotations

import copy
import json
import os
from datetime import date, datetime
from pathlib import Path

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

from server.app import visitor_session
from server.app.mds import cache as mds_cache
from server.app.mds import entries as mds_entries
from server.app.mds import files as mds_files
from server.app.mds import listed_uploads
from server.app.mds import uploads as mds_uploads
from server.app.mds import verifier as mds_verifier
from server.app.storage import session_metadata
from tests.app.metadata.cache_locks import FillingLock

PACKAGED = "f1d0f1d0-0000-4000-8000-000000000001"
OTHER = "0badc0de-0000-4000-8000-000000000001"
DUPLICATED = "d0d0d0d0-0000-4000-8000-000000000001"
REVOKED_LAST = "e0e0e0e0-0000-4000-8000-000000000001"
STATEMENT_ONLY = "5a5a5a5a-0000-4000-8000-000000000001"
FIXTURE_REVOKED = "f1d0f1d0-0000-4000-8000-000000000005"


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


def _uploads() -> list[dict]:
    """The visitor's uploads, the newest first."""

    return [
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


def _store(namespace: str, name: str, data: bytes, age: int) -> None:
    """``data`` stored as the upload ``name``, written ``age`` seconds before the others' first."""

    session_metadata.write_file(namespace, name, data)
    os.utime(Path(os.environ["FIDO_SERVER_SESSION_METADATA_DIR"]) / namespace / name, (2_000_000_000 - age,) * 2)


def _verifier(monkeypatch, packaged: list[dict] | None, uploads: list[dict] = ()):
    """``get_mds_verifier`` over ``packaged`` and the visitor's ``uploads``, the first the newest."""

    monkeypatch.setattr(mds_cache, "load_verified_entries", lambda: packaged)
    namespace = visitor_session.ensure_id()
    for age, raw in enumerate(uploads):
        _store(namespace, f"{age:032d}.json", json.dumps(raw).encode(), age)
    return mds_verifier.get_mds_verifier()


def _reference(packaged: list[dict], uploads: list[dict]) -> MdsAttestationVerifier:
    """fido2's verifier over the metadata the verifier used to merge: every packaged entry parsed."""

    kept, seen = [], set()
    for entry in (mds_entries.build_metadata_entry_components(raw)[0] for raw in uploads):
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
def test_every_lookup_finds_what_fido2s_verifier_over_the_merged_metadata_found(visitor, monkeypatch, mds_fixture_snapshot, with_uploads):
    packaged = _packaged(mds_fixture_snapshot)
    uploads = _uploads() if with_uploads else []
    reference = _reference(packaged, uploads)
    indexed = _verifier(monkeypatch, packaged, uploads)
    aaguids = {raw.get("aaguid") or raw["metadataStatement"].get("aaguid") for raw in packaged} | {OTHER}

    for aaguid in sorted(filter(None, aaguids)):
        found = indexed.find_entry_by_aaguid(Aaguid.parse(aaguid))
        assert _described(found) == _described(reference.find_entry_by_aaguid(Aaguid.parse(aaguid))), aaguid
    for chain in ([SHARED_BY_PACKAGED], [SHARED_WITH_UPLOAD], [UPLOAD_ONLY], [_certificate(104), SHARED_WITH_UPLOAD], [_certificate(104)]):
        assert _described(indexed.find_entry_by_chain(chain)) == _described(reference.find_entry_by_chain(chain))


def test_the_rules_the_lookups_follow(visitor, monkeypatch, mds_fixture_snapshot):
    indexed = _verifier(monkeypatch, _packaged(mds_fixture_snapshot), _uploads())
    by_aaguid = lambda aaguid: _described(indexed.find_entry_by_aaguid(Aaguid.parse(aaguid)))  # noqa: E731

    assert by_aaguid(PACKAGED) == "upload of the packaged AAGUID"
    assert by_aaguid(OTHER) == "upload, first"
    assert by_aaguid(DUPLICATED) is None  # hidden by a revoked upload
    assert by_aaguid(REVOKED_LAST) == "kept"  # the revoked one left out; the upload's statement hides nothing
    assert by_aaguid(STATEMENT_ONLY) is None
    assert _described(indexed.find_entry_by_chain([SHARED_WITH_UPLOAD])) == "key identifier, last"
    assert _described(indexed.find_entry_by_chain([UPLOAD_ONLY])) == "upload by key identifier"


def test_a_revoked_entry_is_found_apart_by_its_aaguid_and_uploads_hide_it_as_they_hide_the_others(visitor, monkeypatch, mds_fixture_snapshot):
    packaged = mds_verifier.PackagedEntries(_packaged(mds_fixture_snapshot))
    with_uploads = _verifier(monkeypatch, packaged.raw, _uploads())
    revoked = lambda verifier, aaguid: _described(verifier.find_revoked_entry_by_aaguid(Aaguid.parse(aaguid)))  # noqa: E731

    assert with_uploads.find_entry_by_aaguid(Aaguid.parse(FIXTURE_REVOKED)) is None
    assert revoked(with_uploads, FIXTURE_REVOKED) == "Fixture Revoked Key"
    assert revoked(with_uploads, REVOKED_LAST) == "revoked, last"
    assert revoked(with_uploads, DUPLICATED) == "revoked upload"  # it hides the packaged entries
    assert revoked(with_uploads, PACKAGED) is None
    assert revoked(mds_verifier.IndexedVerifier(packaged), DUPLICATED) is None
    monkeypatch.setattr(mds_cache, "load_verified_entries", lambda: None)
    assert revoked(mds_verifier.get_mds_verifier(), DUPLICATED) == "revoked upload"


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


def test_an_aaguid_or_key_identifier_that_does_not_read_indexes_nothing():
    unread = {**_raw("Unread", aaguid="not-an-aaguid"), "attestationCertificateKeyIdentifiers": ["zz", 7]}
    packaged = mds_verifier.PackagedEntries([unread, _raw("Read", aaguid=PACKAGED)])

    # Indexing passes over it: the readable entry is found, and no key identifier is indexed.
    assert _described(packaged.by_aaguid(Aaguid.parse(PACKAGED), frozenset())) == "Read"
    assert packaged._by_key_identifier == {}


def test_a_verifier_built_while_this_thread_waited_for_the_lock_is_the_one_used(mds_fixture_snapshot, monkeypatch):
    raw_entries = mds_cache.load_verified_entries()
    built = mds_verifier.IndexedVerifier(mds_verifier.PackagedEntries(raw_entries))
    monkeypatch.setattr(mds_cache.CACHE, "verifier", None)
    monkeypatch.setattr(mds_cache.CACHE, "verifier_lock", FillingLock(lambda: setattr(mds_cache.CACHE, "verifier", built)))

    assert mds_verifier._packaged_verifier() is built


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


def test_the_verifier_holds_the_visitors_uploads_it_found_and_never_trusts_them(visitor):
    _upload(OTHER, "Uploaded")

    entry = mds_verifier.get_mds_verifier().find_entry_by_aaguid(Aaguid.parse(OTHER))

    assert g._mds_session_entries == [entry]
    assert mds_verifier.metadata_entry_trust_anchor_status(entry) is False
    assert mds_verifier.metadata_entry_trust_anchor_status(object()) is None


def test_of_uploads_sharing_a_key_identifier_the_oldest_kept_is_found_as_fido2s_table_holds_it(visitor, monkeypatch):
    shared = _key_identifier(UPLOAD_ONLY)
    verifier = _verifier(monkeypatch, None, [
        {"metadataStatement": {"description": "newest"}, "attestationCertificateKeyIdentifiers": [shared]},
        {"metadataStatement": {"description": "older"}, "attestationCertificateKeyIdentifiers": [shared]},
        {"metadataStatement": {"description": "oldest, revoked"}, "attestationCertificateKeyIdentifiers": [shared],
         "statusReports": [{"status": "REVOKED"}]},
    ])

    assert _described(verifier.find_entry_by_chain([UPLOAD_ONLY])) == "older"


def test_an_upload_with_more_key_identifiers_than_are_kept_is_found_by_them_in_its_place(visitor, monkeypatch):
    many = [f"{number:040x}" for number in range(listed_uploads.KEY_IDENTIFIERS_BOUND)]
    verifier = _verifier(monkeypatch, None, [
        {"metadataStatement": {"description": "newest"}, "attestationCertificateKeyIdentifiers": [_key_identifier(UPLOAD_ONLY)]},
        {"metadataStatement": {"description": "many"}, "attestationCertificateKeyIdentifiers": [*many, _key_identifier(UPLOAD_ONLY)]},
        {"metadataStatement": {"description": "oldest"}, "attestationCertificateKeyIdentifiers": [_key_identifier(SHARED_WITH_UPLOAD)]},
    ])

    assert [upload.verifier_keys.key_identifiers is None for upload in listed_uploads.list_uploads()] == [False, True, False]
    assert _described(verifier.find_entry_by_chain([_certificate(104), UPLOAD_ONLY])) == "many"
    # A certificate that does not load after the one found is never reached, as before.
    assert _described(verifier.find_entry_by_chain([UPLOAD_ONLY, b"not a certificate"])) == "many"
    assert _described(verifier.find_entry_by_chain([SHARED_WITH_UPLOAD])) == "oldest"
    assert verifier.find_entry_by_chain([_certificate(104)]) is None


def test_an_upload_that_does_not_read_is_left_out_and_alone_leaves_the_snapshots_verifier(visitor, monkeypatch, mds_fixture_snapshot):
    packaged = mds_verifier.get_mds_verifier()
    namespace = visitor_session.ensure_id()
    _store(namespace, "broken.json", b"[]", 0)

    assert mds_verifier.get_mds_verifier() is packaged
    _store(namespace, "read.json", json.dumps(_raw("Uploaded", aaguid=PACKAGED)).encode(), 1)
    assert _described(mds_verifier.get_mds_verifier().find_entry_by_aaguid(Aaguid.parse(PACKAGED))) == "Uploaded"


@pytest.fixture
def reads(monkeypatch):
    """The files the store was asked for, by name."""

    names: list[str] = []
    read = session_metadata.read_file

    def _read(namespace, name):
        names.append(name)
        return read(namespace, name)

    monkeypatch.setattr(session_metadata, "read_file", _read)
    return names


def test_a_lookup_in_a_namespace_listed_before_reads_only_the_upload_it_finds(visitor, monkeypatch, reads):
    _verifier(monkeypatch, None, [
        _raw("other", aaguid=OTHER),
        _raw("by key identifier", key_ids=[UPLOAD_ONLY]),
        *(_raw(f"upload {number}", aaguid=f"0badc0de-0000-4000-8000-{number:012d}") for number in range(5)),
    ]).find_entry_by_aaguid(Aaguid.parse(OTHER))
    reads.clear()

    verifier = mds_verifier.get_mds_verifier()
    assert reads == []
    assert _described(verifier.find_entry_by_aaguid(Aaguid.parse(OTHER))) == "other"
    assert _described(verifier.find_entry_by_chain([UPLOAD_ONLY])) == "by key identifier"
    assert verifier.find_entry_by_aaguid(Aaguid.parse(PACKAGED)) is None
    assert verifier.find_entry_by_chain([SHARED_WITH_UPLOAD]) is None
    assert verifier.find_entry_by_aaguid(Aaguid.parse(OTHER)) is verifier.find_entry_by_aaguid(Aaguid.parse(OTHER))
    assert reads == [f"{0:032d}.json", f"{1:032d}.json"]


def test_an_upload_added_written_again_or_deleted_is_what_the_next_lookup_finds(visitor, monkeypatch):
    namespace = visitor_session.ensure_id()
    found = lambda: _described(mds_verifier.get_mds_verifier().find_entry_by_aaguid(Aaguid.parse(OTHER)))  # noqa: E731
    _verifier(monkeypatch, None, [_raw("first", aaguid=OTHER)])
    assert found() == "first"

    _store(namespace, "added.json", json.dumps(_raw("added", aaguid=OTHER)).encode(), -1)
    assert found() == "added"
    _store(namespace, "added.json", json.dumps(_raw("added, then written again", aaguid=OTHER)).encode(), -2)
    assert found() == "added, then written again"
    session_metadata.delete_file(namespace, "added.json")
    assert found() == "first"


def test_a_namespace_never_finds_another_namespaces_uploads(visitor, monkeypatch):
    # One name, one size and one time in each: only the namespace tells them apart.
    for namespace, description in (("a" * 32, "A's upload"), ("b" * 32, "B's upload")):
        _store(namespace, "same.json", json.dumps(_raw(description, aaguid=OTHER)).encode(), 0)

    for namespace, description in (("a" * 32, "A's upload"), ("b" * 32, "B's upload"), ("c" * 32, None)) * 2:
        monkeypatch.setattr(visitor_session, "current_id", lambda namespace=namespace: namespace)
        verifier = mds_verifier.get_mds_verifier()
        assert _described(verifier.find_entry_by_aaguid(Aaguid.parse(OTHER)) if verifier else None) == description
