"""The verifier attestations are checked against: the verified snapshot's entries, a visitor's uploads first.

fido2's ``MdsAttestationVerifier`` parses every entry of a payload into its
dataclasses, about two seconds of CPU for the real snapshot, while a registration
needs one entry. So the packaged entries are indexed from the verified payload's
JSON (``PackagedEntries``) by the keys fido2's tables use, and an entry is parsed
when it is first found. The rules are fido2's and the merge's they replace:

- an entry is found by its own ``aaguid`` and ``attestationCertificateKeyIdentifiers``
  (not its statement's); a revoked entry is never found, but asked for apart by its
  AAGUID (``find_revoked_entry_by_aaguid``), so a registration can say so; of the
  entries with one key, the last wins;
- a visitor's upload hides every packaged entry whose statement has its
  statement's AAGUID, even when the upload itself is revoked; of two uploads with
  one such AAGUID the first listed (the newer) is kept;
- the uploads come before the packaged entries, so a key identifier both have
  finds the packaged entry.

A visitor's uploads are indexed the same way, from what ``mds.listed_uploads`` keeps of
each for its version (``VerifierKeys``), and an upload is read when a lookup finds it.
"""
from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from fido2.mds3 import (
    MdsAttestationVerifier,
    MetadataBlobPayload,
    MetadataBlobPayloadEntry,
)
from fido2.webauthn import Aaguid
from flask import g, has_request_context

from . import cache as mds_cache
from . import entries as mds_entries
from . import listed_uploads
from . import uploads as mds_uploads


def _certificate_key_identifier(der: bytes) -> bytes:
    certificate = x509.load_der_x509_certificate(der)
    return x509.SubjectKeyIdentifier.from_public_key(certificate.public_key()).digest


def _revoked(raw: Mapping[str, Any]) -> bool:
    reports = raw.get("statusReports")
    return isinstance(reports, list) and any(
        isinstance(report, Mapping) and report.get("status") == "REVOKED" for report in reports
    )


def _entry_aaguid(raw: Mapping[str, Any]) -> Aaguid | None:
    value = raw.get("aaguid")
    if not isinstance(value, str):
        return None
    try:
        aaguid = Aaguid.parse(value)
    except ValueError:
        return None
    return aaguid or None


def _key_identifiers(raw: Mapping[str, Any]) -> list[bytes]:
    values = raw.get("attestationCertificateKeyIdentifiers")
    identifiers: list[bytes] = []
    for value in values if isinstance(values, list) else []:
        try:
            identifiers.append(bytes.fromhex(value))
        except (TypeError, ValueError):
            continue
    return identifiers


def _statement_aaguid(raw: Mapping[str, Any]) -> str | None:
    statement = raw.get("metadataStatement")
    return mds_entries._normalise_aaguid(statement.get("aaguid")) if isinstance(statement, Mapping) else None


class PackagedEntries:
    """The verified snapshot's entries as JSON, found as fido2's tables find them, each parsed when first found."""

    def __init__(self, raw_entries: list[Any]):
        self.raw = raw_entries
        self._by_aaguid: dict[bytes, list[int]] = {}
        self._revoked_by_aaguid: dict[bytes, list[int]] = {}
        self._by_key_identifier: dict[bytes, list[int]] = {}
        for index, raw in enumerate(raw_entries):
            if not isinstance(raw, Mapping):
                continue
            aaguid = _entry_aaguid(raw)
            if _revoked(raw):
                if aaguid:
                    self._revoked_by_aaguid.setdefault(aaguid, []).append(index)
                continue
            if aaguid:
                self._by_aaguid.setdefault(aaguid, []).append(index)
            for identifier in _key_identifiers(raw):
                self._by_key_identifier.setdefault(identifier, []).append(index)
        self._parsed: dict[int, MetadataBlobPayloadEntry] = {}
        self._parsed_ids: set[int] = set()
        self._lock = threading.Lock()

    def _last(self, indices: list[int], hidden: frozenset[str]) -> MetadataBlobPayloadEntry | None:
        for index in reversed(indices):
            if _statement_aaguid(self.raw[index]) not in hidden:
                return self._parse(index)
        return None

    def _parse(self, index: int) -> MetadataBlobPayloadEntry:
        with self._lock:
            entry = self._parsed.get(index)
            if entry is None:
                entry = mds_entries.parse_entry(self.raw[index])
                self._parsed[index] = entry
                self._parsed_ids.add(id(entry))
            return entry

    def by_aaguid(self, aaguid: bytes, hidden: frozenset[str]) -> MetadataBlobPayloadEntry | None:
        """The last entry with ``aaguid`` that no upload hides."""

        return self._last(self._by_aaguid.get(bytes(aaguid), []), hidden)

    def revoked_by_aaguid(self, aaguid: bytes, hidden: frozenset[str]) -> MetadataBlobPayloadEntry | None:
        """The last revoked entry with ``aaguid`` that no upload hides."""

        return self._last(self._revoked_by_aaguid.get(bytes(aaguid), []), hidden)

    def by_key_identifier(self, identifier: bytes, hidden: frozenset[str]) -> MetadataBlobPayloadEntry | None:
        """The last entry with the key identifier that no upload hides."""

        return self._last(self._by_key_identifier.get(identifier, []), hidden)

    def holds(self, entry: Any) -> bool:
        """Whether ``entry`` is one of these, as parsed here."""

        with self._lock:
            return id(entry) in self._parsed_ids


class IndexedVerifier(MdsAttestationVerifier):
    """fido2's verifier over the uploads of the visitor's ``namespace``, the newest first, with
    the packaged entries behind them. An upload is read when a lookup finds it, once."""

    def __init__(
        self,
        packaged: PackagedEntries | None,
        namespace: str = "",
        uploads: Sequence[listed_uploads.ListedUpload] = (),
    ):
        today = datetime.now(timezone.utc).date()
        super().__init__(MetadataBlobPayload(legal_header="", no=0, next_update=today, entries=()))
        self.packaged = packaged
        self._namespace = namespace
        kept: list[listed_uploads.ListedUpload] = []
        hidden: set[str] = set()
        for upload in uploads:
            aaguid = upload.verifier_keys.hides
            if aaguid and aaguid in hidden:
                continue
            if aaguid:
                hidden.add(aaguid)
            kept.append(upload)
        self._hidden = frozenset(hidden)
        # As fido2's tables: revoked uploads left out, and of the uploads with one key the last
        # (the oldest) kept. The newest revoked upload of an AAGUID is found apart.
        self._live = [upload for upload in kept if not upload.verifier_keys.revoked]
        self._by_aaguid = {upload.verifier_keys.aaguid: upload for upload in self._live if upload.verifier_keys.aaguid}
        self._revoked: dict[bytes, listed_uploads.ListedUpload] = {}
        for upload in kept:
            if upload.verifier_keys.aaguid and upload.verifier_keys.revoked:
                self._revoked.setdefault(upload.verifier_keys.aaguid, upload)
        self._by_key_identifier: dict[bytes, int] = {}
        self._unindexed: list[int] = []
        for position, upload in enumerate(self._live):
            if upload.verifier_keys.key_identifiers is None:
                self._unindexed.append(position)
            for identifier in upload.verifier_keys.key_identifiers or ():
                self._by_key_identifier[identifier] = position
        self._entries: dict[str, MetadataBlobPayloadEntry | None] = {}

    def _entry(self, upload: listed_uploads.ListedUpload | None) -> MetadataBlobPayloadEntry | None:
        if upload is None:
            return None
        if upload.filename not in self._entries:
            entry = mds_uploads.read_upload_entry(self._namespace, upload.filename)
            self._entries[upload.filename] = entry
            if entry is not None and has_request_context():
                # Held on ``g``, its id stays valid while the request lasts.
                g.setdefault("_mds_session_entries", []).append(entry)
                g.setdefault("_mds_session_entry_ids", set()).add(id(entry))
        return self._entries[upload.filename]

    def find_entry_by_aaguid(self, aaguid: Aaguid) -> MetadataBlobPayloadEntry | None:
        found = self.packaged.by_aaguid(aaguid, self._hidden) if self.packaged is not None else None
        return found if found is not None else self._entry(self._by_aaguid.get(bytes(aaguid)))

    def find_revoked_entry_by_aaguid(self, aaguid: Aaguid) -> MetadataBlobPayloadEntry | None:
        """The revoked entry with ``aaguid``, which ``find_entry_by_aaguid`` never finds: the
        packaged one no upload hides, else a revoked upload's."""

        found = self.packaged.revoked_by_aaguid(aaguid, self._hidden) if self.packaged is not None else None
        return found if found is not None else self._entry(self._revoked.get(bytes(aaguid)))

    def find_entry_by_chain(self, certificate_chain: Sequence[bytes]) -> MetadataBlobPayloadEntry | None:
        unindexed: dict[int, set[bytes]] | None = None
        for der in certificate_chain:
            identifier = _certificate_key_identifier(der)
            found = self.packaged.by_key_identifier(identifier, self._hidden) if self.packaged is not None else None
            if found is None:
                if unindexed is None:
                    unindexed = self._unindexed_identifiers(certificate_chain)
                position = self._by_key_identifier.get(identifier, -1)
                position = max([position, *(later for later, held in unindexed.items() if identifier in held)])
                found = self._entry(self._live[position]) if position >= 0 else None
            if found is not None:
                return found
        return None

    def _unindexed_identifiers(self, certificate_chain: Sequence[bytes]) -> dict[int, set[bytes]]:
        """Of each upload with more key identifiers than are kept, read again one at a time,
        those of ``certificate_chain``'s certificates."""

        if not self._unindexed:
            return {}
        wanted: set[bytes] = set()
        for der in certificate_chain:
            try:
                wanted.add(_certificate_key_identifier(der))
            except Exception:  # find_entry_by_chain raises it when it reaches this certificate
                continue
        held: dict[int, set[bytes]] = {}
        for position in self._unindexed:
            entry = mds_uploads.read_upload_entry(self._namespace, self._live[position].filename)
            held[position] = wanted.intersection(entry.attestation_certificate_key_identifiers or ()) if entry else set()
        return held


def metadata_entry_trust_anchor_status(entry: Any) -> bool | None:
    """Return whether *entry* originates from a trust-anchored metadata source.

    Returns ``False`` for session-uploaded entries, ``True`` for entries of the
    verified FIDO MDS snapshot, and ``None`` when the origin cannot be
    established. Unknown entries are never reported as trusted.
    """

    if entry is None or not isinstance(entry, MetadataBlobPayloadEntry):
        return None

    # Session-uploaded entries are tracked per request (see IndexedVerifier._entry)
    # so that concurrent requests from other sessions cannot change the outcome.
    request_session_ids = (
        getattr(g, "_mds_session_entry_ids", None) if has_request_context() else None
    )
    if request_session_ids and id(entry) in request_session_ids:
        return False
    verifier = mds_cache.CACHE.verifier
    if verifier is not None and verifier.packaged is not None and verifier.packaged.holds(entry):
        return True

    return None


def _packaged_verifier() -> IndexedVerifier | None:
    """The verifier over the verified snapshot alone, one for each version of its file."""

    raw_entries = mds_cache.load_verified_entries()
    if raw_entries is None:
        return None
    cached = mds_cache.CACHE.verifier
    if cached is not None and cached.packaged is not None and cached.packaged.raw is raw_entries:
        return cached
    with mds_cache.CACHE.verifier_lock:
        cached = mds_cache.CACHE.verifier
        if cached is not None and cached.packaged is not None and cached.packaged.raw is raw_entries:
            return cached
        verifier = IndexedVerifier(PackagedEntries(raw_entries))
        mds_cache.CACHE.verifier = verifier
        return verifier


def get_mds_verifier() -> MdsAttestationVerifier | None:
    """Return an MDS attestation verifier using session metadata when available."""

    packaged = _packaged_verifier()
    namespace, uploads = listed_uploads.list_namespace_uploads()
    if not uploads:
        return packaged
    return IndexedVerifier(packaged.packaged if packaged is not None else None, namespace, uploads)
