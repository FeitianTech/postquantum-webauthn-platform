"""The verifier attestations are checked against: the verified snapshot's entries, a visitor's uploads first.

fido2's ``MdsAttestationVerifier`` parses every entry of a payload into its
dataclasses, about two seconds of CPU for the real snapshot, while a registration
needs one entry. So the packaged entries are indexed from the verified payload's
JSON (``PackagedEntries``) by the keys fido2's tables use, and an entry is parsed
when it is first found. The rules are fido2's and the merge's they replace:

- an entry is found by its own ``aaguid`` and ``attestationCertificateKeyIdentifiers``
  (not its statement's); a revoked entry is never found; of the entries with one
  key, the last wins;
- a visitor's upload hides every packaged entry whose statement has its
  statement's AAGUID, even when the upload itself is revoked; of two uploads with
  one such AAGUID the first listed (the newer) is kept;
- the uploads come before the packaged entries, so a key identifier both have
  finds the packaged entry.
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
from . import uploads as mds_uploads


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
        self._by_key_identifier: dict[bytes, list[int]] = {}
        for index, raw in enumerate(raw_entries):
            if not isinstance(raw, Mapping) or _revoked(raw):
                continue
            aaguid = _entry_aaguid(raw)
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
                entry = MetadataBlobPayloadEntry.from_dict(self.raw[index])
                self._parsed[index] = entry
                self._parsed_ids.add(id(entry))
            return entry

    def by_aaguid(self, aaguid: bytes, hidden: frozenset[str]) -> MetadataBlobPayloadEntry | None:
        """The last entry with ``aaguid`` that no upload hides."""

        return self._last(self._by_aaguid.get(bytes(aaguid), []), hidden)

    def by_key_identifier(self, identifier: bytes, hidden: frozenset[str]) -> MetadataBlobPayloadEntry | None:
        """The last entry with the key identifier that no upload hides."""

        return self._last(self._by_key_identifier.get(identifier, []), hidden)

    def holds(self, entry: Any) -> bool:
        """Whether ``entry`` is one of these, as parsed here."""

        with self._lock:
            return id(entry) in self._parsed_ids


class IndexedVerifier(MdsAttestationVerifier):
    """fido2's verifier over a visitor's uploads, with the packaged entries behind them."""

    def __init__(self, packaged: PackagedEntries | None, uploads: Sequence[MetadataBlobPayloadEntry] = ()):
        kept: list[MetadataBlobPayloadEntry] = []
        hidden: set[str] = set()
        for entry in uploads:
            aaguid = mds_entries._extract_entry_aaguid(entry)
            if aaguid and aaguid in hidden:
                continue
            if aaguid:
                hidden.add(aaguid)
            kept.append(entry)
        today = datetime.now(timezone.utc).date()
        super().__init__(MetadataBlobPayload(legal_header="", no=0, next_update=today, entries=tuple(kept)))
        self.packaged = packaged
        self._hidden = frozenset(hidden)

    def find_entry_by_aaguid(self, aaguid: Aaguid) -> MetadataBlobPayloadEntry | None:
        found = self.packaged.by_aaguid(aaguid, self._hidden) if self.packaged is not None else None
        return found if found is not None else super().find_entry_by_aaguid(aaguid)

    def find_entry_by_chain(self, certificate_chain: Sequence[bytes]) -> MetadataBlobPayloadEntry | None:
        for der in certificate_chain:
            certificate = x509.load_der_x509_certificate(der)
            identifier = x509.SubjectKeyIdentifier.from_public_key(certificate.public_key()).digest
            found = self.packaged.by_key_identifier(identifier, self._hidden) if self.packaged is not None else None
            if found is None:
                found = self._ski_table.get(identifier)
            if found is not None:
                return found
        return None


def metadata_entry_trust_anchor_status(entry: Any) -> bool | None:
    """Return whether *entry* originates from a trust-anchored metadata source.

    Returns ``False`` for session-uploaded entries, ``True`` for entries of the
    verified FIDO MDS snapshot, and ``None`` when the origin cannot be
    established. Unknown entries are never reported as trusted.
    """

    if entry is None or not isinstance(entry, MetadataBlobPayloadEntry):
        return None

    # Session-uploaded entries are tracked per request (see get_mds_verifier) so
    # that concurrent requests from other sessions cannot change the outcome.
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
    session_items = mds_uploads.list_session_metadata_items()
    session_entries = tuple(
        entry
        for entry in (getattr(item, "entry", None) for item in session_items)
        if entry is not None
    )

    if has_request_context():
        # Holding the entry objects on ``g`` keeps their ids valid for the
        # lifetime of the request.
        g._mds_session_entries = session_entries
        g._mds_session_entry_ids = frozenset(id(entry) for entry in session_entries)

    if not session_entries:
        return packaged
    return IndexedVerifier(packaged.packaged if packaged is not None else None, session_entries)
