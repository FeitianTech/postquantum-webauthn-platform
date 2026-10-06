"""Tests of mds build behavior."""

from __future__ import annotations

from server.app.mds import build as m


def test_snapshot_builders_keep_entry_ids_metadata_and_readable_entries(monkeypatch):
    entry_aaguid = {'aaguid': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'}
    assert m.build_entry_id(entry_aaguid).startswith('aaguid:')
    assert m.build_entry_id({'metadataStatement': {'aaid': 'AAID'}}) == 'aaid:AAID'
    assert m.build_entry_id({'metadataStatement': {'attestationCertificateKeyIdentifiers': ['KID']}}) == 'akid:kid'
    digest_id = m.build_entry_id({'metadataStatement': {}, 'statusReports': []})
    assert digest_id.startswith('entry:')
    meta = m.build_snapshot_meta({'entries': [1, 2], 'legalHeader': 'L'}, {'last_modified': 'x'}, source='session')
    assert meta['source'] == 'session'
    assert meta['entryCount'] == 2
    assert meta['generatedAt']
    explorer = m.build_explorer_snapshot({'entries': [{'metadataStatement': {'description': 'Name', 'protocolFamily': 'fido2'}, 'statusReports': []}, 'not-a-mapping']}, {'generated_at': '2026-01-01T00:00:00+00:00'}, include_detail=True, include_raw_entry=True)
    assert explorer['meta']['entryCount'] == 1
    assert explorer['entries'][0]['metadataStatement']['description'] == 'Name'
    bootstrap = m.build_bootstrap_snapshot({'entries': []}, {'generated_at': '2026-01-01T00:00:00+00:00'})
    assert bootstrap['meta']['entryCount'] == 0
