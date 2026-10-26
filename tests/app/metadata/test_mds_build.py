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


def test_an_id_already_given_out_gets_the_next_suffix_free():
    taken = {}

    assert [m.unique_entry_id("aaid:F1D0#0012", taken) for _ in range(3)] == ["aaid:F1D0#0012", "aaid:F1D0#0012~2", "aaid:F1D0#0012~3"]
    # An id that is itself spelled with a suffix takes that spelling, and the next suffix skips it.
    assert m.unique_entry_id("akid:ab~2", taken) == "akid:ab~2"
    assert m.unique_entry_id("akid:ab", taken) == "akid:ab"
    assert m.unique_entry_id("akid:ab", taken) == "akid:ab~3"
    assert m.unique_entry_id("akid:ab~2", taken) == "akid:ab~2~2"


def test_a_row_names_its_latest_status_beside_its_certification_text():
    entry = m.build_explorer_entry(
        {
            'metadataStatement': {'description': 'Key'},
            'statusReports': [
                {'status': 'FIDO_CERTIFIED_L2', 'effectiveDate': '2024-01-01', 'certificationDescriptor': 'Key'},
                {'status': 'UPDATE_AVAILABLE', 'effectiveDate': '2025-01-01'},
            ],
        },
        source='packaged',
        trust_anchor_status=True,
    )

    assert entry['latestStatus'] == 'Update Available'
    assert entry['certification'] == 'Update Available'
    assert 'certificationStatus' not in entry
