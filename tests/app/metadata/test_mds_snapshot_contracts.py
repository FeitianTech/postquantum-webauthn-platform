from __future__ import annotations

from datetime import date, datetime, timezone

from server.app.mds import build as m
from server.app.webauthn import signature_algorithms as names


def test_basic_mapping_string_list_and_byte_helpers():
    mapping = {'a': 1, 'b': 2}
    assert m._mapping_value(mapping, 'x', 'b', 'a') == 2
    assert m._mapping_value(mapping, 'x', 'y') is None

    assert m._string_or_none(' value ') == 'value'
    assert m._string_or_none('   ') is None
    assert m._string_or_none(123) is None

    assert m._extract_list(None) == []
    assert m._extract_list('') == []
    assert m._extract_list([1, None, '', 2]) == [1, 2]
    assert m._extract_list((1, None, 3)) == [1, 3]
    assert m._extract_list('x') == ['x']

    assert m._extract_byte_array(None) is None
    assert m._extract_byte_array([1, 2, 3]) == b'\x01\x02\x03'
    assert m._extract_byte_array(b'\x01\x02') == b'\x01\x02'
    assert m._extract_byte_array([1, 256]) is None
    assert m._extract_byte_array('bad') is None


def test_parse_and_format_date_paths():
    naive = datetime(2024, 1, 2, 3, 4, 5)
    aware = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    assert m._parse_date(naive).tzinfo == timezone.utc
    assert m._parse_date(aware).tzinfo == timezone.utc
    assert m._parse_date(date(2024, 1, 2)).tzinfo == timezone.utc
    assert m._parse_date(123) is None
    assert m._parse_date('  ') is None
    assert m._parse_date('2024-01-02T03:04:05Z') == datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert m._parse_date('2024-01-02T03:04:05+01:00') == datetime(2024, 1, 2, 2, 4, 5, tzinfo=timezone.utc)
    assert m._parse_date('2024-01-02') == datetime(2024, 1, 2, tzinfo=timezone.utc)
    # A zone needs a time: no ISO 8601 date is "2024-01-02Z".
    assert m._parse_date('2024-01-02Z') is None
    assert m._parse_date('not-a-date') is None

    assert m._format_date('2024-01-02') == 'Jan 2, 2024'
    assert m._format_date('not-a-date') == 'not-a-date'
    assert m._format_date(123) == ''


def test_guid_formatting_and_aaguid_normalisation_edge_cases():
    assert m.format_guid_candidate('AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA') == 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    assert m.format_guid_candidate('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') == 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    assert m.format_guid_candidate([0] * 16) == '00000000-0000-0000-0000-000000000000'
    assert m.format_guid_candidate(bytes(range(16))) == '00010203-0405-0607-0809-0a0b0c0d0e0f'
    # Not bytes: a value over 255 makes no AAGUID, where it once made a 33-digit one.
    assert m.format_guid_candidate([256] + [0] * 15) == ''
    assert m.format_guid_candidate('invalid') == ''

    class _BadStr:
        def __str__(self):
            raise RuntimeError('no str')

    assert m.format_guid_candidate(_BadStr()) == ''
    assert m.normalise_aaguid_key('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa') == 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'


def test_enum_protocol_certification_and_extraction_helpers():
    assert m._format_enum('fido_certified_l1') == 'Fido Certified L1'
    assert m._format_enum('') == ''
    assert m._format_protocol('fido2') == 'FIDO2'
    assert m._format_protocol('custom-proto') == 'Custom Proto'

    reports = [
        {'status': 'fido_certified_l1', 'effectiveDate': '2020-01-01', 'certificationDescriptor': 'Desc', 'certificateNumber': '1'},
        {'status': 'fido_certified_l2', 'effectiveDate': '2024-01-01', 'certificationDescriptor': 'Newest', 'certificateNumber': '2'},
    ]
    cert_text, cert_status = m._format_certification(reports)
    assert 'Newest' in cert_text and cert_status == 'FIDO_CERTIFIED_L2'
    assert m._format_certification([]) == ('', '')

    assert m._latest_effective_date(reports) == '2024-01-01'
    assert m._latest_effective_date([]) == ''

    uvd = [[{'userVerificationMethod': 'presence_internal'}], {'userVerificationMethod': 'fingerprint_internal'}]
    assert m._extract_user_verification(uvd) == ['Fingerprint Internal', 'Presence Internal']

    metadata = {'authenticatorGetInfo': {'transports': ['usb']}, 'transports': ['nfc', 'usb']}
    assert m._extract_transports(metadata) == ['Nfc', 'Usb']

    assert m._normalise_icon('http://icon', None) == 'http://icon'
    assert m._normalise_icon('iVBOR', 'image/png').startswith('data:image/png;base64,')
    assert m._normalise_icon(None, None) == ''


def test_name_identifier_aaguid_and_identifier_list_resolution():
    entry = {
        'statusReports': [{'certificationDescriptor': 'Status Name'}],
        'attestationCertificateKeyIdentifiers': ['ID1', 'id1', '', None, 'ID2'],
    }
    metadata = {
        'description': {'en': 'Dict Name'},
        'alternativeDescriptions': {'fr': 'Alt Name'},
        'aaid': 'AAID-1',
        'attestationCertificateKeyIdentifiers': ['id2', 'ID3'],
    }

    assert m._resolve_name({'description': 'Direct Name'}, entry) == 'Direct Name'
    assert m._resolve_name(metadata, entry) == 'Dict Name'
    assert m._resolve_name({'alternativeDescriptions': {'en': 'Alt'}}, entry) == 'Alt'
    assert m._resolve_name({}, entry) == 'Status Name'
    assert m._resolve_name({}, {'statusReports': []}) == 'Unknown Authenticator'

    assert m._resolve_identifier({'aaguid': 'AAG'}, {}) == 'AAG'
    assert m._resolve_identifier({}, {'aaguid': 'AAG2'}) == 'AAG2'
    assert m._resolve_identifier({}, {'aaid': 'AAID'}) == 'AAID'
    assert m._resolve_identifier({}, {'attestationCertificateKeyIdentifiers': ['KID']}) == 'KID'
    assert m._resolve_identifier({}, {}) == '—'

    assert m._resolve_aaguid({'aaguid': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}, {}) == 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    assert m._resolve_aaguid({}, {'aaguid': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}) == 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    assert m._resolve_aaguid({}, {}) == ''

    key_ids = m._extract_attestation_key_identifiers(metadata, entry)
    assert key_ids == ['id2', 'ID3', 'ID1']


def test_json_compaction_entry_id_meta_and_snapshot_builders(monkeypatch):
    payload = {'x': 1, 'y': 2}
    assert m._canonical_json(payload) == '{"x":1,"y":2}'

    compact = m._compact_metadata_statement(
        {
            'attestationRootCertificates': ['a'],
            'attestationCertificateKeyIdentifiers': ['b'],
            'icon': 'c',
            'iconType': 'd',
            'iconDark': 'e',
            'providerLogoLight': 'f',
            'providerLogoDark': 'g',
            'keep': 1,
        }
    )
    assert compact == {'keep': 1}

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

    explorer = m.build_explorer_snapshot(
        {
            'entries': [
                {
                    'metadataStatement': {'description': 'Name', 'protocolFamily': 'fido2'},
                    'statusReports': [],
                },
                'not-a-mapping',
            ]
        },
        {'generated_at': '2026-01-01T00:00:00+00:00'},
        include_detail=True,
        include_raw_entry=True,
    )
    assert explorer['meta']['entryCount'] == 1
    assert explorer['entries'][0]['metadataStatement']['description'] == 'Name'

    bootstrap = m.build_bootstrap_snapshot({'entries': []}, {'generated_at': '2026-01-01T00:00:00+00:00'})
    assert bootstrap['meta']['entryCount'] == 0


def test_a_guid_candidate_that_is_no_text_formats_as_empty():
    assert m.format_guid_candidate(12345) == ''


def test_a_certification_is_described_by_its_descriptor_or_else_its_status_and_number():
    assert m._format_certification([
        {'effectiveDate': '2026-01-01', 'certificationDescriptor': 'Only Descriptor'}
    ]) == ('Only Descriptor', '')

    cert_text, cert_status = m._format_certification([
        {'effectiveDate': '2026-01-01', 'status': 'FIDO_CERTIFIED_L1', 'certificateNumber': '42'}
    ])
    assert cert_status == 'FIDO_CERTIFIED_L1'
    assert '(42)' in cert_text


def test_user_verification_skips_entries_that_are_no_objects():
    assert m._extract_user_verification([['not-a-mapping']]) == []
    assert m._extract_user_verification([[{}]]) == []


def test_an_entry_without_a_readable_name_is_an_unknown_authenticator():
    name = m._resolve_name(
        {
            'description': {'en': '   '},
            'alternativeDescriptions': {'en': '   '},
        },
        {'statusReports': ['not-a-mapping', {'certificationDescriptor': '   '}]},
    )
    assert name == 'Unknown Authenticator'


def test_attestation_key_identifiers_are_trimmed_and_unique_ignoring_case():
    key_ids = m._extract_attestation_key_identifiers(
        {'attestationCertificateKeyIdentifiers': [None, '   ', 'A']},
        {'attestationCertificateKeyIdentifiers': ['a', 'B']},
    )
    assert key_ids == ['A', 'B']


def test_blank_names_format_as_empty():
    assert names.normalise_signature_algorithm_name('   ') == ''
    assert m._format_enum('A--B') == 'A B'
    assert names.format_hash_name('   ') == ''
    assert names.format_hash_name('abc-123') == 'ABC123'
