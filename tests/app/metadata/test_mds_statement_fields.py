"""Tests of mds statement fields behavior."""

from __future__ import annotations

from datetime import date, datetime, timezone

from server.app.mds import statement_fields as fields


def test_basic_mapping_string_list_and_byte_helpers():
    mapping = {'a': 1, 'b': 2}
    assert fields.mapping_value(mapping, 'x', 'b', 'a') == 2
    assert fields.mapping_value(mapping, 'x', 'y') is None

    assert fields.string_or_none(' value ') == 'value'
    assert fields.string_or_none('   ') is None
    assert fields.string_or_none(123) is None

    assert fields.extract_list(None) == []
    assert fields.extract_list('') == []
    assert fields.extract_list([1, None, '', 2]) == [1, 2]
    assert fields.extract_list((1, None, 3)) == [1, 3]
    assert fields.extract_list('x') == ['x']

    assert fields._extract_byte_array(None) is None
    assert fields._extract_byte_array([1, 2, 3]) == b'\x01\x02\x03'
    assert fields._extract_byte_array(b'\x01\x02') == b'\x01\x02'
    assert fields._extract_byte_array([1, 256]) is None
    assert fields._extract_byte_array('bad') is None


def test_parse_and_format_date_paths():
    naive = datetime(2024, 1, 2, 3, 4, 5)
    aware = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    assert fields._parse_date(naive).tzinfo == timezone.utc
    assert fields._parse_date(aware).tzinfo == timezone.utc
    assert fields._parse_date(date(2024, 1, 2)).tzinfo == timezone.utc
    assert fields._parse_date(123) is None
    assert fields._parse_date('  ') is None
    assert fields._parse_date('2024-01-02T03:04:05Z') == datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert fields._parse_date('2024-01-02T03:04:05+01:00') == datetime(2024, 1, 2, 2, 4, 5, tzinfo=timezone.utc)
    assert fields._parse_date('2024-01-02') == datetime(2024, 1, 2, tzinfo=timezone.utc)
    # A zone needs a time: no ISO 8601 date is "2024-01-02Z".
    assert fields._parse_date('2024-01-02Z') is None
    assert fields._parse_date('not-a-date') is None

    assert fields.format_date('2024-01-02') == 'Jan 2, 2024'
    assert fields.format_date('not-a-date') == 'not-a-date'
    assert fields.format_date(123) == ''


def test_guid_formatting_and_aaguid_normalisation_edge_cases():
    assert fields.format_guid_candidate('AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA') == 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    assert fields.format_guid_candidate('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') == 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    assert fields.format_guid_candidate([0] * 16) == '00000000-0000-0000-0000-000000000000'
    assert fields.format_guid_candidate(bytes(range(16))) == '00010203-0405-0607-0809-0a0b0c0d0e0f'
    # Not bytes: a value over 255 makes no AAGUID, where it once made a 33-digit one.
    assert fields.format_guid_candidate([256] + [0] * 15) == ''
    assert fields.format_guid_candidate('invalid') == ''

    class _BadStr:
        def __str__(self):
            raise RuntimeError('no str')

    assert fields.format_guid_candidate(_BadStr()) == ''


def test_enum_protocol_certification_and_extraction_helpers():
    assert fields.format_enum('fido_certified_l1') == 'Fido Certified L1'
    assert fields.format_enum('') == ''
    assert fields.format_protocol('fido2') == 'FIDO2'
    assert fields.format_protocol('custom-proto') == 'Custom Proto'

    reports = [
        {'status': 'fido_certified_l1', 'effectiveDate': '2020-01-01', 'certificationDescriptor': 'Desc', 'certificateNumber': '1'},
        {'status': 'fido_certified_l2', 'effectiveDate': '2024-01-01', 'certificationDescriptor': 'Newest', 'certificateNumber': '2'},
    ]
    cert_text, cert_status = fields.format_certification(reports)
    assert 'Newest' in cert_text and cert_status == 'FIDO_CERTIFIED_L2'
    assert fields.format_certification([]) == ('', '')

    assert fields.latest_effective_date(reports) == '2024-01-01'
    assert fields.latest_effective_date([]) == ''

    uvd = [[{'userVerificationMethod': 'presence_internal'}], {'userVerificationMethod': 'fingerprint_internal'}]
    assert fields.extract_user_verification(uvd) == ['Fingerprint Internal', 'Presence Internal']

    metadata = {'authenticatorGetInfo': {'transports': ['usb']}, 'transports': ['nfc', 'usb']}
    assert fields.extract_transports(metadata) == ['Nfc', 'Usb']

    assert fields.normalise_icon('http://icon', None) == 'http://icon'
    assert fields.normalise_icon('iVBOR', 'image/png').startswith('data:image/png;base64,')
    assert fields.normalise_icon(None, None) == ''


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

    assert fields.resolve_name({'description': 'Direct Name'}, entry) == 'Direct Name'
    assert fields.resolve_name(metadata, entry) == 'Dict Name'
    assert fields.resolve_name({'alternativeDescriptions': {'en': 'Alt'}}, entry) == 'Alt'
    assert fields.resolve_name({}, entry) == 'Status Name'
    assert fields.resolve_name({}, {'statusReports': []}) == 'Unknown Authenticator'

    assert fields.resolve_identifier({'aaguid': 'AAG'}, {}) == 'AAG'
    assert fields.resolve_identifier({}, {'aaguid': 'AAG2'}) == 'AAG2'
    assert fields.resolve_identifier({}, {'aaid': 'AAID'}) == 'AAID'
    assert fields.resolve_identifier({}, {'attestationCertificateKeyIdentifiers': ['KID']}) == 'KID'
    assert fields.resolve_identifier({}, {}) == '—'

    assert fields.resolve_aaguid({'aaguid': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}, {}) == 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    assert fields.resolve_aaguid({}, {'aaguid': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}) == 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    assert fields.resolve_aaguid({}, {}) == ''

    key_ids = fields.extract_attestation_key_identifiers(metadata, entry)
    assert key_ids == ['id2', 'ID3', 'ID1']


def test_json_compaction_keeps_only_statement_fields(monkeypatch):
    payload = {'x': 1, 'y': 2}
    assert fields.canonical_json(payload) == '{"x":1,"y":2}'
    compact = fields.compact_metadata_statement({'attestationRootCertificates': ['a'], 'attestationCertificateKeyIdentifiers': ['b'], 'icon': 'c', 'iconType': 'd', 'iconDark': 'e', 'providerLogoLight': 'f', 'providerLogoDark': 'g', 'keep': 1})
    assert compact == {'keep': 1}


def test_a_guid_candidate_that_is_no_text_formats_as_empty():
    assert fields.format_guid_candidate(12345) == ''


def test_a_certification_is_described_by_its_descriptor_or_else_its_status_and_number():
    assert fields.format_certification([
        {'effectiveDate': '2026-01-01', 'certificationDescriptor': 'Only Descriptor'}
    ]) == ('Only Descriptor', '')

    cert_text, cert_status = fields.format_certification([
        {'effectiveDate': '2026-01-01', 'status': 'FIDO_CERTIFIED_L1', 'certificateNumber': '42'}
    ])
    assert cert_status == 'FIDO_CERTIFIED_L1'
    assert '(42)' in cert_text


def test_user_verification_skips_entries_that_are_no_objects():
    assert fields.extract_user_verification([['not-a-mapping']]) == []
    assert fields.extract_user_verification([[{}]]) == []


def test_an_entry_without_a_readable_name_is_an_unknown_authenticator():
    name = fields.resolve_name(
        {
            'description': {'en': '   '},
            'alternativeDescriptions': {'en': '   '},
        },
        {'statusReports': ['not-a-mapping', {'certificationDescriptor': '   '}]},
    )
    assert name == 'Unknown Authenticator'


def test_attestation_key_identifiers_are_trimmed_and_unique_ignoring_case():
    key_ids = fields.extract_attestation_key_identifiers(
        {'attestationCertificateKeyIdentifiers': [None, '   ', 'A']},
        {'attestationCertificateKeyIdentifiers': ['a', 'B']},
    )
    assert key_ids == ['A', 'B']


def test_enum_names_replace_repeated_hyphens_with_spaces():
    assert fields.format_enum('A--B') == 'A B'
