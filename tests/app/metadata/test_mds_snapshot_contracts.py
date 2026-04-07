from __future__ import annotations

from datetime import date, datetime, timezone
import types

import pytest

import server.app.mds_snapshot as m


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
    assert m._extract_byte_array([1, 2, 3]) == [1, 2, 3]
    assert m._extract_byte_array(b'\x01\x02') == [1, 2]
    assert m._extract_byte_array('bad') is None


def test_parse_and_format_date_paths():
    naive = datetime(2024, 1, 2, 3, 4, 5)
    aware = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    assert m._parse_date(naive).tzinfo == timezone.utc
    assert m._parse_date(aware).tzinfo == timezone.utc
    assert m._parse_date(date(2024, 1, 2)).tzinfo == timezone.utc
    assert m._parse_date(123) is None
    assert m._parse_date('  ') is None
    assert m._parse_date('2024-01-02T03:04:05Z') is not None
    assert m._parse_date('2024-01-02') is not None
    assert m._parse_date('not-a-date') is None

    assert m._format_date('2024-01-02') == 'Jan 2, 2024'
    assert m._format_date('not-a-date') == 'not-a-date'
    assert m._format_date(123) == ''


def test_guid_formatting_and_aaguid_normalisation_edge_cases():
    assert m.format_guid_candidate('AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA') == 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    assert m.format_guid_candidate('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') == 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    assert m.format_guid_candidate([0] * 16) == '00000000-0000-0000-0000-000000000000'
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


def test_algorithm_and_certificate_decoding_helpers(monkeypatch):
    assert m._normalise_signature_algorithm_name('ecdsa-with-sha256') == 'ECDSA'
    assert m._normalise_signature_algorithm_name('rsassa-pss') == 'RSASSA-PSS'
    assert m._normalise_signature_algorithm_name('rsa encryption') == 'RSASSA-PKCS1-v1_5'
    assert m._normalise_signature_algorithm_name('ed25519') == 'ED25519'
    assert m._normalise_signature_algorithm_name('ed448') == 'ED448'
    assert m._normalise_signature_algorithm_name('dsa') == 'DSA'
    assert m._normalise_signature_algorithm_name('custom-alg') == 'CUSTOMALG'

    assert m._format_hash_value('sha256') == 'SHA256'
    assert m._format_hash_value(' SHA-1 ') == 'SHA1'
    assert m._format_hash_value('') == ''
    assert m._derive_certificate_algorithm_info('ecdsa', 'sha256') == 'ECDSA_SHA256'

    assert m._decode_der_certificate(b'bytes') == b'bytes'
    assert m._decode_der_certificate('YQ') == b'a'
    assert m._decode_der_certificate(123) is None

    fake_cert = types.SimpleNamespace(
        signature_hash_algorithm=types.SimpleNamespace(name='sha256'),
        signature_algorithm_oid=types.SimpleNamespace(_name='ecdsa-with-SHA256', dotted_string='1.2.3'),
        subject=types.SimpleNamespace(
            get_attributes_for_oid=lambda _oid: [types.SimpleNamespace(value='CN1'), types.SimpleNamespace(value='CN1')]
        ),
    )

    monkeypatch.setattr(m, '_decode_der_certificate', lambda value: b'der' if value != 'skip' else None)
    monkeypatch.setattr(m.x509, 'load_der_x509_certificate', lambda _der: fake_cert)

    algs, cns = m._summarise_attestation_certificates(['cert-a', 'skip'])
    assert algs == ['ECDSA_SHA256']
    assert cns == ['CN1']

    class _CertNoHash:
        @property
        def signature_hash_algorithm(self):
            raise m.UnsupportedAlgorithm('x')

        signature_algorithm_oid = types.SimpleNamespace(_name='unknown oid', dotted_string='1.2.3.4')
        subject = types.SimpleNamespace(get_attributes_for_oid=lambda _oid: [])

    monkeypatch.setattr(m.x509, 'load_der_x509_certificate', lambda _der: _CertNoHash())
    algs2, cns2 = m._summarise_attestation_certificates(['cert-b'])
    assert algs2 == ['1.2.3.4']
    assert cns2 == []


def test_json_compaction_entry_id_meta_and_snapshot_builders(monkeypatch):
    payload = {'x': 1, 'y': 2}
    assert m._canonical_json(payload) == '{"x":1,"y":2}'

    compact = m._compact_metadata_statement(
        {
            'attestationRootCertificates': ['a'],
            'attestationCertificateKeyIdentifiers': ['b'],
            'icon': 'c',
            'iconType': 'd',
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


def test_mds_snapshot_residual_branch_cases(monkeypatch):
    # format_guid_candidate fallback through str(value)
    assert m.format_guid_candidate(12345) == ''

    # certification formatting with empty status and descriptor-only payload
    cert_text, cert_status = m._format_certification([
        {'effectiveDate': '2026-01-01', 'certificationDescriptor': 'Only Descriptor'}
    ])
    assert cert_status == ''
    assert cert_text == 'Only Descriptor'

    # descriptor-missing path with status + certificate number
    cert_text2, cert_status2 = m._format_certification([
        {'effectiveDate': '2026-01-01', 'status': 'FIDO_CERTIFIED_L1', 'certificateNumber': '42'}
    ])
    assert cert_status2 == 'FIDO_CERTIFIED_L1'
    assert '(42)' in cert_text2

    # user verification ignores non-mapping entries
    assert m._extract_user_verification([['not-a-mapping']]) == []
    assert m._extract_user_verification([[{}]]) == []

    # resolve_name should fall through empty mapping/status values
    name = m._resolve_name(
        {
            'description': {'en': '   '},
            'alternativeDescriptions': {'en': '   '},
        },
        {'statusReports': ['not-a-mapping', {'certificationDescriptor': '   '}]},
    )
    assert name == 'Unknown Authenticator'

    # attestation key identifiers ignore None/whitespace and dedupe case-insensitively
    key_ids = m._extract_attestation_key_identifiers(
        {'attestationCertificateKeyIdentifiers': [None, '   ', 'A']},
        {'attestationCertificateKeyIdentifiers': ['a', 'B']},
    )
    assert key_ids == ['A', 'B']

    # force defensive candidate-empty branch via helper monkeypatch
    original_extract_list = m._extract_list
    monkeypatch.setattr(m, '_extract_list', lambda _value: [None, '', 'A'])
    forced = m._extract_attestation_key_identifiers({}, {})
    assert forced == ['A']
    monkeypatch.setattr(m, '_extract_list', original_extract_list)

    assert m._normalise_signature_algorithm_name('   ') == ''
    assert m._format_enum('A--B') == 'A B'
    assert m._format_hash_value('   ') == ''
    assert m._format_hash_value('abc-123') == 'ABC123'
    assert m._decode_der_certificate('   ') is None

    # summarizer: duplicate algorithms and non-string/blank CN values are skipped
    class _FakeCert:
        signature_hash_algorithm = types.SimpleNamespace(name='sha256')
        signature_algorithm_oid = types.SimpleNamespace(_name='ecdsa-with-SHA256', dotted_string='1.2.3')
        subject = types.SimpleNamespace(
            get_attributes_for_oid=lambda _oid: [
                types.SimpleNamespace(value=123),
                types.SimpleNamespace(value='   '),
                types.SimpleNamespace(value='CN-Valid'),
            ]
        )

    monkeypatch.setattr(m, '_decode_der_certificate', lambda _value: b'der')
    monkeypatch.setattr(m.x509, 'load_der_x509_certificate', lambda _der: _FakeCert())

    algs, cns = m._summarise_attestation_certificates(['cert-a', 'cert-b'])
    assert algs == ['ECDSA_SHA256']
    assert cns == ['CN-Valid']
