"""Tests of mds statement fields behavior."""

from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

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
    assert fields.certification_level(reports) == 'FIDO Certified L2 • Newest • (2)'
    assert fields.latest_status(reports) == 'FIDO Certified L2'
    assert fields.certification_level([]) == fields.latest_status([]) == ''

    assert fields.latest_effective_date(reports) == '2024-01-01'
    assert fields.latest_effective_date([]) == ''

    uvd = [[{'userVerificationMethod': 'presence_internal'}], {'userVerificationMethod': 'fingerprint_internal'}]
    assert fields.extract_user_verification(uvd) == ['Fingerprint Internal', 'Presence Internal']

    metadata = {'authenticatorGetInfo': {'transports': ['usb']}, 'transports': ['nfc', 'usb']}
    assert fields.extract_transports(metadata) == ['Nfc', 'Usb']

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


def test_a_report_without_a_descriptor_reads_as_its_status_and_number():
    assert fields.certification_level([
        {'effectiveDate': '2026-01-01', 'status': 'FIDO_CERTIFIED_L1', 'certificateNumber': '42'}
    ]) == 'FIDO Certified L1 • (42)'


def _report(status, date=None, **more):
    report = {"status": status, **more}
    if date is not None:
        report["effectiveDate"] = date
    return report


def test_the_latest_status_is_the_newest_report_whatever_it_says_and_the_level_stays():
    reports = [_report("FIDO_CERTIFIED_L2", "2024-01-01"), _report("UPDATE_AVAILABLE", "2025-06-01")]

    assert fields.latest_status(reports) == "Update Available"
    assert fields.certification_level(reports) == "FIDO Certified L2"


@pytest.mark.parametrize(
    ("statuses", "latest"),
    [
        (("FIDO_CERTIFIED", "FIDO_CERTIFIED_L1"), "FIDO Certified L1"),
        (("FIDO_CERTIFIED_L2", "FIDO_CERTIFIED_L1PLUS"), "FIDO Certified L2"),
        (("FIDO_CERTIFIED_L3PLUS", "UPDATE_AVAILABLE"), "Update Available"),
        (("UPDATE_AVAILABLE", "REVOKED", "FIDO_CERTIFIED_L2"), "Revoked"),
        (("USER_VERIFICATION_BYPASS", "ATTESTATION_KEY_COMPROMISE"), "Attestation KEY Compromise"),
        (("NOT_FIDO_CERTIFIED", "SELF_ASSERTION_SUBMITTED"), "SELF Assertion Submitted"),
        (("A_FUTURE_STATUS", "NOT_FIDO_CERTIFIED"), "NOT FIDO Certified"),
    ],
)
def test_of_reports_of_one_date_the_more_serious_status_is_the_latest_in_either_order(statuses, latest):
    reports = [_report(status, "2025-01-01") for status in statuses]

    assert fields.latest_status(reports) == latest
    assert fields.latest_status(list(reversed(reports))) == latest


def test_the_latest_status_code_is_the_latest_reports_status_as_mds_writes_it():
    reports = [_report("FIDO_CERTIFIED_L2", "2024-01-01"), _report("user_verification_bypass", "2025-06-01")]

    assert fields.latest_status_code(reports) == "USER_VERIFICATION_BYPASS"
    assert fields.latest_status(reports) == "USER Verification Bypass"
    assert fields.latest_status_code([]) == fields.latest_status_code("no reports") == ""


def test_reports_alike_but_for_their_descriptor_give_one_text_in_either_order():
    first = _report("FIDO_CERTIFIED_L1", "2025-01-01", certificationDescriptor="Key A", certificateNumber="1")
    second = _report("FIDO_CERTIFIED_L1", "2025-01-01", certificationDescriptor="Key B", certificateNumber="2")

    assert fields.certification_level([first, second]) == fields.certification_level([second, first]) == "FIDO Certified L1 • Key A • (1)"


def test_a_report_without_a_date_is_in_force_and_one_whose_date_does_not_read_is_the_oldest():
    # MDS3: a status without an effective date is effective while it is present.
    assert fields.latest_status([_report("FIDO_CERTIFIED_L1", "2025-01-01"), _report("REVOKED")]) == "Revoked"
    assert fields.latest_status([_report("REVOKED", "someday"), _report("FIDO_CERTIFIED_L1", "2025-01-01")]) == "FIDO Certified L1"
    assert fields.latest_status([_report("REVOKED", "someday")]) == "Revoked"


def test_a_report_without_a_status_is_passed_over():
    reports = [
        _report("", "2026-01-01"),
        {"effectiveDate": "2026-02-01", "certificationDescriptor": "Only Descriptor"},
        _report("fido_certified_l1", "2025-01-01"),
        "not a report",
    ]

    assert fields.latest_status(reports) == "FIDO Certified L1"
    assert fields.latest_status([{"certificationDescriptor": "Only Descriptor"}]) == ""


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


@pytest.mark.parametrize(
    "icon",
    [
        "http://example.com/icon.png",
        "HTTPS://example.com/icon.png",
        "//example.com/icon.png",
        "javascript:alert(1)",
        "not an icon",
        "iVBOR",
    ],
)
def test_an_icon_that_is_no_data_url_or_base64_is_none(icon):
    # The page's policy loads images from data: URLs only; another would be refused, and reported.
    assert fields.normalise_icon(icon, "image/png") == ""


def test_a_data_url_icon_is_kept_and_bare_base64_becomes_one():
    assert fields.normalise_icon(" data:image/svg+xml;base64,PHN2Zy8+ ", None) == "data:image/svg+xml;base64,PHN2Zy8+"
    assert fields.normalise_icon("DATA:image/png;base64,iVBORw0KGgo=", None) == "DATA:image/png;base64,iVBORw0KGgo="
    assert fields.normalise_icon("iVBORw0KGgo=", None) == "data:image/png;base64,iVBORw0KGgo="
    assert fields.normalise_icon("iVBORw0K\nGgo=", "image/webp") == "data:image/webp;base64,iVBORw0K\nGgo="


def test_a_lookup_reads_an_entrys_aaguid_and_aaid_or_else_its_statements():
    aaguid_key = "f1d0f1d0000040008000000000000001"
    assert fields.lookup_keys({"aaguid": "F1D0F1D0-0000-4000-8000-000000000001", "aaid": " F1D0#0012 "}) == (aaguid_key, "F1D0#0012")
    assert fields.lookup_keys(
        {"aaguid": "", "metadataStatement": {"aaguid": "f1d0f1d0-0000-4000-8000-000000000001", "aaid": "F1D0#0012"}}
    ) == (aaguid_key, "F1D0#0012")
    assert fields.lookup_keys({"aaid": 7, "metadataStatement": "not a statement"}) == ("", None)


def test_a_statements_icon_is_read_with_its_type_under_either_name():
    assert fields.statement_icon({"icon": "iVBORw0KGgo=", "iconType": "image/webp"}) == "data:image/webp;base64,iVBORw0KGgo="
    assert fields.statement_icon({"icon": "iVBORw0KGgo=", "icon_type": "image/gif"}) == "data:image/gif;base64,iVBORw0KGgo="
    assert fields.statement_icon({}) == ""


@pytest.mark.parametrize(
    ("reports", "level"),
    [
        ([_report("FIDO_CERTIFIED_L1", "2023-01-10"), _report("REVOKED", "2026-05-20")], "FIDO Certified L1"),
        ([_report("FIDO_CERTIFIED_L2", "2024-01-01"), _report("FIDO_CERTIFIED_L1", "2025-01-01")], "FIDO Certified L2"),
        ([_report("FIDO_CERTIFIED", "2025-01-01"), _report("FIDO_CERTIFIED_L1", "2025-01-01")], "FIDO Certified L1"),
        ([_report("FIDO_CERTIFIED_L3PLUS", "2025-01-01"), _report("FIDO_CERTIFIED_L4", "2020-01-01")], "FIDO Certified L4"),
        ([_report("FIDO_CERTIFIED_L1PLUS", "2025-01-01"), _report("FIDO_CERTIFIED_L1", "2026-01-01")], "FIDO Certified L1plus"),
        ([_report("NOT_FIDO_CERTIFIED", "2025-01-01"), _report("SELF_ASSERTION_SUBMITTED", "2026-01-01")], ""),
        ([_report("FIDO_CERTIFIEDX", "2025-01-01")], ""),
        ([], ""),
    ],
)
def test_the_certification_is_the_highest_level_reached(reports, level):
    assert fields.certification_level(reports) == level


def test_of_reports_at_the_highest_level_the_latest_describes_it():
    reports = [
        _report("FIDO_CERTIFIED_L1", "2023-01-01", certificationDescriptor="First", certificateNumber="1"),
        _report("FIDO_CERTIFIED_L1", "2025-01-01", certificationDescriptor="Renewed", certificateNumber="2"),
        _report("UPDATE_AVAILABLE", "2026-01-01"),
    ]

    assert fields.certification_level(reports) == "FIDO Certified L1 • Renewed • (2)"
    assert fields.latest_status(reports) == "Update Available"
