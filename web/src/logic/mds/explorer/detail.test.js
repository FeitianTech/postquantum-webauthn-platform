import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  DEFAULT_DETAIL_TITLE,
  detailSections,
  detailSubtitleParts,
  detailTitle,
  extractList,
  formatDetailSubtitle,
  rawListValues,
} from './detail.js';
import { BIOMETRIC_REPORT_COLUMNS, STATUS_REPORT_COLUMNS } from './status-reports.js';
import { repoFile } from '@/test/logic/repo-file.js';

const FIXTURE = JSON.parse(readFileSync(repoFile('tests/fixtures/mds/snapshot/fido-mds3.explorer.full.json'), 'utf8'));
const named = name => FIXTURE.entries.find(entry => entry.name === name);

const section = (entry, key) => detailSections(entry).find(candidate => candidate.key === key);

describe('the detail page: title and subtitle', () => {
  it('titles the page with the name as written, else "Authenticator"', () => {
    expect(DEFAULT_DETAIL_TITLE).toBe('Authenticator');
    expect(detailTitle({ name: ' Key ' })).toBe(' Key ');
    expect(detailTitle({ name: '   ' })).toBe('Authenticator');
    expect(detailTitle({ name: 7 })).toBe('Authenticator');
    expect(detailTitle(null)).toBe('Authenticator');
  });

  it('names the AAGUID, the id when it is another, and the protocol', () => {
    const fido2 = named('Fixture Security Key L1');
    expect(formatDetailSubtitle(fido2)).toBe(`AAGUID: ${fido2.aaguid} • FIDO2`);
    expect(detailSubtitleParts(fido2)).toEqual([
      { label: 'AAGUID', value: fido2.aaguid },
      { label: '', value: 'FIDO2' },
    ]);
    expect(formatDetailSubtitle(named('Fixture UAF Authenticator'))).toBe('ID: F1D0#0012 • Uaf');
    expect(formatDetailSubtitle({ aaguid: 'a', id: 'b' })).toBe('AAGUID: a • ID: b');
    expect(formatDetailSubtitle({})).toBe('');
    expect(detailSubtitleParts(null)).toEqual([]);
  });
});

describe('the detail page: sections', () => {
  it('orders the sections as the page shows them', () => {
    expect(detailSections(named('Fixture Security Key L1')).map(({ key, title }) => [key, title])).toEqual([
      ['overview', 'Overview'],
      ['metadataStatement', 'Metadata Statement'],
      ['userVerification', 'User Verification Details'],
      ['certificates', 'Attestation Root Certificates'],
      ['authenticatorGetInfo', 'Authenticator Get Info'],
      ['statusReports', 'Status Reports'],
    ]);
  });

  it('keeps the Overview and the Metadata Statement even with nothing under them', () => {
    expect(detailSections(null)).toEqual([
      { key: 'overview', title: 'Overview', fields: [{ label: 'Identifier', value: '—' }], chipLists: [] },
      { key: 'metadataStatement', title: 'Metadata Statement', fields: [], chipLists: [] },
    ]);
    expect(detailSections({ metadataStatement: 'not an object', statusReports: 'none' })).toHaveLength(2);
  });

  it('shows the overview fields that have a value, identifiers marked', () => {
    const entry = named('Fixture Security Key L1');
    expect(section(entry, 'overview').fields).toEqual([
      { label: 'Identifier', value: entry.id, identifier: true },
      { label: 'AAGUID', value: entry.aaguid, identifier: true },
      { label: 'Protocol', value: 'FIDO2' },
      { label: 'Certification', value: entry.certification },
      { label: 'Authenticator Version', value: '2' },
      { label: 'Date Updated', value: entry.dateUpdated },
    ]);
    // A blank id is no field; a missing one reads "—"; a version of 0 is shown.
    expect(section({ id: '  ', metadataStatement: { authenticatorVersion: 0 } }, 'overview').fields).toEqual([
      { label: 'Authenticator Version', value: '0' },
    ]);
  });

  it('shows the statement fields, key identifiers as codes, UPV, and the chip lists of raw values', () => {
    const u2f = named('Fixture U2F Key');
    const statement = section(u2f, 'metadataStatement');
    expect(statement.fields.map(field => field.label)).toEqual([
      'Description',
      'Legal Header',
      'Schema',
      'Crypto Strength',
      'Attestation Certificate Key IDs',
      'UPV',
    ]);
    expect(statement.fields[4]).toEqual({ label: 'Attestation Certificate Key IDs', codes: u2f.attestationKeyIdentifiers });
    expect(statement.chipLists.map(list => list.label)).toEqual([
      'Authentication Algorithms',
      'Public Key Algorithms',
      'Attestation Types',
      'Key Protection',
      'Matcher Protection',
      'Attachment Hints',
    ]);

    const odd = section(
      {
        attestationKeyIdentifiers: ['  ab ', '', 'cd'],
        metadataStatement: {
          description: '   ',
          legalHeader: '',
          schema: 0,
          cryptoStrength: null,
          upv: [{ major: 1, minor: 0 }, { Major: 2, Minor: 1 }, {}],
          tcDisplay: 'any',
        },
      },
      'metadataStatement',
    );
    expect(odd.fields).toEqual([
      { label: 'Schema', value: '0' },
      { label: 'Attestation Certificate Key IDs', codes: ['ab', 'cd'] },
      { label: 'UPV', value: '1.0, 2.1' },
    ]);
    expect(odd.chipLists).toEqual([{ label: 'TC Display', values: ['any'] }]);
  });

  it('writes a list value as the metadata does', () => {
    const noJson = Object.assign(Object.create(null), { big: 1n });
    expect(
      rawListValues(['a', 1, 2n, true, false, null, { x: 1 }, [1, 2], () => 1, Symbol('s'), { big: 1n }, noJson, '']),
    // A false or null item is dropped with the empty ones, as the list reader does.
    ).toEqual(['a', '1', '2', 'true', '{"x":1}', '[1,2]', '[object Object]']);
    expect(rawListValues('one')).toEqual(['one']);
    expect(rawListValues(undefined)).toEqual([]);
  });

  it('lists each combination with a method or a code accuracy, counting those left out', () => {
    const details = [
      [
        { userVerificationMethod: 'passcode_internal', caDesc: { base: 10, minLength: 4, maxRetries: 5, blockSlowdown: 30 } },
        { userVerificationMethod: 'fingerprint_internal', baDesc: { selfAttestedFRR: 0.01, selfAttestedFAR: 0.00002, maxTemplates: 5, maxRetries: 5, blockSlowdown: 0 } },
      ],
      [],
      [null, 'text'],
      { userVerificationMethod: 'pattern_internal', paDesc: { minComplexity: 9, maxRetries: 3, blockSlowdown: 60 } },
      [{ caDesc: { base: 36, maxRetries: null } }],
      [{ userVerificationMethod: '' }],
      [{ userVerificationMethod: 0, caDesc: 'not a descriptor' }],
    ];
    expect(section({ metadataStatement: { userVerificationDetails: details } }, 'userVerification').combinations).toEqual([
      {
        title: 'Combination 1',
        methods: [
          {
            method: 'passcode_internal',
            codeAccuracy: 'Base: 10 • Min length: 4 • Max retries: 5 • Block slowdown: 30',
            biometricAccuracy: '',
            patternAccuracy: '',
          },
          {
            method: 'fingerprint_internal',
            codeAccuracy: '',
            biometricAccuracy: 'Self-attested FRR: 0.01 • Self-attested FAR: 0.00002 • Max templates: 5 • Max retries: 5 • Block slowdown: 0',
            patternAccuracy: '',
          },
        ],
      },
      {
        title: 'Combination 4',
        methods: [{ method: 'pattern_internal', codeAccuracy: '', biometricAccuracy: '', patternAccuracy: 'Min complexity: 9 • Max retries: 3 • Block slowdown: 60' }],
      },
      {
        title: 'Combination 5',
        methods: [{ method: '', codeAccuracy: 'Base: 36 • Max retries: null', biometricAccuracy: '', patternAccuracy: '' }],
      },
      { title: 'Combination 7', methods: [{ method: '0', codeAccuracy: '', biometricAccuracy: '', patternAccuracy: '' }] },
    ]);
    expect(section({ metadataStatement: { userVerificationDetails: [[{ userVerificationMethod: '' }]] } }, 'userVerification')).toBeUndefined();
    expect(section({ metadataStatement: { userVerificationDetails: 'none' } }, 'userVerification')).toBeUndefined();
  });

  it('numbers the certificates that are not empty', () => {
    expect(section({ attestationCertificates: ['', 'MIIB', null, 'MIIC'] }, 'certificates').certificates).toEqual([
      { number: 1, label: 'Certificate 1', certificate: 'MIIB' },
      { number: 2, label: 'Certificate 2', certificate: 'MIIC' },
    ]);
    expect(section({ attestationCertificates: [''] }, 'certificates')).toBeUndefined();
    expect(section({ attestationCertificates: 'MIIB' }, 'certificates')).toBeUndefined();
  });

  it('shows getInfo, its AAGUID dashed, its numbers, chips and options', () => {
    const info = section(
      {
        metadataStatement: {
          authenticatorGetInfo: {
            aaguid: 'F1D0F1D0000040008000000000000001',
            maxMsgSize: 1200,
            maxCredentialCountInList: 8,
            maxCredentialIdLength: 128,
            maxSerializedLargeBlobArray: 1024,
            minPINLength: 4,
            firmwareVersion: 0,
            maxCredBlobLength: 32,
            maxRPIDsForSetMinPINLength: 1,
            remainingDiscoverableCredentials: 25,
            versions: ['FIDO_2_0'],
            extensions: ['credProtect'],
            transports: ['usb'],
            algorithms: [{ type: 'public-key', alg: -7 }],
            pinUvAuthProtocols: [1, 2],
            options: { rk: true, up: false, uv: null },
          },
        },
      },
      'authenticatorGetInfo',
    );
    expect(info.title).toBe('Authenticator Get Info');
    expect(info.fields).toEqual([
      { label: 'AAGUID', value: 'f1d0f1d0-0000-4000-8000-000000000001', identifier: true },
      { label: 'Max Message Size', value: '1200' },
      { label: 'Max Credential Count', value: '8' },
      { label: 'Max Credential ID Length', value: '128' },
      { label: 'Max Serialized Large Blob Array', value: '1024' },
      { label: 'Min PIN Length', value: '4' },
      { label: 'Firmware Version', value: '0' },
      { label: 'Max Cred Blob Length', value: '32' },
      { label: 'Max RP IDs for Set Min PIN Length', value: '1' },
      { label: 'Remaining Discoverable Credentials', value: '25' },
    ]);
    expect(info.chipLists).toEqual([
      { label: 'Versions', values: ['FIDO_2_0'] },
      { label: 'Extensions', values: ['credProtect'] },
      { label: 'Transports', values: ['usb'] },
      { label: 'Algorithms', values: ['{"type":"public-key","alg":-7}'] },
      { label: 'pinUvAuth Protocols', values: ['1', '2'] },
      { label: 'Options', values: ['rk: true', 'up: false'] },
    ]);

    // An AAGUID that is not one is shown as written; an empty getInfo still has its heading.
    expect(section({ metadataStatement: { authenticatorGetInfo: { aaguid: 'nope', options: 'x' } } }, 'authenticatorGetInfo')).toEqual({
      key: 'authenticatorGetInfo',
      title: 'Authenticator Get Info',
      fields: [{ label: 'AAGUID', value: 'nope', identifier: true }],
      chipLists: [],
    });
    expect(section({ metadataStatement: { authenticatorGetInfo: {} } }, 'authenticatorGetInfo').fields).toEqual([]);
    expect(section({ metadataStatement: { authenticatorGetInfo: { options: {} } } }, 'authenticatorGetInfo').chipLists).toEqual([]);
  });

  it('gives each status report its cells, the descriptor column\'s two lines and its certificate', () => {
    expect(STATUS_REPORT_COLUMNS).toEqual(['Status', 'Effective Date', 'Authenticator Version', 'Certificate Number', 'Descriptor']);
    const reports = section(
      {
        statusReports: [
          null,
          { status: '', certificateNumber: 0 },
          {
            status: 'FIDO_CERTIFIED_L1',
            effectiveDate: '2026-09-01',
            authenticatorVersion: 0,
            certificateNumber: 'FIDO20020260901001',
            certificationDescriptor: 'Fixture Security Key',
            url: 'https://example.com/certificate',
            certificationPolicyVersion: '1.4.0',
            certificationRequirementsVersion: '1.3',
          },
          { url: 'https://example.com/only-url' },
        ],
      },
      'statusReports',
    );
    expect(reports.columns).toBe(STATUS_REPORT_COLUMNS);
    expect(reports.fields).toBeUndefined();
    expect(reports.statusReports).toEqual([
      { status: '', effectiveDate: '—', authenticatorVersion: '—', certificateNumber: '—', descriptor: '', details: '', certificate: '' },
      {
        status: 'FIDO_CERTIFIED_L1',
        effectiveDate: '2026-09-01',
        authenticatorVersion: '0',
        certificateNumber: 'FIDO20020260901001',
        descriptor: 'Fixture Security Key • https://example.com/certificate',
        details: 'Policy: 1.4.0 • Requirements: 1.3',
        certificate: '',
      },
      {
        status: '—',
        effectiveDate: '—',
        authenticatorVersion: '—',
        certificateNumber: '—',
        descriptor: 'https://example.com/only-url',
        details: '',
        certificate: '',
      },
    ]);
    expect(section({ statusReports: [] }, 'statusReports')).toBeUndefined();
  });

  it('shows every other field a status report has, and the entry\'s last status change', () => {
    const reports = section(
      {
        timeOfLastStatusChange: '2026-09-01',
        statusReports: [
          {
            status: 'FIDO_CERTIFIED_L1',
            effectiveDate: '2026-09-01',
            certificate: 'MIIB',
            notYetDefined: { kept: true },
            fipsPhysicalSecurityLevel: 2,
            sunsetDate: '2029-09-01',
            certificationProfiles: ['consumer', 'enterprise'],
            fipsRevision: 3,
            certificationRequirementsVersion: '1.3',
            certificationPolicyVersion: '1.4.0',
            listOfThings: [{ a: 1 }, 'b'],
            empty: '',
            nothing: null,
          },
        ],
      },
      'statusReports',
    );
    expect(reports.fields).toEqual([{ label: 'Last Status Change', value: '2026-09-01' }]);
    expect(reports.statusReports[0].certificate).toBe('MIIB');
    expect(reports.statusReports[0].details).toBe(
      [
        'Policy: 1.4.0',
        'Requirements: 1.3',
        'Profiles: consumer, enterprise',
        'Sunset Date: 2029-09-01',
        'FIPS Revision: 3',
        'FIPS Physical Security Level: 2',
        'Not Yet Defined: {"kept":true}',
        'List Of Things: {"a":1}, b',
      ].join(' • '),
    );
    expect(section({ statusReports: [{ certificate: 7 }] }, 'statusReports').statusReports[0].certificate).toBe('');
  });

  it('lists the biometric status reports after the status reports, in a table of the same shape', () => {
    const entry = named('Fixture Security Key L2');
    expect(detailSections(entry).map(({ key, title }) => [key, title]).slice(-2)).toEqual([
      ['statusReports', 'Status Reports'],
      ['biometricStatusReports', 'Biometric Status Reports'],
    ]);
    const biometric = section(entry, 'biometricStatusReports');
    expect(BIOMETRIC_REPORT_COLUMNS).toEqual(['Modality', 'Effective Date', 'Certification Level', 'Certificate Number', 'Descriptor']);
    expect(biometric.columns).toBe(BIOMETRIC_REPORT_COLUMNS);
    expect(biometric.fields).toBeUndefined();
    expect(biometric.statusReports).toEqual([
      {
        status: 'fingerprint_internal',
        effectiveDate: '2026-08-15',
        authenticatorVersion: '1',
        certificateNumber: 'FIDOBIO20260815002',
        descriptor: 'Fixture Fingerprint Sensor',
        details: 'Policy: 1.4.0 • Requirements: 3.0',
        certificate: '',
      },
    ]);
    // A field a status report has is only a detail of a biometric report, and the other way round.
    const crossed = { status: 'REVOKED', authenticatorVersion: 2, modality: 'face_internal', certLevel: 2 };
    expect(section({ biometricStatusReports: [null, crossed] }, 'biometricStatusReports').statusReports[0]).toMatchObject({
      status: 'face_internal',
      authenticatorVersion: '2',
      details: 'Status: REVOKED • Authenticator Version: 2',
    });
    expect(section({ statusReports: [crossed] }, 'statusReports').statusReports[0]).toMatchObject({
      status: 'REVOKED',
      details: 'Modality: face_internal • Cert Level: 2',
    });
    expect(section({ biometricStatusReports: [] }, 'biometricStatusReports')).toBeUndefined();
    expect(section({ biometricStatusReports: 'none' }, 'biometricStatusReports')).toBeUndefined();
  });

  it('shows the entry\'s rogue list over its status reports, with or without reports', () => {
    const entry = named('Fixture Security Key L2');
    expect(section(entry, 'statusReports').fields).toEqual([
      { label: 'Last Status Change', value: entry.timeOfLastStatusChange },
      { label: 'Rogue List URL', value: 'https://fixture.example/rogue-lists/fixture-security-key-l2.json' },
      { label: 'Rogue List Hash', value: entry.rogueListHash, identifier: true },
    ]);
    expect(section({ rogueListHash: 'ab', timeOfLastStatusChange: '2026-01-01' }, 'statusReports')).toEqual({
      key: 'statusReports',
      title: 'Status Reports',
      fields: [
        { label: 'Last Status Change', value: '2026-01-01' },
        { label: 'Rogue List Hash', value: 'ab', identifier: true },
      ],
    });
    expect(section({ timeOfLastStatusChange: '2026-01-01', rogueListURL: ' ' }, 'statusReports')).toBeUndefined();
  });
});

describe('extractList', () => {
  it('lists a value, keeps a list\'s values, and lists nothing for none', () => {
    expect(extractList('single')).toEqual(['single']);
    expect(extractList(['a', '', null, 'b'])).toEqual(['a', 'b']);
    expect(extractList(null)).toEqual([]);
  });
});
