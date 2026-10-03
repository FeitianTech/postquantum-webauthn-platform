import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { DEFAULT_DETAIL_TITLE, detailSections, detailSubtitleParts, detailTitle, formatDetailSubtitle } from './detail.js';
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

  it('shows the statement\'s other descriptions and friendly names, one field for each language', () => {
    const fields = section(named('Fixture Security Key L2'), 'metadataStatement').fields;
    expect(fields.slice(0, 6)).toEqual([
      { label: 'Description', value: 'Fixture Security Key L2' },
      { label: 'Description (de-DE)', value: 'Fixture Sicherheitsschlüssel L2' },
      { label: 'Description (zh-CN)', value: 'Fixture 安全密钥 L2' },
      { label: 'Friendly Name (en-US)', value: 'Fixture Security Key L2' },
      { label: 'Friendly Name (zh-CN)', value: 'Fixture 安全密钥 L2' },
      { label: 'Legal Header', value: named('Fixture Security Key L2').metadataStatement.legalHeader },
    ]);
    const odd = section(
      { metadataStatement: { friendlyNames: { 'en-US': ' ', fr: 7, de: null }, alternativeDescriptions: ['not', 'by', 'language'] } },
      'metadataStatement',
    );
    expect(odd.fields).toEqual([{ label: 'Friendly Name (fr)', value: '7' }]);
    expect(section({ metadataStatement: { friendlyNames: 'Name' } }, 'metadataStatement').fields).toEqual([]);
  });

  it('says whether the statement\'s key is restricted, wants fresh user verification, or syncs, as it says it', () => {
    const fields = section(named('Fixture Security Key L2'), 'metadataStatement').fields;
    const first = fields.findIndex(({ label }) => label === 'Key Restricted');
    expect(fields.slice(first, first + 3)).toEqual([
      { label: 'Key Restricted', value: 'true' },
      { label: 'Fresh User Verification Required', value: 'false' },
      { label: 'Multi-Device Credential Support', value: 'unsupported' },
    ]);
    // Neither is guessed from MDS3's default when the statement leaves it out.
    expect(section(named('Fixture Security Key L1'), 'metadataStatement').fields.map(({ label }) => label)).not.toContain('Key Restricted');
  });

  it('shows the supported extensions and how the transaction display shows its text', () => {
    const statement = section(named('Fixture Security Key L2'), 'metadataStatement');
    const contentType = statement.fields.findIndex(({ label }) => label === 'TC Display Content Type');
    expect(statement.fields.slice(contentType, contentType + 3)).toEqual([
      { label: 'TC Display Content Type', value: 'image/png' },
      {
        label: 'TC Display PNG 1',
        value: 'Width: 320 • Height: 480 • Bit depth: 16 • Color type: 2 • Compression: 0 • Filter: 0 • Interlace: 0',
      },
      {
        label: 'TC Display PNG 2',
        value:
          'Width: 32 • Height: 32 • Bit depth: 1 • Color type: 3 • Compression: 0 • Filter: 0 • Interlace: 0 • ' +
          'Palette: rgb(255, 255, 255), rgb(0, 0, 0)',
      },
    ]);
    expect(statement.chipLists.slice(-2)).toEqual([
      { label: 'TC Display', values: ['any', 'hardware'] },
      { label: 'Supported Extensions', values: ['hmac-secret', 'credProtect (tag 1, data 03, fail if unknown)'] },
    ]);

    const odd = section(
      {
        metadataStatement: {
          tcDisplayPNGCharacteristics: [null, { plte: [{ r: 1, g: 2 }, 'grey'] }],
          supportedExtensions: ['credBlob', { tag: 0 }, [], { id: 'x', fail_if_unknown: false, data: '' }, null],
        },
      },
      'metadataStatement',
    );
    expect(odd.fields).toEqual([{ label: 'TC Display PNG', value: 'Palette: {"r":1,"g":2}, grey' }]);
    expect(odd.chipLists).toEqual([{ label: 'Supported Extensions', values: ['credBlob', '(tag 0)', 'x'] }]);
    expect(section({ metadataStatement: { tcDisplayPNGCharacteristics: {} } }, 'metadataStatement').fields).toEqual([]);
  });

  it('shows every other member of the statement, a later version\'s named from its key', () => {
    const fields = section(named('Fixture Security Key L2'), 'metadataStatement').fields;
    expect(fields.slice(-3)).toEqual([
      { label: 'Credential Exchange Config URL', value: 'https://fixture.example/credential-exchange.json' },
      { label: 'Fixture Future Statement Field', value: 'A statement field no MDS3 version defines' },
      { label: 'Operating Environment', value: 'Secure Element (SE)' },
    ]);
    const odd = section(
      {
        metadataStatement: {
          ecdaaTrustAnchors: [{ X: 'x', Y: 'y' }],
          iconDark: 'data:image/png;base64,AA==',
          laterList: ['a', 2],
          laterFlag: false,
          laterNothing: null,
          laterEmpty: [],
        },
      },
      'metadataStatement',
    );
    expect(odd.fields).toEqual([
      { label: 'ECDAA Trust Anchors', value: '{"X":"x","Y":"y"}' },
      { label: 'Later List', value: 'a, 2' },
      { label: 'Later Flag', value: 'false' },
    ]);
    // The overview, the sections and the fields above show the rest of these statements.
    for (const name of ['Fixture Security Key L1', 'Fixture U2F Key', 'Fixture UAF Authenticator']) {
      expect(section(named(name), 'metadataStatement').fields.at(-1).label).toBe('UPV');
    }
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
      { status: '', effectiveDate: '—', authenticatorVersion: '—', certificateNumber: '0', descriptor: '', details: '', certificate: '' },
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
    expect(section({ statusReports: [{ certificateNumber: '' }] }, 'statusReports').statusReports[0].certificateNumber).toBe('—');
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
