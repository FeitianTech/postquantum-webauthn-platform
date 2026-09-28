import { describe, expect, it } from 'vitest';

// The MDS explorer's leaves the current UI's views also used, which their tests
// reached through the advanced/mds/utils.js barrel until Phase 30 removed it with
// those views: each function imported from its own leaf.
import {
  extractAttestationKeyIdentifiers,
  extractByteArray,
  extractList,
  extractTransports,
  extractUserVerification,
} from '../../../../frontend/static/scripts/advanced/mds/utils/extractors.js';
import {
  formatCertificateDateDisplay,
  formatCertification,
  formatDate,
  formatDetailValue,
  formatEnum,
  formatProtocol,
  formatSignatureHashName,
  formatUpv,
  normaliseEnumKey,
  parseIsoDate,
} from '../../../../frontend/static/scripts/advanced/mds/utils/formatters.js';
import {
  formatGuidCandidate,
  normaliseAaguid,
  normaliseIcon,
  resolveAaguid,
  resolveIdentifier,
  resolveName,
} from '../../../../frontend/static/scripts/advanced/mds/utils/resolvers.js';
import { latestEffectiveDate } from '../../../../frontend/static/scripts/advanced/mds/utils/status-reports.js';

function createSampleStatusReports() {
  return [
    {
      status: 'NOT_FIDO_CERTIFIED',
      effectiveDate: '2024-04-01T00:00:00Z',
      certificationDescriptor: 'Old',
      certificateNumber: '001',
    },
    {
      status: 'FIDO_CERTIFIED_L1',
      effectiveDate: '2025-05-10T00:00:00Z',
      certificationDescriptor: 'L1',
      certificateNumber: '1234',
    },
  ];
}

function createMetadataStatement() {
  return {
    description: 'Acme Security Key',
    protocolFamily: 'fido2',
    userVerificationDetails: [
      [
        { userVerificationMethod: 'presence_internal' },
        { userVerificationMethod: 'fingerprint_internal' },
      ],
      [{ userVerificationMethod: 'presence_internal' }],
    ],
    attachmentHint: ['internal'],
    authenticatorGetInfo: {
      transports: ['usb', 'nfc'],
    },
    transports: ['ble'],
    keyProtection: ['hardware'],
    authenticationAlgorithms: ['secp256r1_ecdsa_sha256_raw'],
    icon: 'ZmFrZS1wbmc=',
    iconType: 'image/png',
    attestationRootCertificates: ['CERT_BASE64_A', 'CERT_BASE64_B'],
    attestationCertificateKeyIdentifiers: ['Key-A', 'key-a', '  KEY-B  '],
    upv: [{ major: 1, minor: 0 }, { Major: 1, Minor: 1 }],
  };
}

function createRawEntry() {
  return {
    aaguid: '00112233445566778899aabbccddeeff',
    metadataStatement: createMetadataStatement(),
    statusReports: createSampleStatusReports(),
    timeOfLastStatusChange: '2025-05-11T09:30:00Z',
  };
}

describe('mds-utils', () => {
  it('formats enums/protocols/keys and detail values consistently', () => {
    expect(formatEnum('FIDO_CERTIFIED_L1')).toBe('FIDO Certified L1');
    expect(formatEnum('uvm-passcode_internal')).toBe('Uvm Passcode Internal');

    expect(normaliseEnumKey('  fido certified-l1 ')).toBe('FIDO_CERTIFIED_L1');
    expect(normaliseEnumKey(null)).toBe('');

    expect(formatProtocol('fido2')).toBe('FIDO2');
    expect(formatProtocol('fido_2_custom')).toBe('Fido 2 Custom');

    expect(formatDetailValue(true)).toBe('true');
    expect(formatDetailValue(['a', false, null])).toBe('a, false, —');
    expect(formatDetailValue(undefined)).toBe('—');
  });

  it('normalizes icons and identifier/name/aaguid resolution fallbacks', () => {
    expect(normaliseIcon('https://example.com/icon.png', 'image/png')).toBe('https://example.com/icon.png');
    expect(normaliseIcon('data:image/png;base64,AAAA', 'image/png')).toBe('data:image/png;base64,AAAA');
    expect(normaliseIcon('AAAA', 'image/svg+xml')).toBe('data:image/svg+xml;base64,AAAA');
    expect(normaliseIcon('', 'image/png')).toBe('');

    expect(resolveName({ description: '  Primary Name ' }, {})).toBe('Primary Name');
    expect(resolveName({ description: { en: 'Localized Name' } }, {})).toBe('Localized Name');
    expect(resolveName({ alternativeDescriptions: { fr: 'Nom FR' } }, {})).toBe('Nom FR');
    expect(resolveName({}, { statusReports: [{ certificationDescriptor: 'Descriptor Name' }] })).toBe('Descriptor Name');
    expect(resolveName({}, {})).toBe('Unknown Authenticator');

    expect(resolveIdentifier({ aaguid: 'AAGUID-ENTRY' }, {})).toBe('AAGUID-ENTRY');
    expect(resolveIdentifier({}, { aaguid: 'AAGUID-META' })).toBe('AAGUID-META');
    expect(resolveIdentifier({}, { aaid: 'AAID-1234' })).toBe('AAID-1234');
    expect(resolveIdentifier({}, { attestationCertificateKeyIdentifiers: ['key-id-1'] })).toBe('key-id-1');
    expect(resolveIdentifier({}, {})).toBe('—');

    expect(resolveAaguid({ aaguid: '00112233445566778899AABBCCDDEEFF' }, {})).toBe(
      '00112233-4455-6677-8899-aabbccddeeff',
    );
    expect(resolveAaguid({}, {})).toBe('');
    expect(normaliseAaguid('00112233-4455-6677-8899-AABBCCDDEEFF')).toBe('00112233-4455-6677-8899-aabbccddeeff');
  });

  it('parses guid candidates and byte-array like inputs', () => {
    expect(formatGuidCandidate('00112233445566778899aabbccddeeff')).toBe('00112233-4455-6677-8899-aabbccddeeff');
    expect(formatGuidCandidate('00112233-4455-6677-8899-aabbccddeeff')).toBe('00112233-4455-6677-8899-aabbccddeeff');

    const bytes = new Uint8Array([
      0x00, 0x11, 0x22, 0x33,
      0x44, 0x55,
      0x66, 0x77,
      0x88, 0x99,
      0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]);
    expect(formatGuidCandidate(bytes)).toBe('00112233-4455-6677-8899-aabbccddeeff');
    expect(formatGuidCandidate({ toString: () => '00112233445566778899aabbccddeeff' })).toBe(
      '00112233-4455-6677-8899-aabbccddeeff',
    );
    expect(formatGuidCandidate('not-guid')).toBe('');

    expect(extractByteArray([1, 2, 3])).toEqual([1, 2, 3]);
    expect(extractByteArray(bytes)).toEqual(Array.from(bytes));
    expect(extractByteArray(new DataView(bytes.buffer))).toEqual(Array.from(bytes));
    expect(extractByteArray(bytes.buffer)).toEqual(Array.from(bytes));
    expect(extractByteArray(['1', 2])).toBeNull();
    expect(extractByteArray(null)).toBeNull();
  });

  it('extracts and formats transport, verification, UPV, and attestation key identifiers', () => {
    const metadata = createMetadataStatement();

    expect(extractList('single')).toEqual(['single']);
    expect(extractList(['a', '', null, 'b'])).toEqual(['a', 'b']);
    expect(extractList(null)).toEqual([]);

    expect(extractUserVerification(metadata.userVerificationDetails)).toEqual([
      'Fingerprint Internal',
      'Presence Internal',
    ]);

    expect(extractTransports(metadata)).toEqual(['Ble', 'Nfc', 'Usb']);

    expect(formatUpv(metadata.upv)).toEqual(['1.0', '1.1']);
    expect(formatUpv(null)).toEqual([]);

    expect(extractAttestationKeyIdentifiers(metadata, { attestationCertificateKeyIdentifiers: ['key-c'] })).toEqual([
      'Key-A',
      'KEY-B',
      'key-c',
    ]);
  });

  it('formats status and date values for metadata timelines', () => {
    const reports = createSampleStatusReports();

    const certification = formatCertification(reports);
    expect(certification.status).toBe('FIDO_CERTIFIED_L1');
    expect(certification.display).toContain('FIDO Certified L1');
    expect(certification.display).toContain('L1');
    expect(certification.display).toContain('1234');

    expect(formatCertification([])).toEqual({ display: '', status: '' });

    expect(latestEffectiveDate(reports)).toBe('2025-05-10T00:00:00Z');
    expect(latestEffectiveDate([])).toBe('');

    expect(parseIsoDate('2025-03-14T12:00:00Z')).toBeInstanceOf(Date);
    expect(parseIsoDate('')).toBeNull();
    expect(parseIsoDate('not-a-date')).toBeNull();

    expect(formatDate('2025-03-14T12:00:00Z')).toMatch(/2025/);
    expect(formatDate('not-a-date')).toBe('not-a-date');
    expect(formatDate('')).toBe('');

    expect(formatCertificateDateDisplay('2025-03-14T12:00:00Z')).toContain('GMT');
    expect(formatCertificateDateDisplay('bad-date')).toBe('bad-date');
    expect(formatCertificateDateDisplay(null)).toBe('');
  });
});
