import { describe, expect, it } from 'vitest';

import {
  collectOptionSets,
  createSummaryItem,
  decodeBase64Url,
  determinePublicKeyAlgorithm,
  extractAttestationKeyIdentifiers,
  extractByteArray,
  extractList,
  extractTransports,
  extractUserVerification,
  formatCertificateDateDisplay,
  formatCertification,
  formatDate,
  formatDetailValue,
  formatEnum,
  formatGuidCandidate,
  formatProtocol,
  formatSignatureHashName,
  formatUpv,
  latestEffectiveDate,
  normaliseAaguid,
  normaliseEnumKey,
  normaliseIcon,
  parseIsoDate,
  renderCertificatePublicKey,
  renderCertificateSignature,
  renderCertificateSummary,
  resolveAaguid,
  resolveIdentifier,
  resolveName,
  transformEntry,
  transformEntryLightweight,
  upgradeEntryToFull,
} from '../../static/scripts/advanced/mds-utils.js';

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

  it('transforms entries, builds option sets, and upgrades lightweight rows', () => {
    const rawEntry = createRawEntry();

    const full = transformEntry(rawEntry, 7);
    expect(full.index).toBe(7);
    expect(full.name).toBe('Acme Security Key');
    expect(full.protocol).toBe('FIDO2');
    expect(full.id).toBe(rawEntry.aaguid);
    expect(full.aaguid).toBe('00112233-4455-6677-8899-aabbccddeeff');
    expect(full.userVerificationList).toContain('Presence Internal');
    expect(full.attachmentList).toEqual(['Internal']);
    expect(full.transportsList).toEqual(['Ble', 'Nfc', 'Usb']);
    expect(full.keyProtectionList).toEqual(['Hardware']);
    expect(full.algorithmsList).toEqual(['SECP256R1 Ecdsa SHA256 Raw']);
    expect(full.attestationCertificates).toEqual(['CERT_BASE64_A', 'CERT_BASE64_B']);
    expect(full.attestationKeyIdentifiers).toEqual(['Key-A', 'KEY-B']);
    expect(full.dateUpdated).toMatch(/2025/);

    const lightweight = transformEntryLightweight(rawEntry, 8);
    expect(lightweight.isLightweightEntry).toBe(true);
    expect(lightweight.metadataStatement).toBeNull();
    expect(lightweight.deferredRawEntry).toBe(rawEntry);

    const upgraded = upgradeEntryToFull(lightweight);
    expect(upgraded.isLightweightEntry).toBe(false);
    expect(upgraded.metadataStatement).toEqual(rawEntry.metadataStatement);
    expect(upgraded.attestationCertificates).toEqual(['CERT_BASE64_A', 'CERT_BASE64_B']);
    expect(upgraded.attestationKeyIdentifiers).toEqual(['Key-A', 'KEY-B']);

    expect(upgradeEntryToFull(full)).toBe(full);

    const sets = collectOptionSets([full]);
    expect(sets.protocol.has('FIDO2')).toBe(true);
    expect(sets.certification.has('FIDO Certified L1')).toBe(true);
    expect(sets.userVerification.has('Presence Internal')).toBe(true);
    expect(sets.attachment.has('Internal')).toBe(true);
    expect(sets.transports.has('Ble')).toBe(true);
    expect(sets.keyProtection.has('Hardware')).toBe(true);
    expect(sets.algorithms.has('SECP256R1 Ecdsa SHA256 Raw')).toBe(true);
  });

  it('renders certificate summary item and certificate sections for modal views', () => {
    const item = createSummaryItem('Serial', '123', { variant: 'primary' });
    expect(item).not.toBeNull();
    expect(item.querySelector('.mds-certificate-summary__label')?.textContent).toBe('Serial');
    expect(item.querySelector('.mds-certificate-summary__label')?.classList.contains('mds-certificate-summary__label--primary')).toBe(true);

    const codeItem = createSummaryItem('Value', 'ABCD', { code: true });
    expect(codeItem?.querySelector('code')?.textContent).toBe('ABCD');

    const arrayItem = createSummaryItem('Policies', ['a', 'b']);
    expect(arrayItem?.querySelectorAll('.mds-certificate-summary__value > div')).toHaveLength(2);

    expect(createSummaryItem('', 'x')).toBeNull();
    expect(createSummaryItem('Empty', '')).toBeNull();

    const publicKeySection = renderCertificatePublicKey({
      algorithm: { name: 'RSA', modulusLength: 2048 },
      publicExponent: 65537,
      modulusHex: 'ABCD',
      uncompressedPoint: 'POINT',
      subjectPublicKeyInfoBase64: 'BASE64SPKI',
    });
    expect(publicKeySection).not.toBeNull();
    expect(publicKeySection?.textContent).toContain('Public Key');
    expect(publicKeySection?.textContent).toContain('RSA');

    const emptyPublicKey = renderCertificatePublicKey({ algorithm: '' });
    expect(emptyPublicKey).toBeNull();

    const signatureSection = renderCertificateSignature({
      algorithm: 'rsassa-pkcs1-v1_5',
      hash: { name: 'sha256' },
      hex: 'DEADBEEF',
    });
    expect(signatureSection).not.toBeNull();
    expect(signatureSection?.textContent).toContain('SHA-256');

    expect(formatSignatureHashName('sha384')).toBe('SHA-384');
    expect(formatSignatureHashName('sha3-256')).toBe('SHA3-256');
    expect(formatSignatureHashName(null)).toBe('');

    expect(determinePublicKeyAlgorithm({ algorithm: { name: 'EC' } })).toBe('EC');
    expect(determinePublicKeyAlgorithm({ type: 'RSA' })).toBe('RSA');
    expect(determinePublicKeyAlgorithm(null)).toBe('');

    const summary = renderCertificateSummary({
      subject: 'CN=Subject',
      issuer: 'CN=Issuer',
      validity: {
        notBefore: '2025-01-01T00:00:00Z',
        notAfter: '2026-01-01T00:00:00Z',
      },
      serialNumber: {
        decimal: '100',
        hex: '64',
      },
      publicKeyInfo: {
        algorithm: { name: 'RSA', modulusLength: 2048 },
      },
      signature: {
        algorithm: 'rsassa-pkcs1-v1_5',
        hash: 'sha256',
        hex: 'ABCD',
      },
    });
    expect(summary).not.toBeNull();

    const summaryContainer = document.createElement('div');
    summaryContainer.appendChild(summary);
    expect(summaryContainer.textContent).toContain('CN=Subject');
    expect(summaryContainer.textContent).toContain('Signature');
  });

  it('decodes base64url payloads to UTF-8 text', () => {
    expect(decodeBase64Url('aGVsbG8')).toBe('hello');
    expect(decodeBase64Url('8J-MjQ')).toBe('🌍');
  });
});
