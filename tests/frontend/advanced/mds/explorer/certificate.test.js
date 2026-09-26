import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  CERTIFICATE_DECODE_FAILED,
  CERTIFICATE_DECODE_PATH,
  DEFAULT_CERTIFICATE_TITLE,
  NO_CERTIFICATE_DETAILS,
  certificateDecodeFailure,
  certificatePublicKeySection,
  certificateSignatureSection,
  certificateSummary,
  certificateSummaryItem,
  describeCertificate,
  determinePublicKeyAlgorithm,
  formatCertificateOutput,
  normaliseCertificateBase64,
  requestCertificateDecode,
} from '../../../../../frontend/static/scripts/advanced/mds/explorer/certificate.js';

// What POST /api/mds/decode-certificate answers for an EC root (its shape).
const EC_DETAILS = {
  subject: 'C=SE, O=Characterization Test, CN=Fixture FIDO2 Attestation Root',
  issuer: 'C=SE, O=Characterization Test, CN=Fixture FIDO2 Attestation Root',
  validity: { notBefore: '2024-01-01T00:00:00+00:00', notAfter: '2044-01-01T00:00:00+00:00' },
  serialNumber: { decimal: '1001', hex: '03E9' },
  publicKeyInfo: {
    type: 'EC',
    algorithm: { name: 'ECDSA', namedCurve: 'secp256r1' },
    keySize: 256,
    uncompressedPoint: '04ABCD',
    subjectPublicKeyInfoBase64: 'MFkwEwYHKoZIzj0CAQ',
  },
  signature: { algorithm: 'ECDSA_SHA256', hash: 'sha256', hex: '3045022100' },
  summary: 'Version: 3 (0x2)\nSerial Number: 1001',
};

function answer(body, { ok = true, status = 200 } = {}) {
  return { ok, status, json: async () => body, text: async () => JSON.stringify(body) };
}

afterEach(() => {
  vi.restoreAllMocks();
  delete globalThis.fetch;
});

describe('the certificate page: its input and output (MDS-X1)', () => {
  it('sends the base64 without its whitespace', () => {
    expect(normaliseCertificateBase64(' MIIB\n  CAFE= ')).toBe('MIIBCAFE=');
    expect(normaliseCertificateBase64(null)).toBe('');
  });

  it('shows the server summary as Decoded Output, else the details as JSON', () => {
    expect(formatCertificateOutput(EC_DETAILS)).toBe('Version: 3 (0x2)\nSerial Number: 1001');
    expect(formatCertificateOutput({ summary: '  ', subject: 'x' })).toBe('{\n  "summary": "  ",\n  "subject": "x"\n}');
    expect(formatCertificateOutput(null)).toBe(NO_CERTIFICATE_DETAILS);
    expect(NO_CERTIFICATE_DETAILS).toBe('No decoded certificate details available.');
  });
});

describe('the certificate page: the decode (MDS-X2)', () => {
  it('posts the certificate and gives the details', async () => {
    globalThis.fetch = vi.fn(async () => answer({ details: EC_DETAILS }));
    await expect(requestCertificateDecode('MIIB')).resolves.toBe(EC_DETAILS);
    expect(CERTIFICATE_DECODE_PATH).toBe('/api/mds/decode-certificate');
    expect(globalThis.fetch).toHaveBeenCalledWith('/api/mds/decode-certificate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: '{"certificate":"MIIB"}',
      cache: 'no-store',
    });
    globalThis.fetch = vi.fn(async () => answer(null));
    await expect(requestCertificateDecode('MIIB')).resolves.toBeNull();
  });

  it('says a refusal by its status, with the server reason beside it', async () => {
    globalThis.fetch = vi.fn(async () => answer({ error: 'Invalid certificate encoding.' }, { ok: false, status: 400 }));
    const refused = await requestCertificateDecode('!!').catch(error => error);
    expect(refused.message).toBe('Certificate decode failed with status 400');
    expect(refused.reason).toBe('Invalid certificate encoding.');

    globalThis.fetch = vi.fn(async () => answer(null, { ok: false, status: 500 }));
    const failed = await requestCertificateDecode('MIIB').catch(error => error);
    expect(failed.message).toBe('Certificate decode failed with status 500');
    expect(failed.reason).toBe('');
  });

  it('words a failure by its message, else the page sentence', () => {
    expect(certificateDecodeFailure(new TypeError('Failed to fetch'))).toBe('Failed to fetch');
    expect(certificateDecodeFailure('not an error')).toBe(CERTIFICATE_DECODE_FAILED);
    expect(CERTIFICATE_DECODE_FAILED).toBe('Unable to decode certificate.');
  });
});

describe('the certificate page: the summary (MDS-X3)', () => {
  it('names the public key algorithm, else the key type', () => {
    expect(determinePublicKeyAlgorithm({ algorithm: ' RSA ' })).toBe('RSA');
    expect(determinePublicKeyAlgorithm({ algorithm: { name: ' ECDSA ' } })).toBe('ECDSA');
    expect(determinePublicKeyAlgorithm({ algorithm: '  ', type: ' Ed25519 ' })).toBe('Ed25519');
    expect(determinePublicKeyAlgorithm({ algorithm: { name: 5 }, type: 'EC' })).toBe('EC');
    expect(determinePublicKeyAlgorithm({ algorithm: 7, type: null })).toBe('');
    expect(determinePublicKeyAlgorithm({})).toBe('');
    expect(determinePublicKeyAlgorithm('RSA')).toBe('');
    expect(determinePublicKeyAlgorithm(null)).toBe('');
  });

  it('gives a line only when it has something to show', () => {
    expect(certificateSummaryItem('Subject', ' CN=x ', { primary: true })).toEqual({
      label: 'Subject',
      value: 'CN=x',
      primary: true,
      code: false,
    });
    expect(certificateSummaryItem('Value', ' AB ', { code: true })).toEqual({ label: 'Value', value: ' AB ', primary: false, code: true });
    expect(certificateSummaryItem('Names', ['a', '', 'b'])).toEqual({ label: 'Names', lines: ['a', 'b'], primary: false, code: false });
    expect(certificateSummaryItem('Zero', 0)).toEqual({ label: 'Zero', value: '0', primary: false, code: false });
    expect(certificateSummaryItem('', 'x')).toBeNull();
    expect(certificateSummaryItem('Blank', '  ')).toBeNull();
    expect(certificateSummaryItem('None', null)).toBeNull();
    expect(certificateSummaryItem('Missing')).toBeNull();
    expect(certificateSummaryItem('Empty', ['', null])).toBeNull();
  });

  it('lists the public key: algorithm, curve, size, exponent, modulus, point, value', () => {
    expect(certificatePublicKeySection(EC_DETAILS.publicKeyInfo)).toEqual({
      title: 'Public Key',
      items: [
        { label: 'Algorithm', value: 'ECDSA', primary: false, code: false },
        { label: 'Named Curve', value: 'secp256r1', primary: false, code: false },
        { label: 'Key Size', value: '256 bit', primary: false, code: false },
        { label: 'Uncompressed Point', value: '04ABCD', primary: false, code: true },
        { label: 'Value', value: 'MFkwEwYHKoZIzj0CAQ', primary: false, code: true },
      ],
    });
    expect(
      certificatePublicKeySection({ type: 'RSA', curve: 'none', algorithm: { modulusLength: 2048 }, keySize: 1024, publicExponent: 65537, modulusHex: 'C0FFEE' })
        .items.map(item => [item.label, item.value]),
    ).toEqual([
      ['Algorithm', 'RSA'],
      ['Named Curve', 'none'],
      ['Key Size', '2048 bit'],
      ['Public Exponent', '65537'],
      ['Modulus', 'C0FFEE'],
    ]);
    expect(certificatePublicKeySection({ publicExponent: 0 }).items).toEqual([
      { label: 'Public Exponent', value: '0', primary: false, code: false },
    ]);
    expect(certificatePublicKeySection({ algorithm: '' })).toBeNull();
    expect(certificatePublicKeySection('RSA')).toBeNull();
  });

  it('lists the signature: algorithm, hash, value', () => {
    expect(certificateSignatureSection(EC_DETAILS.signature).items.map(item => [item.label, item.value])).toEqual([
      ['Algorithm', 'ECDSA_SHA256'],
      ['Hash', 'SHA-256'],
      ['Value', '3045022100'],
    ]);
    expect(certificateSignatureSection({ hash: { name: 'sha3-256' } }).items[0].value).toBe('SHA3-256');
    expect(certificateSignatureSection({ hash: { name: 5 } }).items[0].value).toBe('5');
    expect(certificateSignatureSection({ hash: { name: '' } })).toBeNull();
    expect(certificateSignatureSection({})).toBeNull();
    expect(certificateSignatureSection(null)).toBeNull();
  });

  it('puts the subject, issuer, validity and serial numbers first, then the sections', () => {
    const summary = certificateSummary(EC_DETAILS);
    expect(summary.items.map(item => [item.label, item.primary])).toEqual([
      ['Subject', true],
      ['Issuer', true],
      ['Not Before', true],
      ['Not After', true],
      ['Serial Number', true],
      ['Serial Number (Hex)', false],
    ]);
    expect(summary.items[2].value).toBe(new Date('2024-01-01T00:00:00+00:00').toUTCString());
    expect(summary.items[4].value).toBe('1001');
    expect(summary.sections.map(section => section.title)).toEqual(['Public Key', 'Signature']);

    expect(certificateSummary({ serialNumber: { hex: '0A' } }).items.map(item => [item.label, item.value])).toEqual([
      ['Serial Number', '0A'],
      ['Serial Number (Hex)', '0A'],
    ]);
    expect(certificateSummary({ signature: { algorithm: 'x' } })).toEqual({
      items: [],
      sections: [{ title: 'Signature', items: [{ label: 'Algorithm', value: 'x', primary: false, code: false }] }],
    });
    expect(certificateSummary({ summary: 'only text' })).toBeNull();
    expect(certificateSummary('text')).toBeNull();
  });
});

describe('the certificate page: what it shows for a decode', () => {
  it('titles the page with the subject and the issuer', () => {
    expect(describeCertificate({ details: EC_DETAILS })).toEqual({
      title: EC_DETAILS.subject,
      subtitle: EC_DETAILS.issuer,
      summary: certificateSummary(EC_DETAILS),
      message: '',
      output: EC_DETAILS.summary,
      failed: false,
      reason: '',
    });
  });

  it('keeps the default title and says so when there is nothing to summarise', () => {
    expect(DEFAULT_CERTIFICATE_TITLE).toBe('Attestation Certificate');
    expect(describeCertificate({ details: { subject: ' ', issuer: 5 } })).toMatchObject({ title: 'Attestation Certificate', subtitle: '' });
    expect(describeCertificate({ details: { summary: 'Unable to parse attestation certificate' } })).toMatchObject({
      title: 'Attestation Certificate',
      subtitle: '',
      summary: null,
      message: NO_CERTIFICATE_DETAILS,
      output: 'Unable to parse attestation certificate',
    });
    expect(describeCertificate()).toMatchObject({ title: 'Attestation Certificate', message: NO_CERTIFICATE_DETAILS, output: NO_CERTIFICATE_DETAILS });
  });

  it('says a failure in the summary and in Decoded Output, with the server reason', () => {
    const refused = Object.assign(new Error('Certificate decode failed with status 400'), { reason: 'Invalid certificate encoding.' });
    expect(describeCertificate({ error: refused })).toEqual({
      title: 'Attestation Certificate',
      subtitle: '',
      summary: null,
      message: 'Certificate decode failed with status 400',
      output: 'Certificate decode failed with status 400',
      failed: true,
      reason: 'Invalid certificate encoding.',
    });
    expect(describeCertificate({ error: 'thrown' })).toMatchObject({ message: 'Unable to decode certificate.', reason: '' });
  });
});
