import { describe, expect, it } from 'vitest';

import { formatCertificateDetails } from './text.js';
import { wholeCertificates } from '@/test/logic/credentials/certificates.js';

// A certificate as text (credentials/certificates/text.js), as the
// registration view's certificate shows it.

// Every certificate the server's characterization read (device captures and the ones
// its tests build), serialised whole, with the server's summary.
const CORPUS = Object.entries(wholeCertificates()).filter(([, details]) => details && !details.parseError);

/**
 * The certificate as a registration keeps it (webauthn/attestation/certificates.py):
 * no summary or PEM, the signature's hex alone, the public key's base64 without its hex.
 */
function registrationCopy(details) {
  const copy = structuredClone(details);
  delete copy.summary;
  delete copy.pem;
  delete copy.signature.colon;
  delete copy.signature.lines;
  if (copy.publicKeyInfo.publicKeyBase64) {
    delete copy.publicKeyInfo.publicKeyHex;
    delete copy.publicKeyInfo.publicKeyHexLines;
  }
  return copy;
}

/** The text for details holding only the given extension. */
const extensionText = (extension) => formatCertificateDetails({ extensions: [extension] });

/** The text for details holding only the given public key info. */
const publicKeyText = (info) => formatCertificateDetails({ publicKeyInfo: info });

describe('formatCertificateDetails', () => {
  it('has no text without details', () => {
    expect(formatCertificateDetails(null)).toBe('');
    expect(formatCertificateDetails('Version: 3')).toBe('');
  });

  it('gives the summary a record kept', () => {
    const [, details] = CORPUS[0];
    expect(formatCertificateDetails({ summary: `\n${details.summary}\n` })).toBe(details.summary);
  });

  it.each(CORPUS)("writes %s's text as the server's summary, from what a registration keeps", (name, details) => {
    expect(formatCertificateDetails(registrationCopy(details))).toBe(details.summary);
  });

  it('writes the same text from details that keep every form', () => {
    CORPUS.forEach(([, details]) => {
      expect(formatCertificateDetails({ ...details, summary: '  ' })).toBe(details.summary);
    });
  });

  it('has no text for a certificate the server could not read, only its error', () => {
    expect(formatCertificateDetails({ error: 'Unable to decode attestation certificate bytes.' })).toBe('');
  });
});

describe('the identity and the dates', () => {
  it('writes the serial number it has when the other spelling is missing', () => {
    expect(formatCertificateDetails({ serialNumber: { decimal: '7855', hex: 7855 } })).toBe('Certificate Serial Number: 7855');
    expect(formatCertificateDetails({ serialNumber: { hex: '0x1eaf' } })).toBe('Certificate Serial Number: 0x1eaf');
  });

  it('leaves out a version, serial number, algorithm or name that is not text', () => {
    expect(formatCertificateDetails({ version: 3, serialNumber: '7855', signatureAlgorithm: 5, issuer: null, subject: {} })).toBe('');
  });

  it('writes the names as they are, an empty one too', () => {
    expect(formatCertificateDetails({ issuer: 'CN=CA ', subject: '' })).toBe('Issuer: CN=CA \n\nSubject:');
  });

  it('writes the validity dates it has', () => {
    expect(formatCertificateDetails({ validity: { notAfter: '2099-12-31' } })).toBe('Validity:\n    Not After: 2099-12-31');
    expect(formatCertificateDetails({ validity: { notBefore: '', notAfter: 5 } })).toBe('Validity:\n    Not Before:');
  });

  it('leaves out a validity without dates', () => {
    expect(formatCertificateDetails({ validity: { notBefore: null } })).toBe('');
    expect(formatCertificateDetails({ validity: '2020' })).toBe('');
  });
});

describe('the public key', () => {
  it('leaves out a public key info that is not a map, or holds nothing to write', () => {
    expect(publicKeyText('ECC')).toBe('');
    expect(publicKeyText({ type: '' })).toBe('');
  });

  it('writes what the server read of a key it could not load', () => {
    expect(publicKeyText({ type: 'Unknown', algorithm: { name: 'Unknown', oid: '1.2.840.10045.2.9' } })).toBe(
      'Subject Public Key Info:\n    Type: Unknown\n    Algorithm OID: 1.2.840.10045.2.9',
    );
  });

  it("writes a key's wrapped form in lines", () => {
    expect(publicKeyText({ type: 'X', algorithm: { oid: '1.2' }, keySize: 0, wrappedPublicKeyBase64: 'AQI=' })).toBe(
      'Subject Public Key Info:\n    Type: X\n    Algorithm OID: 1.2\n    Wrapped Public Key (hex):\n        01:02',
    );
  });

  it('writes no lines for a key whose base64 does not decode', () => {
    expect(publicKeyText({ type: 'ML-DSA', mechanismFamily: 'ML-DSA', algorithm: 'ML-DSA', publicKeyBase64: 'AQI' })).toBe(
      'Subject Public Key Info:\n    Type: ML-DSA\n    Public Key (base64): AQI',
    );
  });

  it('names a key of another type by its type alone', () => {
    expect(publicKeyText({ type: 'DSAPublicKey', keySize: 2048, algorithm: { name: 'DSAPublicKey' } })).toBe(
      'Subject Public Key Info:\n    Type: DSAPublicKey',
    );
  });

  it('leaves out what an EC key does not say', () => {
    expect(publicKeyText({ type: 'ECC', uncompressedPoint: 'not hex' })).toBe('Subject Public Key Info:\n    Type: ECC');
  });
});

describe('the extensions', () => {
  it('skips entries that are not extensions', () => {
    expect(formatCertificateDetails({ extensions: [null, 'keyUsage', { name: 'Key Usage' }] })).toBe(
      'X509v3 extensions:\n    Key Usage:',
    );
  });

  it('leaves out an empty list of extensions', () => {
    expect(formatCertificateDetails({ extensions: [] })).toBe('');
  });

  it('names an extension by its OID and its name when it has no friendly name', () => {
    expect(extensionText({ oid: '2.5.29.15', name: 'keyUsage' })).toBe('X509v3 extensions:\n    2.5.29.15 (keyUsage):');
  });

  it('does not repeat a name that is the OID', () => {
    expect(extensionText({ oid: '2.5.29.15', name: '2.5.29.15' })).toBe('X509v3 extensions:\n    2.5.29.15:');
  });

  it('leaves the OID out of the header when the extension asks', () => {
    expect(extensionText({ oid: '2.5.29.15', friendlyName: 'Key Usage', includeOidInHeader: false })).toBe(
      'X509v3 extensions:\n    Key Usage:',
    );
  });

  it('falls back to the OID when the extension has no other name and asks to leave it out', () => {
    expect(extensionText({ oid: '2.5.29.15', name: '2.5.29.15', includeOidInHeader: false })).toBe(
      'X509v3 extensions:\n    2.5.29.15:',
    );
    expect(extensionText({ oid: '2.5.29.15', includeOidInHeader: false })).toBe('X509v3 extensions:\n    2.5.29.15:');
  });

  it('calls an extension with nothing to name it Extension', () => {
    expect(extensionText({ critical: true })).toBe('X509v3 extensions:\n    Extension [critical]:');
  });

  it('ignores an OID and names that are not text', () => {
    expect(extensionText({ oid: 5, friendlyName: 7, displayHeader: 9, name: 'Key Usage' })).toBe(
      'X509v3 extensions:\n    Key Usage:',
    );
  });

  it('writes a value that is text, a number or a boolean on its own line, as Python writes it', () => {
    expect(formatCertificateDetails({
      extensions: [{ name: 'A', value: 'Digital Signature' }, { name: 'B', value: 5 }, { name: 'C', value: true }],
    })).toBe('X509v3 extensions:\n    A:\n        Digital Signature\n    B:\n        5\n    C:\n        True');
  });

  it('writes an empty text value as an indented blank line', () => {
    expect(formatCertificateDetails({ extensions: [{ name: 'Key Usage', value: '' }, { name: 'B', value: 'x' }] })).toBe(
      'X509v3 extensions:\n    Key Usage:\n        \n    B:\n        x',
    );
  });

  it('lists the non-empty items of a list of text', () => {
    expect(extensionText({ name: 'A', value: ['sign', '', 'verify'] })).toBe('X509v3 extensions:\n    A:\n        sign\n        verify');
  });

  it('writes each item of another list as a value of its own', () => {
    expect(extensionText({ name: 'SCTs', value: [{ Version: 'v1', Empty: '' }, null, '', false] })).toBe(
      'X509v3 extensions:\n    SCTs:\n        Version: v1\n        \n        False',
    );
  });

  it('writes a map under its key, its empty values left out and an empty map or list as its key alone', () => {
    expect(extensionText({
      name: 'A',
      value: { 'Hex value': ['01:02'], blank: '', none: null, lists: [], maps: {}, 'Path Length': 0 },
    })).toBe([
      'X509v3 extensions:',
      '    A:',
      '        Hex value:',
      '            01:02',
      '        lists:',
      '        maps:',
      '        Path Length: 0',
    ].join('\n'));
  });
});

describe('the signature', () => {
  it("writes the signature's hex in lines under the certificate's signature algorithm", () => {
    expect(formatCertificateDetails({ signatureAlgorithm: 'ed25519', signature: { hex: '97ef' } })).toBe(
      'Signature Algorithm: ed25519\n\nSignature Algorithm: ed25519\n    97:ef',
    );
  });

  it('writes the lines under an empty name when the certificate names no algorithm', () => {
    expect(formatCertificateDetails({ signature: { algorithm: 'ed25519', hex: '0102' } })).toBe('Signature Algorithm: \n    01:02');
  });

  it('leaves out a signature without bytes', () => {
    expect(formatCertificateDetails({ signature: { algorithm: 'ed25519', hex: '' } })).toBe('');
    expect(formatCertificateDetails({ signature: null })).toBe('');
  });
});

describe('the fingerprints', () => {
  it('writes MD5, SHA1 and SHA256 in that order, whatever order they come in', () => {
    expect(formatCertificateDetails({ fingerprints: { sha256: '03', sha1: '02', md5: '01', sha512: '04' } })).toBe(
      'Fingerprint:\n    MD5:\n        01\n    SHA1:\n        02\n    SHA256:\n        03',
    );
  });

  it('writes an odd-length fingerprint with a leading zero, and one that is no hex as it is', () => {
    expect(formatCertificateDetails({ fingerprints: { sha1: 'abc', md5: 'unknown' } })).toBe(
      'Fingerprint:\n    MD5:\n        unknown\n    SHA1:\n        0a:bc',
    );
  });

  it('leaves out the fingerprints that are empty or not text', () => {
    expect(formatCertificateDetails({ fingerprints: { sha1: 5, md5: '' } })).toBe('');
    expect(formatCertificateDetails({ fingerprints: 'abc' })).toBe('');
  });
});

describe('the subject key identifier', () => {
  it("writes the identifier's lines from its extension", () => {
    expect(formatCertificateDetails({ extensions: [{ oid: '2.5.29.14', name: 'SKI', value: { 'Hex value': ['01:02'] } }] })).toBe(
      'X509v3 extensions:\n    2.5.29.14 (SKI):\n        Hex value:\n            01:02\n\nSubject Key Identifier:\n    01:02',
    );
  });

  it('leaves it out when the extension holds no lines', () => {
    expect(formatCertificateDetails({ extensions: [{ oid: '2.5.29.14', name: 'SKI', value: { 'Hex value': '' } }] })).toBe(
      'X509v3 extensions:\n    2.5.29.14 (SKI):',
    );
    expect(formatCertificateDetails({ extensions: [{ oid: '2.5.29.14', name: 'SKI' }] })).toBe('X509v3 extensions:\n    2.5.29.14 (SKI):');
  });
});
