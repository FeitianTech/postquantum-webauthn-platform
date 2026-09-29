import { describe, expect, it } from 'vitest';

import { formatCertificateDetails } from './certificate-text.js';
import { advancedComplete, registration } from '@/test/logic/advanced/credentials/registration-detail-answers.js';

// A certificate as text (advanced/credential-display/certificate-text.js), as the
// registration view's certificate shows it.

/** The attestation certificate as the decoder parsed it (POST /api/decode): no summary. */
const decodedCertificate = () => registration('packedX5c').attestationDecode.data.attestationObject.attStmt.x5c[0].parsedX5c;

/** The same certificate as register-complete describes it, with the server's summary. */
const describedCertificate = () => advancedComplete().relyingParty.attestationCertificate;

/** The text for details holding only the given extension. */
const extensionText = (extension) => formatCertificateDetails({ extensions: [extension] });

describe('formatCertificateDetails', () => {
  it('has no text without details', () => {
    expect(formatCertificateDetails(null)).toBe('');
    expect(formatCertificateDetails('Version: 3')).toBe('');
  });

  it("gives the decoder's summary when it has one", () => {
    const certificate = describedCertificate();
    expect(formatCertificateDetails({ ...certificate, summary: `\n${certificate.summary}\n` })).toBe(certificate.summary);
  });

  it('builds an OpenSSL-like text from the fields when there is no summary', () => {
    expect(formatCertificateDetails(decodedCertificate())).toBe([
      'Version: 3 (0x2)',
      'Certificate Serial Number: 7855 / 0x1eaf',
      'Signature Algorithm: ed25519',
      'Issuer: CN=Characterization Test CA',
      '',
      'Validity:',
      '    Not Before: 2020-01-01T00:00:00+00:00',
      '    Not After: 2099-12-31T00:00:00+00:00',
      '',
      'Subject: CN=Characterization Attestation Leaf,OU=Authenticator Attestation,O=Characterization Test,C=SE',
      '',
      'Subject Public Key Info:',
      '    algorithm:',
      '        name: ECDSA',
      '        namedCurve: secp256r1',
      '    curve: secp256r1',
      '    keySize: 256',
      '    type: ECC',
      '    uncompressedPoint: 04:64:1a:28:f0:44:a1:9d:8b:40:83:b1:dc:9c:d0:2b:b0:a9:af:ba:77:45:e6:77:53:25:ed:3a:39:7d:b1:88:2f:33:4f:50:76:15:07:0e:c7:29:31:15:70:cf:4b:32:9d:e4:44:7a:d0:b9:c2:48:bf:f7:06:b1:ae:5b:d7:21:c6',
      '',
      'X509v3 extensions:',
      '    X509v3 Basic Constraints [critical]:',
      '        CA: FALSE',
      '    1.3.6.1.4.1.45724.1.1.4 (FIDO: Device AAGUID):',
      '        AAGUID: 00112233445566778899aabbccddeeff',
      '',
      'Signature Algorithm: ed25519',
      '    97:ef:c8:b1:16:2d:d6:c6:27:ad:aa:5d:d4:d3:2d:98',
      '    33:d7:1a:74:2d:85:a9:9b:f8:fc:5b:9f:ee:dc:f0:52',
      '    97:59:d4:54:ba:10:3d:f6:52:fb:a0:7e:c4:44:ab:53',
      '    3c:16:03:69:ab:55:11:b2:d8:d8:bc:33:7f:73:9c:07',
      '',
      'Fingerprint:',
      '    MD5:',
      '        ed:83:57:b0:48:fe:55:52:67:1d:d9:40:36:1e:a1:ba',
      '    SHA1:',
      '        ee:e4:2e:39:bd:27:2a:7b:08:15:0a:28:73:ff:48:31',
      '        21:68:fe:ba',
      '    SHA256:',
      '        e5:d9:8c:65:07:23:83:3d:e4:89:25:5a:07:81:64:b1',
      '        e0:ab:91:fb:27:ae:62:01:1c:a6:a9:9b:8c:a6:c5:21',
    ].join('\n'));
  });

  it('builds the text when the summary is blank', () => {
    const certificate = decodedCertificate();
    expect(formatCertificateDetails({ ...certificate, summary: '  ' })).toBe(formatCertificateDetails(certificate));
  });

  it('has no text for details with no field it writes', () => {
    expect(formatCertificateDetails({ algorithmInfo: 'ED25519_SHA512' })).toBe('');
  });
});

describe('the version', () => {
  it('does not repeat a hex that is the display', () => {
    expect(formatCertificateDetails({ version: { display: '0x2', hex: '0x2' } })).toBe('Version: 0x2');
  });

  it('does not repeat a hex the display already gives in parentheses', () => {
    expect(formatCertificateDetails({ version: { display: '3 (0x2)', hex: '0x2' } })).toBe('Version: 3 (0x2)');
  });

  it('adds the hex after a display that does not give it', () => {
    expect(formatCertificateDetails({ version: { display: '3', hex: '0x2' } })).toBe('Version: 3 0x2');
  });

  it('writes the hex alone when there is no display', () => {
    expect(formatCertificateDetails({ version: { display: ' ', hex: '0x2' } })).toBe('Version: 0x2');
  });

  it('leaves out a version with neither a display nor a hex', () => {
    expect(formatCertificateDetails({ version: { numeric: 3, hex: 2 } })).toBe('');
  });

  it('writes a version given as a number or text', () => {
    expect(formatCertificateDetails({ version: 3 })).toBe('Version: 3');
  });

  it('leaves out a blank version', () => {
    expect(formatCertificateDetails({ version: '  ' })).toBe('');
  });
});

describe('the serial number', () => {
  it('writes the decimal alone when there is no hex', () => {
    expect(formatCertificateDetails({ serialNumber: { decimal: '7855', hex: ' ' } })).toBe('Certificate Serial Number: 7855');
  });

  it('writes the hex alone when there is no decimal', () => {
    expect(formatCertificateDetails({ serialNumber: { decimal: 7855, hex: '0x1eaf' } })).toBe('Certificate Serial Number: 0x1eaf');
  });

  it('leaves out a serial number with neither', () => {
    expect(formatCertificateDetails({ serialNumber: {} })).toBe('');
  });

  it('writes a serial number given as text', () => {
    expect(formatCertificateDetails({ serialNumber: '7855' })).toBe('Certificate Serial Number: 7855');
  });

  it('leaves out a blank serial number', () => {
    expect(formatCertificateDetails({ serialNumber: ' ' })).toBe('');
  });
});

describe('the names and dates', () => {
  it('leaves out an algorithm, issuer or subject that is blank or not text', () => {
    expect(formatCertificateDetails({ signatureAlgorithm: 5, issuer: ' ', subject: null })).toBe('');
  });

  it('writes the one validity date it has', () => {
    expect(formatCertificateDetails({ validity: { notAfter: '2099-12-31' } })).toBe('Validity:\n    Not After: 2099-12-31');
    expect(formatCertificateDetails({ validity: { notBefore: '2020-01-01' } })).toBe('Validity:\n    Not Before: 2020-01-01');
  });

  it('leaves out a validity without dates', () => {
    expect(formatCertificateDetails({ validity: { notBefore: '', notAfter: null } })).toBe('');
  });

  it('puts a blank line between the sections', () => {
    expect(formatCertificateDetails({ issuer: 'CN=CA', subject: 'CN=Leaf' })).toBe('Issuer: CN=CA\n\nSubject: CN=Leaf');
  });
});

describe('the public key info', () => {
  it('leaves out a public key info that is not a map', () => {
    expect(formatCertificateDetails({ publicKeyInfo: 'ECC' })).toBe('');
  });

  it('gives the heading alone for a public key info with nothing in it', () => {
    expect(formatCertificateDetails({ publicKeyInfo: { type: null, curve: '' } })).toBe('Subject Public Key Info:');
  });

  it('lists the items of a list under its key', () => {
    expect(formatCertificateDetails({ publicKeyInfo: { usages: ['sign', 'verify'] } })).toBe(
      'Subject Public Key Info:\n    usages:\n        sign\n        verify',
    );
  });

  it('leaves out an empty list and a map with nothing in it', () => {
    expect(formatCertificateDetails({ publicKeyInfo: { usages: [], algorithm: { name: '' }, type: 'ECC' } })).toBe(
      'Subject Public Key Info:\n    type: ECC',
    );
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

  it('writes a value that is text, a number or a boolean on its own line', () => {
    expect(formatCertificateDetails({
      extensions: [{ name: 'A', value: 'Digital Signature' }, { name: 'B', value: 5 }, { name: 'C', value: true }],
    })).toBe('X509v3 extensions:\n    A:\n        Digital Signature\n    B:\n        5\n    C:\n        true');
  });

  it('writes the header alone for an empty value', () => {
    expect(formatCertificateDetails({
      extensions: [{ name: 'A', value: ' ' }, { name: 'B', value: [] }, { name: 'C', value: null }, { name: 'D', value: {} }],
    })).toBe('X509v3 extensions:\n    A:\n    B:\n    C:\n    D:');
  });

  it('lists the plain items of a list, leaving out the empty places', () => {
    expect(extensionText({ name: 'A', value: ['sign', null, 2, false] })).toBe(
      'X509v3 extensions:\n    A:\n        sign\n        2\n        false',
    );
    expect(extensionText({ name: 'A', value: [null, undefined] })).toBe('X509v3 extensions:\n    A:');
  });

  it('marks each map of a mixed list with a dash, and each plain item after one', () => {
    expect(extensionText({ name: 'Policies', value: [{ policy: '1.2.3' }, 'any', {}] })).toBe([
      'X509v3 extensions:',
      '    Policies:',
      '        -',
      '            policy: 1.2.3',
      '        - any',
      '        -',
    ].join('\n'));
  });

  it('writes a nested map under its key, leaving out empty lists and maps', () => {
    expect(extensionText({
      name: 'A',
      value: { policy: { id: '1.2' }, empty: {}, blank: { id: '' }, none: [], items: ['x'] },
    })).toBe([
      'X509v3 extensions:',
      '    A:',
      '        policy:',
      '            id: 1.2',
      '        items:',
      '            x',
    ].join('\n'));
  });

  it('writes a value of another kind as its text', () => {
    expect(extensionText({ name: 'A', value: 10n })).toBe('X509v3 extensions:\n    A:\n        10');
  });
});

describe('the signature', () => {
  it('writes the signature as one line when it has no lines', () => {
    expect(formatCertificateDetails({ signature: { algorithm: 'ed25519', colon: '97:ef' } })).toBe(
      'Signature Algorithm: ed25519\n    97:ef',
    );
  });

  it("names the certificate's signature algorithm when the signature does not", () => {
    expect(formatCertificateDetails({ signatureAlgorithm: 'ed25519', signature: { colon: '97:ef' } })).toBe(
      'Signature Algorithm: ed25519\n\nSignature Algorithm: ed25519\n    97:ef',
    );
  });

  it('calls the algorithm Signature when nothing names it, and skips blank lines', () => {
    expect(formatCertificateDetails({ signature: { lines: ['97:ef', ' ', 5] } })).toBe(
      'Signature Algorithm: Signature\n    97:ef',
    );
  });

  it('writes the algorithm alone when the signature has no bytes', () => {
    expect(formatCertificateDetails({ signature: { algorithm: 'ed25519' } })).toBe('Signature Algorithm: ed25519');
  });

  it('leaves out a signature with nothing to write', () => {
    expect(formatCertificateDetails({ signature: { algorithm: 5, lines: '97:ef', colon: 7 } })).toBe('');
  });
});

describe('the fingerprints', () => {
  it('writes an odd-length fingerprint with a leading zero', () => {
    expect(formatCertificateDetails({ fingerprints: { sha1: 'abc' } })).toBe('Fingerprint:\n    SHA1:\n        0a:bc');
  });

  it('writes a fingerprint that holds no hex as it is', () => {
    expect(formatCertificateDetails({ fingerprints: { sha1: 'unknown' } })).toBe('Fingerprint:\n    SHA1:\n        unknown');
  });

  it('calls a fingerprint with a blank name VALUE', () => {
    expect(formatCertificateDetails({ fingerprints: { ' ': 'ab' } })).toBe('Fingerprint:\n    VALUE:\n        ab');
  });

  it('leaves out the fingerprints that are blank or not text', () => {
    expect(formatCertificateDetails({ fingerprints: { sha1: 5, md5: ' ' } })).toBe('');
  });
});
