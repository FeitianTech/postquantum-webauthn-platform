import { describe, expect, it } from 'vitest';

import {
  collectCredentialCertificates,
  deriveCertificateIdentity,
  extractAaguidFromCertificateEntries,
  extractAaguidFromCertificateEntry,
  extractAaguidFromExtensionValue,
  normaliseCertificateEntryForModal,
  normaliseHexFingerprint,
  normalisePemString,
  partitionCertificateEntries,
} from './core.js';
import { goldenAnswers } from '@/test/logic/simple/ceremony-answers.js';

const AAGUID = '00112233445566778899aabbccddeeff';
const AAGUID_OID = '1.3.6.1.4.1.45724.1.1.4';

/** The record register-complete answers for a packed x5c attestation, a fresh copy each time. */
function savedRecord() {
  const answer = goldenAnswers('simple-register-packed-x5c-extensions').find(({ body }) => body && body.storedCredential);
  return structuredClone(answer.body.storedCredential);
}

/** Its attestation certificate as the server parsed it (derBase64, pem, fingerprints, extensions). */
const certificate = () => savedRecord().properties.attestationCertificates[0];

/** A certificate the server could not parse, as it describes one. */
const unparsed = (raw) => ({ parsedX5c: { parseError: 'error parsing asn1 value', raw } });

describe('collectCredentialCertificates', () => {
  it('gathers the certificates a saved record holds', () => {
    const record = savedRecord();
    expect(collectCredentialCertificates(record)).toEqual(record.properties.attestationCertificates);
  });

  it('has none without a record', () => {
    expect(collectCredentialCertificates(null)).toEqual([]);
  });

  it('takes a single certificate as well as a list', () => {
    const cert = certificate();
    expect(collectCredentialCertificates({ attestationCertificate: cert })).toEqual([cert]);
  });

  it('skips empty places in a list', () => {
    const cert = certificate();
    expect(collectCredentialCertificates({ relyingParty: { attestationCertificates: [null, cert] } })).toEqual([cert]);
  });
});

describe('normaliseHexFingerprint', () => {
  it('writes a fingerprint as lowercase hex without separators', () => {
    expect(normaliseHexFingerprint('ED:83:57:B0')).toBe('ed8357b0');
  });

  it('has no fingerprint for text without hex digits, or for anything else', () => {
    expect(normaliseHexFingerprint('--')).toBe('');
    expect(normaliseHexFingerprint(42)).toBe('');
  });
});

describe('normalisePemString', () => {
  it("strips a PEM's armour and line breaks down to its base64", () => {
    const cert = certificate();
    expect(normalisePemString(cert.pem)).toBe(cert.derBase64);
  });

  it('has no PEM for a value that is not text', () => {
    expect(normalisePemString(undefined)).toBe('');
  });
});

describe('deriveCertificateIdentity', () => {
  it('has no identity without an entry', () => {
    expect(deriveCertificateIdentity(null)).toBe('');
  });

  it('names an entry by its raw hex first', () => {
    expect(deriveCertificateIdentity({ raw: '30 82\n01 B4', pem: certificate().pem })).toBe('raw:308201b4');
  });

  it('names an entry by its PEM when its raw hex is blank', () => {
    const cert = certificate();
    expect(deriveCertificateIdentity({ raw: '  ', pem: cert.pem })).toBe(`pem:${cert.derBase64}`);
  });

  it("names a parsed certificate by the server's raw hex", () => {
    expect(deriveCertificateIdentity(unparsed('3082ABCD'))).toBe('raw:3082abcd');
  });

  it('reads the details under parsedX5c only', () => {
    expect(deriveCertificateIdentity({ parsedX5c: { raw: '3082abcd' } })).toBe('raw:3082abcd');
    expect(deriveCertificateIdentity({ parsed: { raw: '3082abcd' } })).not.toBe('raw:3082abcd');
  });

  it('names a parsed certificate by its DER', () => {
    const cert = certificate();
    expect(deriveCertificateIdentity({ parsedX5c: cert })).toBe(`der:${cert.derBase64}`);
  });

  it('names a parsed certificate by its PEM when it has no DER', () => {
    const cert = certificate();
    expect(deriveCertificateIdentity({ parsedX5c: { pem: cert.pem } })).toBe(`pem:${cert.derBase64}`);
  });

  it('names a parsed certificate by the first fingerprint it has', () => {
    const { fingerprints } = certificate();
    const entry = { parsedX5c: { fingerprints: { sha256: '', sha1: fingerprints.sha1, md5: fingerprints.md5 } } };
    expect(deriveCertificateIdentity(entry)).toBe(`sha1:${fingerprints.sha1}`);
  });

  it('has no identity for details with nothing to name them by', () => {
    expect(deriveCertificateIdentity({ parsedX5c: { fingerprints: {} } })).toBe('');
  });

  it('has no identity for an entry without details', () => {
    expect(deriveCertificateIdentity({ summary: 'Version: 3 (0x2)' })).toBe('');
  });
});

describe('normaliseCertificateEntryForModal', () => {
  it('has nothing for a missing entry', () => {
    expect(normaliseCertificateEntryForModal(null)).toBeNull();
  });

  it('keeps parsed details with their PEM and the raw bytes of their DER', () => {
    const cert = certificate();
    const normalised = normaliseCertificateEntryForModal({ parsedX5c: cert });
    expect(normalised.parsedX5c).toBe(cert);
    expect(normalised.pem).toBe(cert.pem);
    expect(normalised.raw).toMatch(/^308201b4/);
    expect(normalised.raw.endsWith(cert.signature.hex)).toBe(true);
  });

  it('reads the details under parsedX5c', () => {
    const details = { parseError: 'error parsing asn1 value' };
    expect(normaliseCertificateEntryForModal({ parsedX5c: details }).parsedX5c).toBe(details);
  });

  it("takes a bare certificate as its own details", () => {
    const cert = certificate();
    const normalised = normaliseCertificateEntryForModal(cert);
    expect(normalised.parsedX5c).toBe(cert);
    expect(normalised.raw).toHaveLength(880);
  });

  it('keeps the raw hex it is given over the DER', () => {
    expect(normaliseCertificateEntryForModal({ raw: ' 308201b4 ', parsedX5c: certificate() }).raw).toBe('308201b4');
  });

  it('has no raw bytes for a DER that is not standard base64', () => {
    const normalised = normaliseCertificateEntryForModal({ derBase64: 'MIIB-tDC' });
    expect(normalised).not.toHaveProperty('raw');
  });

  it('has no PEM for a blank one', () => {
    expect(normaliseCertificateEntryForModal({ pem: '   ' })).not.toHaveProperty('pem');
  });
});

describe('extractAaguidFromExtensionValue', () => {
  it('has no AAGUID in an empty value', () => {
    expect(extractAaguidFromExtensionValue(null)).toBe('');
  });

  it('reads an AAGUID written as text', () => {
    expect(extractAaguidFromExtensionValue(AAGUID.toUpperCase())).toBe(AAGUID);
  });

  it('reads the first AAGUID in a list', () => {
    expect(extractAaguidFromExtensionValue(['', AAGUID])).toBe(AAGUID);
  });

  it('has no AAGUID in a list without one', () => {
    expect(extractAaguidFromExtensionValue([''])).toBe('');
  });

  it("reads the value under a key naming the AAGUID, as the server writes the extension", () => {
    const extension = certificate().extensions.find((ext) => ext.oid === AAGUID_OID);
    expect(extractAaguidFromExtensionValue(extension.value)).toBe(AAGUID);
  });

  it('looks past an empty AAGUID key to the plain value', () => {
    expect(extractAaguidFromExtensionValue({ aaguid: '', value: AAGUID })).toBe(AAGUID);
  });

  it('has no AAGUID when the plain value holds none', () => {
    expect(extractAaguidFromExtensionValue({ hex: '' })).toBe('');
  });

  it('has no AAGUID in a number', () => {
    expect(extractAaguidFromExtensionValue(42)).toBe('');
  });
});

describe('extractAaguidFromCertificateEntry', () => {
  it('has no AAGUID without an entry', () => {
    expect(extractAaguidFromCertificateEntry(null)).toBe('');
  });

  it("reads the AAGUID from a certificate's FIDO extension", () => {
    expect(extractAaguidFromCertificateEntry(certificate())).toBe(AAGUID);
  });

  it('reads an AAGUID given beside the certificate', () => {
    expect(extractAaguidFromCertificateEntry({ aaguidHex: AAGUID, parsedX5c: { extensions: [] } })).toBe(AAGUID);
  });

  it('reads the certificate inside a partitioned entry', () => {
    expect(extractAaguidFromCertificateEntry({ entry: { parsedX5c: certificate() }, index: 0 })).toBe(AAGUID);
  });

  it('looks past an inner entry without an AAGUID', () => {
    expect(extractAaguidFromCertificateEntry({ entry: { summary: '' }, aaguidHex: AAGUID })).toBe(AAGUID);
  });

  it('finds the AAGUID extension by its friendly name when it has no OID', () => {
    const extensions = [null, { friendlyName: 'FIDO: Device AAGUID', value: { AAGUID } }];
    expect(extractAaguidFromCertificateEntry({ parsedX5c: { extensions } })).toBe(AAGUID);
  });

  it('finds the AAGUID extension by its name alone', () => {
    const extensions = [{ name: 'id-fido-gen-ce-aaguid', value: AAGUID }];
    expect(extractAaguidFromCertificateEntry({ parsedX5c: { extensions } })).toBe(AAGUID);
  });

  it('has no AAGUID when the extension holds none', () => {
    expect(extractAaguidFromCertificateEntry({ parsedX5c: { extensions: [{ oid: AAGUID_OID, value: {} }] } })).toBe('');
  });
});

describe('extractAaguidFromCertificateEntries', () => {
  it('has no AAGUID without entries', () => {
    expect(extractAaguidFromCertificateEntries(null)).toBe('');
  });

  it('reads a single entry given alone', () => {
    expect(extractAaguidFromCertificateEntries(certificate())).toBe(AAGUID);
  });

  it('reads the first entry that has an AAGUID', () => {
    expect(extractAaguidFromCertificateEntries([{ summary: '' }, certificate()])).toBe(AAGUID);
  });

  it('has no AAGUID when no entry has one', () => {
    expect(extractAaguidFromCertificateEntries([{ summary: '' }])).toBe('');
  });
});

describe('partitionCertificateEntries', () => {
  const parsedEntry = () => normaliseCertificateEntryForModal({ parsedX5c: certificate() });

  it('has nothing to partition without entries', () => {
    expect(partitionCertificateEntries([])).toEqual({ valid: [], failures: [] });
  });

  it('sets apart a certificate that did not parse', () => {
    const entries = [parsedEntry(), unparsed('3003020101')];
    const { valid, failures } = partitionCertificateEntries(entries);
    expect(valid.map(({ index }) => index)).toEqual([0]);
    expect(failures).toEqual([{ entry: entries[1], index: 1, parsed: entries[1].parsedX5c }]);
  });

  it('skips entries that are not objects', () => {
    const { valid } = partitionCertificateEntries([null, 'MIIB', parsedEntry()]);
    expect(valid.map(({ index }) => index)).toEqual([2]);
  });

  it('counts an entry without parsed details as valid', () => {
    const entry = { pem: certificate().pem };
    expect(partitionCertificateEntries([entry]).valid).toEqual([{ entry, index: 0, parsed: null }]);
  });

  it('drops a failure that repeats a certificate that parsed', () => {
    const entry = parsedEntry();
    expect(partitionCertificateEntries([entry, unparsed(entry.raw)]).failures).toEqual([]);
  });

  it('keeps a failure that cannot be named', () => {
    const failure = { parsedX5c: { parseError: 'error parsing asn1 value' } };
    expect(partitionCertificateEntries([parsedEntry(), failure]).failures).toHaveLength(1);
  });

  it('keeps every failure when no certificate that parsed can be named', () => {
    const entries = [{ parsedX5c: { subject: 'CN=Characterization Attestation Leaf' } }, unparsed('3003020101')];
    expect(partitionCertificateEntries(entries).failures).toHaveLength(1);
  });
});
