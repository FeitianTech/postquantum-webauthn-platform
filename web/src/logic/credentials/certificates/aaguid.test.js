import { describe, expect, it } from 'vitest';

import {
  extractAaguidFromCertificateEntries,
  extractAaguidFromCertificateEntry,
  extractAaguidFromExtensionValue,
} from './aaguid.js';
import { certificate } from '@/test/logic/credentials/certificates.js';

// The AAGUID an attestation certificate carries (credentials/certificates/aaguid.js).

const AAGUID = '00112233445566778899aabbccddeeff';
const AAGUID_OID = '1.3.6.1.4.1.45724.1.1.4';

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
