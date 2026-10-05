// The raw view's entry and words (mds/raw-data.js).
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  authenticatorRawTitle,
  getAuthenticatorRawData,
} from './raw-data.js';
import { repoFile } from '@/test/logic/repo-file.js';

const FIXTURE = JSON.parse(readFileSync(repoFile('tests/fixtures/mds/snapshot/fido-mds3.explorer.full.json'), 'utf8'));
const named = name => FIXTURE.entries.find(entry => entry.name === name);

describe('the raw view\'s words', () => {
  it('keeps the window\'s title, label and the Raw button\'s titles', () => {
    expect(authenticatorRawTitle({ name: ' Fixture Key ' })).toBe('Fixture Key – Authenticator Raw Data');
    expect(authenticatorRawTitle({ name: '  ' })).toBe('Authenticator Raw Data');
    expect(authenticatorRawTitle({ name: 3 })).toBe('Authenticator Raw Data');
    expect(authenticatorRawTitle(null)).toBe('Authenticator Raw Data');
  });
});

describe('the entry as MDS publishes it', () => {
  it('puts back what the explorer took out of a listed entry, and leaves the entry as it was', () => {
    const entry = named('Fixture U2F Key');
    const before = JSON.stringify(entry);
    const raw = getAuthenticatorRawData(entry);
    expect(Object.keys(raw)).toEqual(['metadataStatement', 'attestationCertificateKeyIdentifiers', 'statusReports', 'id', 'timeOfLastStatusChange']);
    expect(raw.metadataStatement.attestationRootCertificates).toBe(entry.attestationCertificates);
    expect(raw.metadataStatement.attestationCertificateKeyIdentifiers).toBe(entry.attestationKeyIdentifiers);
    expect(Object.keys(raw.metadataStatement).slice(-2)).toEqual(['attestationRootCertificates', 'attestationCertificateKeyIdentifiers']);
    expect(raw.attestationCertificateKeyIdentifiers).toBe(entry.attestationKeyIdentifiers);
    expect(JSON.stringify(entry)).toBe(before);

    const fido2 = getAuthenticatorRawData(named('Fixture Security Key L1'));
    expect(Object.keys(fido2)).toEqual(['metadataStatement', 'statusReports', 'aaguid', 'id', 'timeOfLastStatusChange']);
  });

  it('puts back a listed entry\'s biometric status reports and rogue list', () => {
    const entry = named('Fixture Security Key L2');
    const raw = getAuthenticatorRawData(entry);
    expect(Object.keys(raw)).toEqual([
      'metadataStatement',
      'statusReports',
      'biometricStatusReports',
      'aaguid',
      'id',
      'timeOfLastStatusChange',
      'rogueListURL',
      'rogueListHash',
    ]);
    expect(raw.biometricStatusReports).toBe(entry.biometricStatusReports);
    expect(raw.biometricStatusReports[0].modality).toBe('fingerprint_internal');
    expect([raw.rogueListURL, raw.rogueListHash]).toEqual([entry.rogueListURL, entry.rogueListHash]);
    expect(getAuthenticatorRawData({ id: 'i', biometricStatusReports: [], rogueListURL: '', rogueListHash: null })).toEqual({ id: 'i' });
    expect(
      getAuthenticatorRawData({ rawEntry: { rogueListURL: 'own', biometricStatusReports: [] }, rogueListURL: 'listed', biometricStatusReports: [{}] }),
    ).toEqual({ rogueListURL: 'own', biometricStatusReports: [] });
  });

  it('starts from the entry\'s own BLOB entry when it has one', () => {
    const rawEntry = {
      aaguid: 'raw',
      metadataStatement: { description: 'raw', attestationRootCertificates: ['R'] },
      timeOfLastStatusChange: '2020-01-01',
    };
    const raw = getAuthenticatorRawData({
      rawEntry,
      metadataStatement: { description: 'listed' },
      attestationCertificates: ['L'],
      attestationKeyIdentifiers: ['k'],
      statusReports: [{ status: 'FIDO_CERTIFIED' }],
      aaguid: 'listed',
      id: 'listed-id',
      timeOfLastStatusChange: '2021-01-01',
    });
    expect(raw).toEqual({
      aaguid: 'raw',
      metadataStatement: { description: 'raw', attestationRootCertificates: ['R'], attestationCertificateKeyIdentifiers: ['k'] },
      timeOfLastStatusChange: '2020-01-01',
      attestationCertificateKeyIdentifiers: ['k'],
      statusReports: [{ status: 'FIDO_CERTIFIED' }],
      id: 'listed-id',
    });
    expect(rawEntry.metadataStatement).toEqual({ description: 'raw', attestationRootCertificates: ['R'] });
  });

  it('keeps what the entry already says, and a statement that is a list', () => {
    expect(
      getAuthenticatorRawData({
        rawEntry: [1, 2],
        metadataStatement: [1, 2],
        attestationCertificates: ['C'],
        attestationKeyIdentifiers: ['k'],
      }),
    ).toEqual({ metadataStatement: [1, 2], attestationCertificateKeyIdentifiers: ['k'] });
    expect(
      getAuthenticatorRawData({
        rawEntry: { attestationCertificateKeyIdentifiers: ['own'], statusReports: [], aaguid: '', id: '', timeOfLastStatusChange: '' },
        metadataStatement: { attestationCertificateKeyIdentifiers: ['m'] },
        attestationKeyIdentifiers: ['k'],
        statusReports: [{}],
        aaguid: 'a',
        id: 'i',
        timeOfLastStatusChange: 't',
      }),
    ).toEqual({
      attestationCertificateKeyIdentifiers: ['own'],
      statusReports: [],
      aaguid: '',
      id: '',
      timeOfLastStatusChange: '',
      metadataStatement: { attestationCertificateKeyIdentifiers: ['m'] },
    });
    expect(
      getAuthenticatorRawData({ metadataStatement: { attestationCertificateKeyIdentifiers: ['m'] }, attestationKeyIdentifiers: ['k'] }),
    ).toEqual({ metadataStatement: { attestationCertificateKeyIdentifiers: ['m'] }, attestationCertificateKeyIdentifiers: ['k'] });
    expect(getAuthenticatorRawData({ attestationKeyIdentifiers: 'k', attestationCertificates: [], statusReports: 'x' })).toBeNull();
    // A BLOB entry that is a list is not copied, but its time still is.
    expect(getAuthenticatorRawData({ rawEntry: Object.assign([1], { timeOfLastStatusChange: 'r' }) })).toEqual({
      timeOfLastStatusChange: 'r',
    });
    expect(getAuthenticatorRawData({ rawEntry: { aaguid: 'r' }, timeOfLastStatusChange: 't' })).toEqual({
      aaguid: 'r',
      timeOfLastStatusChange: 't',
    });
  });

  it('has nothing for an entry with nothing to show', () => {
    expect(getAuthenticatorRawData({})).toBeNull();
    expect(getAuthenticatorRawData({ metadataStatement: 'text' })).toBeNull();
    expect(getAuthenticatorRawData(null)).toBeNull();
    expect(getAuthenticatorRawData('entry')).toBeNull();
  });
});
