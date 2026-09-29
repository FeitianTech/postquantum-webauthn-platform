// The raw view's logic (MDS-W1), which web/ imports: raw-data.js and
// raw-stringify.js.
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  RAW_DATA_BUTTON_TITLE,
  RAW_DATA_LABEL,
  RAW_DATA_TITLE,
  RAW_DATA_UNAVAILABLE_TITLE,
  authenticatorRawTitle,
  getAuthenticatorRawData,
} from './raw-data.js';
import { stringifyAuthenticatorRawData } from './raw-stringify.js';
import { repoFile } from '@/test/logic/repo-file.js';

const FIXTURE = JSON.parse(readFileSync(repoFile('tests/fixtures/mds/snapshot/fido-mds3.explorer.full.json'), 'utf8'));
const named = name => FIXTURE.entries.find(entry => entry.name === name);

describe('the raw view\'s words', () => {
  it('keeps the window\'s title, label and the Raw button\'s titles', () => {
    expect(RAW_DATA_TITLE).toBe('Authenticator Raw Data');
    expect(RAW_DATA_LABEL).toBe('Raw authenticator metadata');
    expect(RAW_DATA_BUTTON_TITLE).toBe('View raw authenticator data');
    expect(RAW_DATA_UNAVAILABLE_TITLE).toBe('Raw authenticator data unavailable');
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

describe('the raw view\'s text', () => {
  it('is JSON indented by four spaces', () => {
    expect(stringifyAuthenticatorRawData({ a: [1, { b: 'c' }] })).toBe('{\n    "a": [\n        1,\n        {\n            "b": "c"\n        }\n    ]\n}');
  });

  it('writes out what JSON cannot: big integers, maps, sets, bytes and cycles', () => {
    const cycle = { name: 'loop' };
    cycle.self = cycle;
    const bytes = new Uint8Array([9, 1, 2, 3]).subarray(1);
    const value = {
      big: 12345678901234567890n,
      map: new Map([['k', 1]]),
      set: new Set(['a', 'b']),
      buffer: new Uint8Array([4, 5]).buffer,
      view: bytes,
      data: new DataView(new ArrayBuffer(1)),
      cycle,
    };
    expect(JSON.parse(stringifyAuthenticatorRawData(value))).toEqual({
      big: '12345678901234567890',
      map: { k: 1 },
      set: ['a', 'b'],
      buffer: [4, 5],
      view: [1, 2, 3],
      data: [0],
      cycle: { name: 'loop', self: '[Circular]' },
    });
  });

  it('writes a line per key when JSON cannot write the value at all', () => {
    const refuses = () => {
      throw new Error('no JSON');
    };
    const noString = Object.assign(() => 1, { toJSON: refuses, [Symbol.toPrimitive]: refuses });
    const noJson = Object.assign(() => 2, { toJSON: refuses });
    const value = {
      toJSON: refuses,
      text: 'a "quoted" word',
      nothing: undefined,
      empty: null,
      count: 3,
      big: 4n,
      yes: true,
      no: false,
      symbol: Symbol('s'),
      noJson,
      noString,
      emptyList: [],
      emptyMap: {},
      list: [1, [2, [], {}], { inner: 'x' }],
      nested: { deeper: { leaf: 'y' } },
    };
    expect(stringifyAuthenticatorRawData(value).split('\n')).toEqual([
      'toJSON: undefined',
      'text: "a \\"quoted\\" word"',
      'nothing: undefined',
      'empty: null',
      'count: 3',
      'big: 4',
      'yes: true',
      'no: false',
      'symbol: undefined',
      `noJson: ${String(noJson)}`,
      'noString: ',
      'emptyList:',
      '    []',
      'emptyMap:',
      '    {}',
      'list:',
      '    1',
      '        2',
      '        []',
      '        {}',
      // A map inside a list is written at the list's own depth, as it always was.
      '    inner: "x"',
      'nested:',
      '    deeper:',
      '        leaf: "y"',
    ]);
    expect(stringifyAuthenticatorRawData([noJson, [], {}]).split('\n')).toEqual([`    ${String(noJson)}`, '    []', '    {}']);
    expect(stringifyAuthenticatorRawData(noJson)).toBe(String(noJson));
  });
});
