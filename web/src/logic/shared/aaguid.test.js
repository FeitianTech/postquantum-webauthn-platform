import { describe, expect, it } from 'vitest';

import { aaguidGuid, aaguidHex } from './aaguid.js';
import { goldenAnswers } from '@/test/logic/simple/ceremony-answers.js';

// An AAGUID read by each of its two readers (shared/aaguid.js).

function storedCredential(scenario) {
  return goldenAnswers(scenario).find(({ body }) => body && body.storedCredential).body.storedCredential;
}

const ES256 = storedCredential('simple-register-es256');
const AAGUID = '00112233445566778899aabbccddeeff';
const GUID = '00112233-4455-6677-8899-aabbccddeeff';

describe('aaguidHex, a record\'s or the server\'s AAGUID', () => {
  it('reads hex, a dashed GUID in either case, base64 and base64url', () => {
    expect(aaguidHex(AAGUID)).toBe(AAGUID);
    expect(aaguidHex('00112233-4455-6677-8899-AABBCCDDEEFF')).toBe(AAGUID);
    expect(aaguidHex('ABEiM0RVZneImaq7zN3u/w==')).toBe(AAGUID);
    expect(aaguidHex(ES256.aaguid)).toBe(AAGUID);
  });

  it('reads bytes, as an array, a view or a buffer', () => {
    expect(aaguidHex([0, 17, 34, 51])).toBe('00112233');
    expect(aaguidHex(new Uint8Array([0, 17, 34, 51]))).toBe('00112233');
    expect(aaguidHex(new Uint8Array([1, 2, 3, 4]).buffer)).toBe('01020304');
  });

  it('keeps any length, as a certificate whose AAGUID extension is not sixteen bytes gives it', () => {
    expect(aaguidHex('0410' + AAGUID)).toBe('0410' + AAGUID);
  });

  it('reads the hex digits of text that is neither hex nor base64', () => {
    expect(aaguidHex('0011:2233')).toBe('00112233');
  });

  it('reads 22 characters the strict base64url decoder takes as the sixteen bytes they spell, though every one is a hex digit', () => {
    // The all-zero AAGUID, which a browser sends when no attestation is asked for.
    expect(aaguidHex('AAAAAAAAAAAAAAAAAAAAAA')).toBe('0'.repeat(32));
    expect(aaguidHex('0123456789abcdefABCDEA')).toBe('d35db7e39ebbf3d69b71d79f00108310');
  });

  it('reads 22 hex digits that spell no sixteen bytes in base64url as hex, as before', () => {
    expect(aaguidHex('0123456789abcdef012345')).toBe('0123456789abcdef012345');
  });

  it('reads the relying party\'s AAGUID: its raw bytes, else its GUID', () => {
    expect(aaguidHex(ES256.relyingParty.aaguid)).toBe(AAGUID);
    expect(aaguidHex({ raw: [0, 17, 34, 51] })).toBe('00112233');
    expect(aaguidHex({ ...ES256.relyingParty.aaguid, raw: '' })).toBe(AAGUID);
    expect(aaguidHex({ guid: GUID })).toBe(AAGUID);
  });

  it('finds no AAGUID in text it cannot read, a list that is not bytes, a number, or an object with none', () => {
    expect(aaguidHex('')).toBe('');
    expect(aaguidHex('  ')).toBe('');
    expect(aaguidHex('—')).toBe('');
    // Text that looks like base64 but has no base64 length holds no AAGUID; it is not an error.
    expect(aaguidHex('abcde')).toBe('');
    expect(aaguidHex('abcdefgh_')).toBe('');
    expect(aaguidHex([1, Symbol('x')])).toBe('');
    expect(aaguidHex(0)).toBe('');
    expect(aaguidHex({ unknown: true })).toBe('');
    expect(aaguidHex({ raw: '', guid: '' })).toBe('');
  });
});

describe('aaguidGuid, an AAGUID as the server spells an MDS entry\'s', () => {
  it('dashes thirty-two hex digits, or a GUID, in lower case', () => {
    expect(aaguidGuid(AAGUID)).toBe(GUID);
    expect(aaguidGuid('00112233-4455-6677-8899-AABBCCDDEEFF')).toBe(GUID);
    expect(aaguidGuid('{00112233-4455-6677-8899-aabbccddeeff}')).toBe(GUID);
  });

  it('reads sixteen bytes, as a list, a view or a buffer', () => {
    const bytes = new Uint8Array([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    expect(aaguidGuid(Array.from(bytes))).toBe(GUID);
    expect(aaguidGuid(bytes)).toBe(GUID);
    expect(aaguidGuid(new DataView(bytes.buffer))).toBe(GUID);
    expect(aaguidGuid(bytes.buffer)).toBe(GUID);
  });

  it('reads a value by its text form', () => {
    expect(aaguidGuid({ toString: () => AAGUID })).toBe(GUID);
  });

  it('reads no GUID from text that is not one, base64, too few bytes, or a value with no text form', () => {
    expect(aaguidGuid('not-guid')).toBe('');
    expect(aaguidGuid('   ')).toBe('');
    expect(aaguidGuid('ABEiM0RVZneImaq7zN3u_w')).toBe('');
    expect(aaguidGuid('00112233')).toBe('');
    expect(aaguidGuid(['1', 2])).toBe('');
    expect(aaguidGuid(null)).toBe('');
    expect(aaguidGuid(Object.create(null))).toBe('');
    expect(aaguidGuid({ toString() { throw new Error('no'); } })).toBe('');
  });
});
