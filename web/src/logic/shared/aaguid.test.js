import { describe, expect, it } from 'vitest';

import { hexToGuid, normaliseAaguidValue } from './aaguid.js';
import { goldenAnswers } from '@/test/logic/simple/ceremony-answers.js';

// An AAGUID as lower-case hex, from any spelling a record or the server gives
// (shared/aaguid.js).

function storedCredential(scenario) {
  return goldenAnswers(scenario).find(({ body }) => body && body.storedCredential).body.storedCredential;
}

const ES256 = storedCredential('simple-register-es256');
const AAGUID = '00112233445566778899aabbccddeeff';

describe('normaliseAaguidValue', () => {
  it('reads hex, a dashed GUID in either case, base64 and base64url', () => {
    expect(normaliseAaguidValue(AAGUID)).toBe(AAGUID);
    expect(normaliseAaguidValue('00112233-4455-6677-8899-AABBCCDDEEFF')).toBe(AAGUID);
    expect(normaliseAaguidValue('ABEiM0RVZneImaq7zN3u/w==')).toBe(AAGUID);
    expect(normaliseAaguidValue(ES256.aaguid)).toBe(AAGUID);
  });

  it('reads bytes, as an array, a view or a buffer', () => {
    expect(normaliseAaguidValue([0, 17, 34, 51])).toBe('00112233');
    expect(normaliseAaguidValue(new Uint8Array([0, 17, 34, 51]))).toBe('00112233');
    expect(normaliseAaguidValue(new Uint8Array([1, 2, 3, 4]).buffer)).toBe('01020304');
  });

  it('reads the hex digits of text that is neither hex nor base64', () => {
    expect(normaliseAaguidValue('0011:2233')).toBe('00112233');
  });

  it('reads 22 characters the strict base64url decoder takes as the sixteen bytes they spell, though every one is a hex digit', () => {
    // The all-zero AAGUID, which a browser sends when no attestation is asked for.
    expect(normaliseAaguidValue('AAAAAAAAAAAAAAAAAAAAAA')).toBe('0'.repeat(32));
    expect(normaliseAaguidValue('0123456789abcdefABCDEA')).toBe('d35db7e39ebbf3d69b71d79f00108310');
  });

  it('reads 22 hex digits that spell no sixteen bytes in base64url as hex, as before', () => {
    expect(normaliseAaguidValue('0123456789abcdef012345')).toBe('0123456789abcdef012345');
  });

  it('reads each spelling an object may hold, the first that gives one', () => {
    expect(normaliseAaguidValue({ guid: '00112233-4455-6677-8899-aabbccddeeff' })).toBe(AAGUID);
    expect(normaliseAaguidValue({ hex: AAGUID })).toBe(AAGUID);
    expect(normaliseAaguidValue({ raw: [0, 17, 34, 51] })).toBe('00112233');
    expect(normaliseAaguidValue({ base64url: 'ABEiM0RVZneImaq7zN3u_w' })).toBe(AAGUID);
    expect(normaliseAaguidValue({ metadata: { aaguid: 'ABEiM0RVZneImaq7zN3u/w==' } })).toBe(AAGUID);
  });

  it('reads the GUID spelling when the raw bytes or the hex spelling are empty', () => {
    expect(normaliseAaguidValue({ ...ES256.relyingParty.aaguid, raw: '' })).toBe(AAGUID);
    expect(normaliseAaguidValue({ hex: '', guid: ES256.properties.aaguidGuid })).toBe(AAGUID);
  });

  it('skips a base64 spelling that holds no hex and reads the next one', () => {
    expect(normaliseAaguidValue({ base64: '—', base64url: ES256.aaguid })).toBe(AAGUID);
  });

  it('finds no AAGUID in text it cannot read, a list that is not bytes, a number, or an object with none', () => {
    expect(normaliseAaguidValue('')).toBe('');
    expect(normaliseAaguidValue('  ')).toBe('');
    expect(normaliseAaguidValue('—')).toBe('');
    // Text that looks like base64 but has no base64 length holds no AAGUID; it is not an error.
    expect(normaliseAaguidValue('abcde')).toBe('');
    expect(normaliseAaguidValue('abcdefgh_')).toBe('');
    expect(normaliseAaguidValue([1, Symbol('x')])).toBe('');
    expect(normaliseAaguidValue(0)).toBe('');
    expect(normaliseAaguidValue({ unknown: true })).toBe('');
    expect(normaliseAaguidValue({ hex: '', raw: '', guid: '' })).toBe('');
  });

  it('finds none when an object\'s hex method throws', () => {
    expect(normaliseAaguidValue({ hex() { throw new Error('bad hex encoder'); } })).toBe('');
  });
});

describe('hexToGuid', () => {
  it('dashes thirty-two hex digits as a GUID', () => {
    expect(hexToGuid(AAGUID)).toBe('00112233-4455-6677-8899-aabbccddeeff');
  });

  it('gives none for anything but thirty-two digits', () => {
    expect(hexToGuid('00112233')).toBe('');
    expect(hexToGuid('')).toBe('');
  });
});
