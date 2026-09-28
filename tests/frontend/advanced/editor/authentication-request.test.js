import { describe, expect, it } from 'vitest';

import {
  allowedCredentials,
  authenticationControls,
  authenticationDefaults,
  buildRequestOptions,
  changeAuthentication,
  readRequestOptions,
  withAvailability,
} from '../../../../frontend/static/scripts/advanced/json-editor/authentication-request.js';

// An authentication's request and the form's settings it is built from, with
// no page (advanced/json-editor/authentication-request.js).

const CHALLENGE = '00112233445566778899aabbccddeeff';
const PLATFORM = { type: 'advanced', credentialIdHex: 'aa01', authenticatorAttachment: 'platform' };
const ROAMING = { type: 'advanced', credentialIdHex: 'bb02', authenticatorAttachment: 'cross-platform' };
// Its ID only as base64url (AwQ is 0304); no attachment.
const UNATTACHED = { type: 'simple', credentialId: 'AwQ' };
const STORED = [PLATFORM, ROAMING, UNATTACHED];
const CONTEXT = { hostname: 'localhost', storedCredentials: STORED };

function settings(extra = {}) {
  return { ...authenticationDefaults(), challenge: CHALLENGE, ...extra };
}

const build = (extra = {}, context = CONTEXT) => buildRequestOptions(settings(extra), context).publicKey;
const ids = (list) => list.map((descriptor) => descriptor.id.$hex);

describe('the defaults', () => {
  it('are the form\'s, without the values drawn at random', () => {
    expect(authenticationDefaults()).toEqual({
      userVerification: 'preferred',
      allowCredentials: 'all',
      fakeCredLength: '256',
      timeout: '90000',
      hints: [],
      hashAlgorithm: 'SHA-256',
      largeBlob: '',
      largeBlobWrite: '',
      prfFirst: '',
      prfSecond: '',
    });
  });

  it('are a new copy each time', () => {
    authenticationDefaults().hints.push('hybrid');
    expect(authenticationDefaults().hints).toEqual([]);
  });
});

describe('the request the settings build', () => {
  it('holds the challenge, the timeout, the relying party, every saved credential and the user verification', () => {
    expect(build()).toEqual({
      challenge: { $hex: CHALLENGE },
      timeout: 90000,
      rpId: 'localhost',
      allowCredentials: [
        { type: 'public-key', id: { $hex: 'aa01' } },
        { type: 'public-key', id: { $hex: 'bb02' } },
        { type: 'public-key', id: { $hex: '0304' } },
      ],
      userVerification: 'preferred',
      extensions: {},
    });
  });

  it('takes the timeout typed, 90000 for none, and preferred for no user verification', () => {
    expect(build({ timeout: '1234', userVerification: 'required' })).toMatchObject({ timeout: 1234, userVerification: 'required' });
    expect(build({ timeout: '', userVerification: '' })).toMatchObject({ timeout: 90000, userVerification: 'preferred' });
  });

  it('offers, for All, the saved credentials whose attachment the hints allow', () => {
    expect(ids(build({ hints: ['client-device'] }).allowCredentials)).toEqual(['aa01']);
    expect(ids(build({ hints: ['security-key', 'client-device'] }).allowCredentials)).toEqual(['aa01', 'bb02']);
    expect(build({ hints: ['hybrid'] }).hints).toEqual(['hybrid']);
    expect(build()).not.toHaveProperty('hints');
  });

  it('leaves allowCredentials out for Empty, unless fake IDs follow', () => {
    expect(build({ allowCredentials: 'empty' })).not.toHaveProperty('allowCredentials');
    expect(ids(build({ allowCredentials: 'empty' }, { ...CONTEXT, fakeAllowCredentials: ['ffee'] }).allowCredentials)).toEqual(['ffee']);
  });

  it('offers a chosen credential alone, none when the hints refuse it, and All for a choice no credential has', () => {
    expect(ids(build({ allowCredentials: 'bb02' }).allowCredentials)).toEqual(['bb02']);
    expect(ids(build({ allowCredentials: '0304' }).allowCredentials)).toEqual(['0304']);
    expect(build({ allowCredentials: 'bb02', hints: ['client-device'] }).allowCredentials).toEqual([]);
    expect(build({ allowCredentials: '0304', hints: ['hybrid'] }).allowCredentials).toEqual([]);
    expect(ids(build({ allowCredentials: 'gone' }).allowCredentials)).toEqual(['aa01', 'bb02', '0304']);
  });

  it('puts the fake IDs after the saved ones', () => {
    const publicKey = build({ allowCredentials: 'aa01' }, { ...CONTEXT, fakeAllowCredentials: ['ffee', 'ddcc'] });
    expect(ids(publicKey.allowCredentials)).toEqual(['aa01', 'ffee', 'ddcc']);
  });

  it('asks for largeBlob to be read, or written when there is a value to write', () => {
    expect(build({ largeBlob: 'read', largeBlobWrite: 'beef' }).extensions).toEqual({ largeBlob: { read: true } });
    expect(build({ largeBlob: 'write', largeBlobWrite: 'beef' }).extensions).toEqual({ largeBlob: { write: { $hex: 'beef' } } });
    expect(build({ largeBlob: 'write' }).extensions).toEqual({});
  });

  it('asks for the prf evaluations when there is a first one', () => {
    expect(build({ prfFirst: '11' }).extensions).toEqual({ prf: { eval: { first: { $hex: '11' } } } });
    expect(build({ prfFirst: '11', prfSecond: '22' }).extensions).toEqual({ prf: { eval: { first: { $hex: '11' }, second: { $hex: '22' } } } });
    expect(build({ prfSecond: '22' }).extensions).toEqual({});
  });

  it('needs no saved credentials', () => {
    expect(build({}, { hostname: 'localhost' }).allowCredentials).toEqual([]);
  });
});

describe('the saved credentials a choice allows', () => {
  it('reads a record\'s ID from its fields when it has no hex, and skips one with none', () => {
    expect(ids(allowedCredentials([UNATTACHED, { type: 'simple' }], 'all', []))).toEqual(['0304']);
    expect(allowedCredentials(undefined, 'all', [])).toEqual([]);
  });
});

describe('the settings a request says', () => {
  const previous = settings({ prfFirst: '99', largeBlobWrite: '77', hints: ['hybrid'] });
  const read = (publicKey, context = { choices: ['all', 'empty', 'aa01', 'bb02'] }) => readRequestOptions(publicKey, previous, context);

  it('takes what the request gives over the form\'s, and keeps the rest', () => {
    const { settings: next, fakeAllowCredentials } = read({
      challenge: { $hex: 'c0de' },
      timeout: 333,
      allowCredentials: [{ type: 'public-key', id: { $hex: 'bb02' } }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: { $hex: 'aaaa' }, second: { $hex: 'bbbb' } } }, largeBlob: { write: { $hex: '1234' } } },
      hints: ['client-device'],
    });
    expect(next).toEqual({
      ...previous,
      challenge: 'c0de',
      timeout: '333',
      allowCredentials: 'bb02',
      userVerification: 'required',
      prfFirst: 'aaaa',
      prfSecond: 'bbbb',
      largeBlob: 'write',
      largeBlobWrite: '1234',
      hints: ['client-device'],
    });
    expect(fakeAllowCredentials).toEqual([]);
  });

  it('reads Empty without allowCredentials, All for a list that is not one offered credential, and nothing from an empty list', () => {
    expect(read({}).settings.allowCredentials).toBe('empty');
    expect(read({ allowCredentials: 'nope' }).settings.allowCredentials).toBe('all');
    expect(read({ allowCredentials: [{ id: { $hex: 'aa01' } }, { id: { $hex: 'bb02' } }] }).settings.allowCredentials).toBe('all');
    expect(read({ allowCredentials: [{ id: { $hex: 'ffff' } }] }).settings.allowCredentials).toBe('all');
    expect(read({ allowCredentials: [null] }).settings.allowCredentials).toBe('all');
    expect(read({ allowCredentials: [{ id: { $hex: 'aa01' } }] }, {}).settings.allowCredentials).toBe('all');
    expect(read({ allowCredentials: [] }).settings.allowCredentials).toBe('all');
    expect(readRequestOptions({ allowCredentials: [] }, settings({ allowCredentials: 'aa01' })).settings.allowCredentials).toBe('aa01');
  });

  it('reads a largeBlob read, a user verification left empty, and ignores what is not there or not a value', () => {
    const { settings: next } = read({
      challenge: { $hex: '' },
      timeout: 0,
      userVerification: '',
      extensions: { largeBlob: { read: true }, prf: { eval: { first: { $hex: '' } } } },
    });
    expect(next).toMatchObject({ challenge: CHALLENGE, timeout: '90000', userVerification: 'preferred', largeBlob: 'read', prfFirst: '99' });
    expect(read({ extensions: { largeBlob: { write: { $hex: '' } }, prf: {} } }).settings).toMatchObject({ largeBlob: 'write', largeBlobWrite: '77' });
    expect(read({ extensions: { largeBlob: {} } }).settings.largeBlob).toBe('');
    expect(read({ extensions: { prf: { eval: { second: { $hex: '22' } } } } }).settings).toMatchObject({ prfFirst: '99', prfSecond: '22' });
    expect(read({}).settings.hints).toEqual(['hybrid']);
  });
});

describe('the form\'s rules', () => {
  it('empties the second prf evaluation with the first', () => {
    expect(changeAuthentication(settings({ prfFirst: '11', prfSecond: '22' }), 'prfFirst', ' ')).toMatchObject({ prfFirst: ' ', prfSecond: '' });
    expect(changeAuthentication(settings({ prfFirst: '11', prfSecond: '22' }), 'prfFirst', '33')).toMatchObject({ prfSecond: '22' });
    expect(changeAuthentication(settings(), 'userVerification', 'required').userVerification).toBe('required');
  });

  const available = { largeBlob: { available: true }, prf: { available: true } };
  const unavailable = { largeBlob: { available: false }, prf: { available: false } };

  it('clears what the extensions cannot ask for', () => {
    const full = settings({ largeBlob: 'write', largeBlobWrite: 'beef', prfFirst: '11', prfSecond: '22' });
    expect(withAvailability(full, available)).toEqual(full);
    expect(withAvailability(full, unavailable)).toEqual(settings());
  });

  it('locks what the extensions cannot ask for, the value to write but on Write, and the second prf without a first', () => {
    expect(authenticationControls(settings({ largeBlob: 'write', prfFirst: '11' }), available)).toEqual({
      largeBlob: false,
      largeBlobWrite: false,
      prfFirst: false,
      prfSecond: false,
    });
    expect(authenticationControls(settings({ largeBlob: 'read' }), available)).toEqual({
      largeBlob: false,
      largeBlobWrite: true,
      prfFirst: false,
      prfSecond: true,
    });
    expect(authenticationControls(settings({ largeBlob: 'write', prfFirst: '11' }), unavailable)).toEqual({
      largeBlob: true,
      largeBlobWrite: true,
      prfFirst: true,
      prfSecond: true,
    });
  });
});
