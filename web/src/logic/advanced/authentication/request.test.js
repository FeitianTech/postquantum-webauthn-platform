import { describe, expect, it } from 'vitest';

import {
  allowedCredentials,
  authenticationControls,
  authenticationDefaults,
  buildRequestOptions,
  changeAuthentication,
  readRequestOptions,
  withAvailability,
} from './request.js';

// An authentication's request and the form's settings it is built from, with
// no page (advanced/authentication/request.js).

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
  const CHOICES = { storedCredentials: STORED, choices: ['all', 'empty', 'aa01', 'bb02', '0304'] };
  const read = (publicKey, context = CHOICES, from = previous) => readRequestOptions(publicKey, from, context);

  it('takes what the request gives over the form\'s', () => {
    const { settings: next, fakeAllowCredentials } = read({
      challenge: { $hex: 'c0de' },
      timeout: 333,
      allowCredentials: [{ type: 'public-key', id: { $hex: '0304' } }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: { $hex: 'aaaa' }, second: { $hex: 'bbbb' } } }, largeBlob: { write: { $hex: '1234' } } },
      hints: ['client-device'],
    });
    expect(next).toEqual({
      ...previous,
      challenge: 'c0de',
      timeout: '333',
      allowCredentials: '0304',
      userVerification: 'required',
      prfFirst: 'aaaa',
      prfSecond: 'bbbb',
      largeBlob: 'write',
      largeBlobWrite: '1234',
      hints: ['client-device'],
    });
    expect(fakeAllowCredentials).toEqual([]);
  });

  it('turns off what the form writes and the request leaves out: hints, prf, largeBlob', () => {
    const { settings: next } = read({ allowCredentials: [], extensions: {} }, CHOICES, settings({ hints: ['hybrid'], prfFirst: '11', prfSecond: '22', largeBlob: 'read' }));
    expect(next).toMatchObject({ hints: [], prfFirst: '', prfSecond: '', largeBlob: '' });
    // Without extensions at all, and a Write with nothing to write, which builds none, stays.
    expect(read({}, CHOICES, settings({ largeBlob: 'write' })).settings).toMatchObject({ largeBlob: 'write', prfFirst: '' });
    expect(read({}, CHOICES, settings({ largeBlob: 'write', largeBlobWrite: 'beef' })).settings.largeBlob).toBe('');
  });

  it('reads a largeBlob read, a Write with a value it cannot read, and the form\'s own values it always writes', () => {
    const { settings: next } = read({
      challenge: { $hex: '' },
      userVerification: '',
      extensions: { largeBlob: { read: true }, prf: { eval: { first: { $hex: '' }, second: { $hex: '22' } } } },
    });
    expect(next).toMatchObject({ challenge: CHALLENGE, timeout: '90000', userVerification: 'preferred', largeBlob: 'read', largeBlobWrite: '77', prfFirst: '', prfSecond: '' });
    expect(read({ extensions: { largeBlob: { write: { $hex: '' } } } }).settings).toMatchObject({ largeBlob: 'write', largeBlobWrite: '77' });
    expect(read({ timeout: 0 }).settings.timeout).toBe('0');
  });

  it('reads Empty without allowCredentials, and nothing of the choice from an empty list or one that is not a list', () => {
    expect(read({}).settings.allowCredentials).toBe('empty');
    expect(read({ allowCredentials: [] }, CHOICES, settings({ allowCredentials: 'aa01' })).settings.allowCredentials).toBe('aa01');
    expect(read({ allowCredentials: 'nope' }).settings.allowCredentials).toBe('all');
  });

  it('keeps the choice when the list is what it builds, even one credential that All builds', () => {
    const one = [{ type: 'public-key', id: { $hex: 'bb02' } }];
    // With security-key, All builds bb02 alone: an edit elsewhere does not turn All into bb02.
    expect(read({ allowCredentials: one, hints: ['security-key'] }, CHOICES, settings()).settings.allowCredentials).toBe('all');
    expect(read({ allowCredentials: one }, CHOICES, settings()).settings.allowCredentials).toBe('bb02');
    // A choice the hints refuse builds none; the fake IDs follow.
    expect(read({ allowCredentials: [{ id: { $hex: 'ffee' } }], hints: ['client-device'] }, CHOICES, settings({ allowCredentials: 'bb02' })).settings.allowCredentials).toBe('bb02');
    expect(read({ allowCredentials: [{ id: { $hex: 'ffee' } }] }, CHOICES, settings({ allowCredentials: 'empty' })).settings.allowCredentials).toBe('empty');
  });

  it('reads one offered credential as that credential, in any case, and any other list as All', () => {
    expect(read({ allowCredentials: [{ id: { $hex: 'AA01' } }] }, CHOICES, settings({ allowCredentials: 'empty' })).settings.allowCredentials).toBe('aa01');
    expect(read({ allowCredentials: [{ id: { $hex: 'aa01' } }] }, { storedCredentials: STORED }, settings({ allowCredentials: 'empty' })).settings.allowCredentials).toBe('all');
    expect(read({ allowCredentials: [{ id: { $hex: 'bb02' } }, { id: { $hex: 'aa01' } }] }).settings.allowCredentials).toBe('all');
    expect(read({ allowCredentials: [null, { id: {} }] }, CHOICES, settings({ allowCredentials: 'aa01' })).settings.allowCredentials).toBe('all');
  });

  it('gives the IDs no saved credential has as the fake IDs, as they are spelled', () => {
    const list = [{ id: { $hex: 'aa01' } }, { id: { $hex: 'FFEE' } }, { id: 'AwQ' }, { id: { $hex: 'ddcc' } }];
    expect(read({ allowCredentials: list }).fakeAllowCredentials).toEqual(['FFEE', 'ddcc']);
    expect(read({ allowCredentials: list }, {}).fakeAllowCredentials).toEqual(['aa01', 'FFEE', '0304', 'ddcc']);
    expect(read({}).fakeAllowCredentials).toEqual([]);
  });
});

describe('the reading holds what the form writes', () => {
  const CHOICES = { storedCredentials: STORED, choices: ['all', 'empty', 'aa01', 'bb02', '0304'] };
  const every = [];
  for (const userVerification of ['preferred', 'required']) {
    for (const allowCredentials of ['all', 'empty', 'aa01', 'bb02', '0304']) {
      for (const hints of [[], ['client-device'], ['security-key', 'hybrid'], ['security-key']]) {
        for (const [largeBlob, largeBlobWrite] of [['', ''], ['', 'beef'], ['read', ''], ['read', 'beef'], ['write', 'beef'], ['write', '']]) {
          for (const [prfFirst, prfSecond] of [['', ''], ['11', ''], ['11', '22']]) {
            for (const fakes of [[], ['ffee']]) {
              every.push({ settings: settings({ userVerification, allowCredentials, hints, largeBlob, largeBlobWrite, prfFirst, prfSecond, timeout: '1234' }), fakes });
            }
          }
        }
      }
    }
  }

  it(`reads every setting back from the request it builds (${every.length} settings)`, () => {
    for (const { settings: current, fakes } of every) {
      const built = buildRequestOptions(current, { ...CONTEXT, fakeAllowCredentials: fakes }).publicKey;
      const read = readRequestOptions(JSON.parse(JSON.stringify(built)), current, CHOICES);
      expect(read.settings).toEqual(current);
      expect(read.fakeAllowCredentials).toEqual(fakes);
    }
  });

  it('builds again what it built, from any settings', () => {
    const odd = settings({ timeout: '', userVerification: '', prfSecond: '22', allowCredentials: 'gone', hints: ['unknown'] });
    const built = buildRequestOptions(odd, CONTEXT).publicKey;
    const read = readRequestOptions(JSON.parse(JSON.stringify(built)), odd, CHOICES);
    expect(buildRequestOptions(read.settings, { ...CONTEXT, fakeAllowCredentials: read.fakeAllowCredentials }).publicKey).toEqual(built);
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
