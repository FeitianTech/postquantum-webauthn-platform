import { afterEach, describe, expect, it } from 'vitest';

import {
  buildCreationOptions,
  changeRegistration,
  decodeJsonBinaryToHex,
  readCreationOptions,
  registrationControls,
  registrationDefaults,
} from './registration-request.js';

// A registration's request and the form's settings it is built from, with no
// page (advanced/json-editor/registration-request.js).

const CONTEXT = { rpName: 'FIDO2/WebAuthn PQC Developer Tools', hostname: 'localhost' };
const ALICE = 'abcd';
const CHALLENGE = '00112233445566778899aabbccddeeff';

/** The defaults with the values the form draws at random. */
function settings(extra = {}) {
  return { ...registrationDefaults(), userId: ALICE, userName: 'alice', displayName: 'alice', challenge: CHALLENGE, ...extra };
}

const build = (extra = {}, context = CONTEXT) => buildCreationOptions(settings(extra), context).publicKey;

afterEach(() => {
  delete window.__binaryFormat;
});

describe('the defaults', () => {
  it('are the form\'s, without the values drawn at random', () => {
    expect(registrationDefaults()).toEqual({
      timeout: '90000',
      attachment: 'cross-platform',
      residentKey: 'discouraged',
      userVerification: 'preferred',
      attestation: 'direct',
      excludeCredentials: true,
      fakeCredLength: '128',
      algorithms: [-48, -49, -50, -8, -7, -257],
      hints: [],
      credProps: true,
      minPinLength: false,
      credProtect: '',
      enforceCredProtect: true,
      largeBlob: '',
      prf: false,
      prfFirst: '',
      prfSecond: '',
    });
  });

  it('are a new copy each time', () => {
    registrationDefaults().algorithms.push(-7);
    expect(registrationDefaults().algorithms).toHaveLength(6);
  });
});

describe('the request the settings build', () => {
  it('holds the relying party, the user, the challenge, the algorithms most preferred first, and the selection', () => {
    expect(build()).toEqual({
      rp: { name: 'FIDO2/WebAuthn PQC Developer Tools', id: 'localhost' },
      user: { id: { $hex: ALICE }, name: 'alice', displayName: 'alice' },
      challenge: { $hex: CHALLENGE },
      pubKeyCredParams: [-48, -49, -50, -8, -7, -257].map((alg) => ({ type: 'public-key', alg })),
      timeout: 90000,
      authenticatorSelection: {
        authenticatorAttachment: 'cross-platform',
        residentKey: 'discouraged',
        requireResidentKey: false,
        userVerification: 'preferred',
      },
      attestation: 'direct',
      excludeCredentials: [],
      extensions: { credProps: true },
    });
  });

  it('lists the algorithms in the table\'s order, whatever the order chosen', () => {
    expect(build({ algorithms: [-7, 999, -49] }).pubKeyCredParams).toEqual([
      { type: 'public-key', alg: -49 },
      { type: 'public-key', alg: -7 },
    ]);
  });

  it('leaves the attachment out for Unspecified, and requires a resident key only when it is Required', () => {
    const selection = build({ attachment: 'unspecified', residentKey: 'required', userVerification: 'required' }).authenticatorSelection;
    expect(selection).toEqual({ residentKey: 'required', requireResidentKey: true, userVerification: 'required' });
  });

  it('reads empty settings as the defaults the request needs', () => {
    const publicKey = build({ timeout: 'soon', attestation: '', attachment: '', residentKey: '', userVerification: '' });
    expect([publicKey.timeout, publicKey.attestation]).toEqual([90000, 'direct']);
    expect(publicKey.authenticatorSelection).toEqual({
      authenticatorAttachment: 'cross-platform',
      residentKey: 'discouraged',
      requireResidentKey: false,
    });
  });

  it('gives no bytes for an empty user ID or challenge', () => {
    const publicKey = build({ userId: '', challenge: '' });
    expect([publicKey.user.id, publicKey.challenge]).toEqual(['', '']);
  });

  it('asks for each extension that is set, and the prf evaluations only with a first one', () => {
    expect(build({
      credProps: false,
      minPinLength: true,
      credProtect: 'userVerificationRequired',
      largeBlob: 'preferred',
      prf: true,
      prfFirst: 'aa',
      prfSecond: 'bb',
    }).extensions).toEqual({
      minPinLength: true,
      credentialProtectionPolicy: 'userVerificationRequired',
      enforceCredentialProtectionPolicy: true,
      largeBlob: { support: 'preferred' },
      prf: { eval: { first: { $hex: 'aa' }, second: { $hex: 'bb' } } },
    });
    expect(build({ credProtect: 'userVerificationOptional', enforceCredProtect: false, prf: true, prfFirst: 'aa' }).extensions).toEqual({
      credProps: true,
      credentialProtectionPolicy: 'userVerificationOptional',
      prf: { eval: { first: { $hex: 'aa' } } },
    });
    expect(build({ prf: true, prfFirst: '' }).extensions).toEqual({ credProps: true });
    expect(build({ prf: false, prfFirst: 'aa' }).extensions).toEqual({ credProps: true });
  });

  it('gives the hints as chosen, and none when none is', () => {
    expect(build({ hints: ['hybrid', 'client-device'] }).hints).toEqual(['hybrid', 'client-device']);
    expect(build()).not.toHaveProperty('hints');
  });
});

describe('the credentials a registration excludes', () => {
  const ownCredential = { credentialIdHex: 'aa11', userHandleHex: ALICE };
  const context = { ...CONTEXT, storedCredentials: [ownCredential, { credentialIdHex: 'bb22', userHandleHex: 'ef01' }, { userHandleHex: ALICE }, {}] };

  it('are this user\'s saved credentials, then the fake IDs', () => {
    expect(build({}, { ...context, fakeExcludeCredentials: ['cafe', ''] }).excludeCredentials).toEqual([
      { type: 'public-key', id: { $hex: 'aa11' } },
      { type: 'public-key', id: { $hex: 'cafe' } },
    ]);
  });

  it('match the user by the User ID in any case', () => {
    expect(build({ userId: 'ABCD' }, context).excludeCredentials).toEqual([{ type: 'public-key', id: { $hex: 'aa11' } }]);
  });

  it('are none when excluding is off, or without a User ID or saved credentials', () => {
    expect(build({ excludeCredentials: false }, { ...context, fakeExcludeCredentials: ['cafe'] }).excludeCredentials).toEqual([]);
    expect(build({ userId: '' }, context).excludeCredentials).toEqual([]);
    expect(build({}, { ...CONTEXT, storedCredentials: null }).excludeCredentials).toEqual([]);
    expect(buildCreationOptions(settings()).publicKey.excludeCredentials).toEqual([]);
  });

  it('write the fake IDs in the page\'s byte spelling, keeping as hex one that does not convert', () => {
    window.__binaryFormat = 'b64';
    const excluded = build({}, { ...CONTEXT, fakeExcludeCredentials: ['cafe', 'a'] }).excludeCredentials;
    expect(excluded).toEqual([
      { type: 'public-key', id: { $base64: 'yv4=' } },
      { type: 'public-key', id: { $hex: 'a' } },
    ]);
  });
});

describe('a byte value the request holds', () => {
  it('is read as hex from each of its spellings', () => {
    expect(decodeJsonBinaryToHex({ $hex: 'cafe' })).toBe('cafe');
    expect(decodeJsonBinaryToHex({ $base64url: 'yv4' })).toBe('cafe');
    expect(decodeJsonBinaryToHex({ $base64: 'yv4=' })).toBe('cafe');
    expect(decodeJsonBinaryToHex('yv4')).toBe('cafe');
  });

  it('is nothing when missing or spelled no way it knows', () => {
    expect([decodeJsonBinaryToHex(undefined), decodeJsonBinaryToHex({ $js: '[1]' })]).toEqual(['', '']);
  });
});

describe('the settings a request says', () => {
  const previous = settings({ userId: 'ffff', userName: 'bob', displayName: 'Bob', timeout: '5000', attestation: 'none', prfFirst: '11', prfSecond: '22' });
  const read = (publicKey, context = {}) => readCreationOptions(publicKey, previous, context);

  it('take the user, the challenge, the timeout and the attestation it gives', () => {
    const { settings: read1 } = read({
      user: { id: { $hex: ALICE }, name: 'alice', displayName: 'Alice' },
      challenge: { $base64url: 'ABEiM0RVZneImaq7zN3u_w' },
      timeout: 1234,
      attestation: 'enterprise',
    });
    expect(read1).toMatchObject({ userId: ALICE, userName: 'alice', displayName: 'Alice', challenge: CHALLENGE, timeout: '1234', attestation: 'enterprise' });
  });

  it('keep what it leaves out, or gives as nothing', () => {
    const { settings: kept } = read({ user: { id: {}, name: '' }, challenge: {} });
    expect(kept).toMatchObject({ userId: 'ffff', userName: 'bob', displayName: 'Bob', challenge: CHALLENGE, timeout: '5000', attestation: 'none' });
    // A timeout of 0 is a timeout the request gives.
    expect(read({ timeout: 0 }).settings.timeout).toBe('0');
    expect(read({}).settings.algorithms).toEqual(previous.algorithms);
  });

  it('read an empty attestation as Direct', () => {
    expect(read({ attestation: '' }).settings.attestation).toBe('direct');
  });

  it('take the algorithms it lists that the form offers, in the table\'s order', () => {
    const params = [{ alg: -7 }, { alg: '-48' }, { alg: 99 }, { type: 'public-key' }, null];
    expect(read({ pubKeyCredParams: params }).settings.algorithms).toEqual([-48, -7]);
  });

  it('take the selection, a required resident key from either field', () => {
    expect(read({ authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'preferred', userVerification: 'required' } }).settings)
      .toMatchObject({ attachment: 'platform', residentKey: 'preferred', userVerification: 'required' });
    expect(read({ authenticatorSelection: { authenticatorAttachment: 'unspecified', residentKey: 'discouraged', requireResidentKey: true } }).settings)
      .toMatchObject({ attachment: 'unspecified', residentKey: 'required', userVerification: 'preferred' });
    expect(read({ authenticatorSelection: { userVerification: '' } }).settings).toMatchObject({ residentKey: 'discouraged', userVerification: 'preferred' });
  });

  it('read an attachment it does not name as Cross-Platform', () => {
    expect(read({ authenticatorSelection: { authenticatorAttachment: 'other' } }).settings.attachment).toBe('cross-platform');
  });

  it('exclude credentials when the list has any, and give the IDs no saved credential has as the fake ones', () => {
    const context = { storedCredentials: [{ credentialIdHex: 'AA11' }, { credentialId: 'uyI' }, {}] };
    const excludeCredentials = [{ id: { $hex: 'aa11' } }, { id: { $hex: 'bb22' } }, { id: { $hex: 'CAFE' } }, { id: {} }, 'text'];
    expect(read({ excludeCredentials }, context)).toMatchObject({ settings: { excludeCredentials: true }, fakeExcludeCredentials: ['CAFE'] });
    expect(read({ excludeCredentials: [] }, { storedCredentials: null })).toMatchObject({
      settings: { excludeCredentials: true },
      fakeExcludeCredentials: [],
    });
  });

  it('stop excluding credentials when the request has no list', () => {
    expect(read({}).settings.excludeCredentials).toBe(false);
  });

  it('take the extensions it gives, and the prf evaluations it has', () => {
    const extensions = {
      credProps: false,
      minPinLength: true,
      credentialProtectionPolicy: 'userVerificationOptional',
      enforceCredentialProtectionPolicy: false,
      prf: { eval: { first: { $hex: 'aa' }, second: { $hex: 'bb' } } },
    };
    expect(read({ extensions }).settings).toMatchObject({
      credProps: false,
      minPinLength: true,
      credProtect: 'userVerificationOptional',
      enforceCredProtect: false,
      prfFirst: 'aa',
      prfSecond: 'bb',
    });
    expect(read({ extensions: { prf: { eval: {} } } }).settings).toMatchObject({ credProtect: '', enforceCredProtect: true, prfFirst: '11', prfSecond: '22' });
    expect(read({ extensions: { prf: {} } }).settings).toMatchObject({ prfFirst: '11', prfSecond: '22' });
  });

  it('clear the extensions when it has none', () => {
    const from = settings({ credProps: true, minPinLength: true, credProtect: 'userVerificationRequired', enforceCredProtect: false });
    expect(readCreationOptions({}, from).settings).toMatchObject({ credProps: false, minPinLength: false, credProtect: '', enforceCredProtect: true });
  });

  it('take its hints as they are, and none when it has none', () => {
    expect(read({ hints: ['hybrid'] }).settings.hints).toEqual(['hybrid']);
    expect(read({ hints: 'hybrid' }).settings.hints).toEqual([]);
  });

  it('leave the settings it was given as they were', () => {
    const before = JSON.stringify(previous);
    read({ user: { name: 'carol' }, hints: ['hybrid'] });
    expect(JSON.stringify(previous)).toBe(before);
  });
});

describe('one setting\'s change', () => {
  it('copies the user name into the display name', () => {
    expect(changeRegistration(settings(), 'userName', 'carol')).toMatchObject({ userName: 'carol', displayName: 'carol' });
  });

  it('enforces credProtect again when it goes back to Unspecified', () => {
    const enforced = changeRegistration(settings({ credProtect: 'userVerificationRequired', enforceCredProtect: false }), 'credProtect', '');
    expect(enforced.enforceCredProtect).toBe(true);
    expect(changeRegistration(settings({ enforceCredProtect: false }), 'credProtect', 'userVerificationOptional').enforceCredProtect).toBe(false);
  });

  it('asks for no largeBlob once a resident key is no longer required', () => {
    expect(changeRegistration(settings({ residentKey: 'required', largeBlob: 'required' }), 'residentKey', 'preferred').largeBlob).toBe('');
    expect(changeRegistration(settings({ largeBlob: 'preferred' }), 'residentKey', 'required').largeBlob).toBe('preferred');
    expect(changeRegistration(settings({ largeBlob: '' }), 'residentKey', 'discouraged').largeBlob).toBe('');
  });

  it('empties the second prf evaluation with the first', () => {
    expect(changeRegistration(settings({ prfFirst: 'aa', prfSecond: 'bb' }), 'prfFirst', '').prfSecond).toBe('');
    expect(changeRegistration(settings({ prfFirst: 'aa', prfSecond: 'bb' }), 'prfFirst', 'cc').prfSecond).toBe('bb');
  });

  it('changes that setting alone otherwise', () => {
    expect(changeRegistration(settings(), 'attestation', 'none')).toEqual(settings({ attestation: 'none' }));
  });
});

describe('the fields the form cannot change', () => {
  it('are Enforce credProtect without a policy, and the second prf evaluation without a first', () => {
    expect(registrationControls(settings())).toEqual({ enforceCredProtect: true, prfSecond: true });
    expect(registrationControls(settings({ credProtect: 'userVerificationRequired', prfFirst: 'aa' }))).toEqual({
      enforceCredProtect: false,
      prfSecond: false,
    });
  });
});

describe('a request read back into the form', () => {
  // Each setting the form holds, varied on its own and in a few combinations.
  const variations = [
    {},
    { attachment: 'platform' },
    { attachment: 'unspecified' },
    { residentKey: 'required', userVerification: 'discouraged', attestation: 'none' },
    { residentKey: 'preferred', userVerification: 'required', attestation: 'enterprise' },
    { excludeCredentials: false },
    { algorithms: [-7] },
    { algorithms: [-49, -8, -39] },
    { hints: ['hybrid'] },
    { hints: ['client-device', 'security-key'] },
    { credProps: false, minPinLength: true },
    { credProtect: 'userVerificationRequired', enforceCredProtect: false },
    { credProtect: 'userVerificationOptionalWithCredentialIDList' },
    { largeBlob: 'preferred' },
    { largeBlob: 'required', residentKey: 'required' },
    { prf: true, prfFirst: 'aa'.repeat(32) },
    { prf: true, prfFirst: 'aa'.repeat(32), prfSecond: 'bb'.repeat(32) },
    { prf: true },
    { prf: false, prfFirst: 'aa'.repeat(32), prfSecond: 'bb'.repeat(32) },
    { attachment: 'unspecified', largeBlob: 'required', prf: true, prfFirst: 'cc'.repeat(32), hints: ['hybrid'], excludeCredentials: false },
  ];
  const fakes = ['cafe'];

  it('builds the same request again, whatever the form held before', () => {
    for (const variation of variations) {
      for (const before of [settings(variation), settings({ prf: true, prfFirst: 'dd'.repeat(32), prfSecond: 'ee'.repeat(32), largeBlob: 'preferred', attachment: 'platform' }), settings({ excludeCredentials: false })]) {
        const request = buildCreationOptions(settings(variation), { ...CONTEXT, fakeExcludeCredentials: fakes });
        const read = readCreationOptions(request.publicKey, before, {});
        const again = buildCreationOptions(read.settings, { ...CONTEXT, fakeExcludeCredentials: read.fakeExcludeCredentials });
        expect(again, JSON.stringify(variation)).toEqual(request);
      }
    }
  });

  it('keeps the prf switch on while its first evaluation is still empty', () => {
    const { settings: read } = readCreationOptions(build({ prf: true }), settings({ prf: true }));
    expect(read.prf).toBe(true);
  });

  it('keeps excluding credentials when the request excludes none, as the form cannot tell', () => {
    expect(readCreationOptions(build({ excludeCredentials: true }), settings()).settings.excludeCredentials).toBe(true);
    expect(readCreationOptions(build({ excludeCredentials: false }), settings({ excludeCredentials: false })).settings.excludeCredentials).toBe(false);
  });

  it('reads no attachment as Unspecified', () => {
    expect(readCreationOptions({ authenticatorSelection: { residentKey: 'preferred' } }, settings()).settings.attachment).toBe('unspecified');
    expect(readCreationOptions({}, settings()).settings.attachment).toBe('unspecified');
  });
});
