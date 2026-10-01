import { describe, expect, it } from 'vitest';

import {
  authenticationDefaults,
  buildRequestOptions,
} from '../authentication/request.js';
import { requestText } from './model.js';
import {
  buildCreationOptions,
  changeRegistration,
  registrationDefaults,
  requestTimeout,
} from '../registration/request.js';
import { followForm, patchRequest } from './request-patch.js';

// A form change applied to the request the editor holds, with no page
// (advanced/editor/request-patch.js): the fields 29A's report found
// dropped by the next form change, typed, then followed by one.

const CHALLENGE = '00112233445566778899aabbccddeeff';
const MINE = { type: 'advanced', credentialIdHex: 'aa01', userHandleHex: 'abcd', authenticatorAttachment: 'cross-platform' };
const THEIRS = { type: 'advanced', credentialIdHex: 'bb02', userHandleHex: 'ffff', authenticatorAttachment: 'platform' };
const STORED = [MINE, THEIRS];

const REGISTRATION = { rpName: 'FIDO2/WebAuthn PQC Developer Tools', hostname: 'localhost', storedCredentials: STORED, fakeExcludeCredentials: [] };
const registration = (extra = {}) => ({ ...registrationDefaults(), userId: 'abcd', userName: 'alice', displayName: 'alice', challenge: CHALLENGE, ...extra });
const registrationRequest = (settings) => buildCreationOptions(settings, REGISTRATION);

const AUTHENTICATION = { hostname: 'localhost', storedCredentials: STORED, fakeAllowCredentials: [] };
const authentication = (extra = {}) => ({ ...authenticationDefaults(), challenge: CHALLENGE, ...extra });
const authenticationRequest = (settings) => buildRequestOptions(settings, AUTHENTICATION);

const clone = (value) => JSON.parse(JSON.stringify(value));

/**
 * The editor's request after an edit (`typed`, given the form's request) and
 * then a form change from `settings` to `next`.
 */
function follow(build, settings, next, typed) {
  const before = build(settings);
  const edited = typed(clone(before));
  return JSON.parse(followForm(requestText(edited), before, build(next)));
}

describe('a form change on a registration', () => {
  const credPropsOff = (typed) => follow(registrationRequest, registration(), registration({ credProps: false }), typed);

  it('keeps a typed rp.id', () => {
    const publicKey = credPropsOff((request) => ({ ...request, publicKey: { ...request.publicKey, rp: { ...request.publicKey.rp, id: 'example.com' } } })).publicKey;
    expect(publicKey.rp).toEqual({ name: 'FIDO2/WebAuthn PQC Developer Tools', id: 'example.com' });
    expect(publicKey.extensions).not.toHaveProperty('credProps');
  });

  it('keeps the transports typed on an excluded credential, and another user\'s credential typed there', () => {
    const publicKey = credPropsOff((request) => {
      request.publicKey.excludeCredentials[0].transports = ['usb', 'nfc'];
      request.publicKey.excludeCredentials.push({ type: 'public-key', id: { $hex: 'bb02' } });
      return request;
    }).publicKey;
    expect(publicKey.excludeCredentials).toEqual([
      { type: 'public-key', id: { $hex: 'aa01' }, transports: ['usb', 'nfc'] },
      { type: 'public-key', id: { $hex: 'bb02' } },
    ]);
  });

  it('keeps the order typed of the hints and of the algorithms', () => {
    const publicKey = follow(
      registrationRequest,
      registration({ hints: ['client-device', 'security-key'] }),
      registration({ hints: ['client-device', 'security-key'], credProps: false }),
      (request) => {
        request.publicKey.hints.reverse();
        request.publicKey.pubKeyCredParams.reverse();
        return request;
      },
    ).publicKey;
    expect(publicKey.hints).toEqual(['security-key', 'client-device']);
    expect(publicKey.pubKeyCredParams.map((param) => param.alg)).toEqual([-257, -7, -8, -50, -49, -48]);
  });

  it('keeps a typed timeout of 0, which the form reads and builds as 0 too', () => {
    expect(credPropsOff((request) => ({ ...request, publicKey: { ...request.publicKey, timeout: 0 } })).publicKey.timeout).toBe(0);
    expect(registrationRequest(registration({ timeout: '0' })).publicKey.timeout).toBe(0);
    expect([requestTimeout('0'), requestTimeout(''), requestTimeout('soon'), requestTimeout('1234')]).toEqual([0, 90000, 90000, 1234]);
  });

  it('writes what it changes over the typed request: a chosen algorithm where the form puts it, a random challenge whole', () => {
    const settings = registration();
    const publicKey = follow(
      registrationRequest,
      settings,
      changeRegistration(settings, 'algorithms', [...settings.algorithms, -35]),
      (request) => {
        request.publicKey.pubKeyCredParams.reverse();
        request.publicKey.challenge = { $base64url: 'ABEiM0RVZneImaq7zN3u_w' };
        return request;
      },
    ).publicKey;
    // ES384 (-35) follows RS256 (-257), which the form lists just before it; the rest keeps its typed order.
    expect(publicKey.pubKeyCredParams.map((param) => param.alg)).toEqual([-257, -35, -7, -8, -50, -49, -48]);
    expect(publicKey.challenge).toEqual({ $base64url: 'ABEiM0RVZneImaq7zN3u_w' });

    const redrawn = follow(registrationRequest, settings, registration({ challenge: 'ffff' }), (request) => {
      request.publicKey.challenge = { $base64url: 'ABEiM0RVZneImaq7zN3u_w' };
      return request;
    }).publicKey;
    expect(redrawn.challenge).toEqual({ $hex: 'ffff' });
  });

  it('drops what the form drops, and keeps the keys beside publicKey', () => {
    const request = follow(registrationRequest, registration({ hints: ['hybrid', 'security-key'] }), registration({ hints: ['security-key'] }), (typed) => ({
      ...typed,
      mediation: 'conditional',
      publicKey: { ...typed.publicKey, hints: ['security-key', 'hybrid'] },
    }));
    expect(request.mediation).toBe('conditional');
    expect(request.publicKey.hints).toEqual(['security-key']);
  });
});

describe('a form change on an authentication', () => {
  const uvRequired = (typed) => follow(authenticationRequest, authentication(), authentication({ userVerification: 'required' }), typed);

  it('keeps a typed rpId, the transports typed on a credential, and an ID no saved credential has', () => {
    const publicKey = uvRequired((request) => {
      request.publicKey.rpId = 'example.com';
      request.publicKey.allowCredentials[1].transports = ['internal'];
      request.publicKey.allowCredentials.push({ type: 'public-key', id: { $hex: 'ffee' } });
      return request;
    }).publicKey;
    expect(publicKey.rpId).toBe('example.com');
    expect(publicKey.userVerification).toBe('required');
    expect(publicKey.allowCredentials).toEqual([
      { type: 'public-key', id: { $hex: 'aa01' } },
      { type: 'public-key', id: { $hex: 'bb02' }, transports: ['internal'] },
      { type: 'public-key', id: { $hex: 'ffee' } },
    ]);
  });

  it('keeps the order typed of the hints, and a typed timeout of 0', () => {
    const publicKey = follow(
      authenticationRequest,
      authentication({ hints: ['client-device', 'hybrid'] }),
      authentication({ hints: ['client-device', 'hybrid'], userVerification: 'required' }),
      (request) => {
        request.publicKey.hints.reverse();
        request.publicKey.timeout = 0;
        return request;
      },
    ).publicKey;
    expect(publicKey.hints).toEqual(['hybrid', 'client-device']);
    expect(publicKey.timeout).toBe(0);
    expect(authenticationRequest(authentication({ timeout: '0' })).publicKey.timeout).toBe(0);
  });

  it('adds a credential the saved list gains, and leaves out allowCredentials for Empty', () => {
    const before = buildRequestOptions(authentication(), { ...AUTHENTICATION, storedCredentials: [MINE] });
    const typed = clone(before);
    typed.publicKey.allowCredentials[0].transports = ['usb'];
    const after = authenticationRequest(authentication());
    expect(JSON.parse(followForm(requestText(typed), before, after)).publicKey.allowCredentials).toEqual([
      { type: 'public-key', id: { $hex: 'aa01' }, transports: ['usb'] },
      { type: 'public-key', id: { $hex: 'bb02' } },
    ]);

    const empty = follow(authenticationRequest, authentication(), authentication({ allowCredentials: 'empty' }), (request) => request);
    expect(empty.publicKey).not.toHaveProperty('allowCredentials');
  });
});

describe('following the form', () => {
  it('gives the form\'s request exactly when nothing was typed', () => {
    const states = [
      [registration(), registration({ attachment: 'platform', hints: ['client-device'], timeout: '0' })],
      [registration({ excludeCredentials: false }), registration()],
      [registration({ prf: true, prfFirst: '11' }), registration({ prf: true, prfFirst: '11', prfSecond: '22', largeBlob: 'required' })],
    ];
    for (const [settings, next] of states) {
      const before = registrationRequest(settings);
      const after = registrationRequest(next);
      expect(followForm(requestText(before), before, after)).toBe(requestText(after));
    }
    const before = authenticationRequest(authentication());
    const after = authenticationRequest(authentication({ allowCredentials: 'bb02', largeBlob: 'read', hints: ['hybrid'] }));
    expect(followForm(requestText({ ...before, note: 1 }), before, after)).toBe(requestText({ ...after, note: 1 }));
  });

  it('rebuilds text that is not a request from the form, with the keys an edit held beside publicKey', () => {
    const request = authenticationRequest(authentication());
    for (const text of ['{ nope', '[]', '{"publicKey": 7}']) {
      expect(followForm(text, request, request, { note: 'kept' })).toBe(requestText({ note: 'kept', ...request }));
    }
    expect(followForm('{ nope', request, request)).toBe(requestText(request));
  });
});

describe('the patch', () => {
  it('keeps what the change left alone, absent included, and writes what it changed', () => {
    expect(patchRequest({ a: 1 }, { a: 2 }, { a: 2 })).toEqual({ a: 1 });
    expect(patchRequest(undefined, 1, 1)).toBeUndefined();
    expect(patchRequest({ a: 1, b: 2 }, { a: 1 }, { a: 1, c: 3 })).toEqual({ a: 1, b: 2, c: 3 });
    expect(patchRequest({ a: 5, b: 2 }, { a: 1, b: 2 }, { b: 2 })).toEqual({ b: 2 });
    expect(patchRequest({ a: { x: 1 } }, { a: { x: 2 } }, { a: { x: 3 } })).toEqual({ a: { x: 3 } });
    expect(patchRequest('typed', 'before', 'after')).toBe('after');
    expect(patchRequest({ $hex: '01' }, { $hex: '02' }, { $hex: '03' })).toEqual({ $hex: '03' });
    expect(patchRequest({}, { $hex: '02' }, { $hex: '03' })).toEqual({ $hex: '03' });
    expect(patchRequest({ $hex: '01' }, {}, { a: 1 })).toEqual({ a: 1 });
  });

  it('merges lists member by member: case, duplicates, members without an ID, a missing predecessor, several added', () => {
    const id = (hex, extra = {}) => ({ type: 'public-key', id: { $hex: hex }, ...extra });
    // IDs match in any case; a duplicate typed stays; a member with no readable ID stays where it is.
    expect(patchRequest([id('AA01', { t: 1 }), id('aa01'), { id: '!!' }, { note: 1 }], [id('aa01')], [id('aa01'), id('cc03')])).toEqual([
      id('AA01', { t: 1 }),
      id('cc03'),
      id('aa01'),
      { id: '!!' },
      { note: 1 },
    ]);
    // An added member whose predecessors are all gone goes first; several go in the form's order.
    expect(patchRequest(['x', 'b'], ['a', 'b'], ['c', 'd', 'b'])).toEqual(['c', 'd', 'x', 'b']);
    // A member the form kept stays out of a list the edit took it out of.
    expect(patchRequest(['z'], ['a'], ['a', 'c'])).toEqual(['c', 'z']);
    expect(patchRequest([{ alg: -8 }, { alg: '-7' }], [{ alg: -7 }, { alg: -8 }], [{ alg: -7 }])).toEqual([{ alg: '-7' }]);
  });

  it('takes a list whole when the form\'s members have no identity', () => {
    expect(patchRequest([3, 1], [1, 2], [1])).toEqual([1]);
    expect(patchRequest(['x'], [{ note: 1 }], [{ note: 2 }])).toEqual([{ note: 2 }]);
    expect(patchRequest('x', [1], [2])).toEqual([2]);
  });
});
