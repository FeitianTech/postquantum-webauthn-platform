// How the JSON editor merges the form's request into the one being edited, and prunes the members a request does not define (advanced/json-editor/merge-prune.js).
import { describe, expect, it } from 'vitest';

import {
  mergeKnownProperties,
  mergePublicKey,
  pruneUnsupportedProperties,
} from '../../../../frontend/static/scripts/advanced/json-editor/merge-prune.js';
import { KNOWN_RP_KEYS, KNOWN_USER_KEYS } from '../../../../frontend/static/scripts/advanced/json-editor/schema.js';

function registration() {
  return {
    rp: { name: 'FIDO2/WebAuthn PQC Developer Tools', id: 'localhost' },
    user: { id: { $hex: 'abcd' }, name: 'alice', displayName: 'alice' },
    challenge: { $hex: '00112233445566778899aabbccddeeff' },
    pubKeyCredParams: [
      { type: 'public-key', alg: -48 },
      { type: 'public-key', alg: -7 },
    ],
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
  };
}

function authentication() {
  return {
    challenge: { $hex: '00112233445566778899aabbccddeeff' },
    timeout: 90000,
    rpId: 'localhost',
    allowCredentials: [{ type: 'public-key', id: { $hex: 'aa01' } }],
    userVerification: 'preferred',
  };
}

describe('mergeKnownProperties', () => {
  it('keeps the latest members, and a member the existing object alone has that the keys do not know', () => {
    expect(mergeKnownProperties(
      { name: 'Old', policyUrl: 'https://example.com/policy' },
      { name: 'New' },
      KNOWN_RP_KEYS,
    )).toEqual({ name: 'New', policyUrl: 'https://example.com/policy' });
  });

  it('lets the latest value of a member win over the existing one', () => {
    expect(mergeKnownProperties({ policyUrl: 'old' }, { policyUrl: 'new' }, KNOWN_RP_KEYS)).toEqual({ policyUrl: 'new' });
  });

  it('does not bring back a known member the latest object left out', () => {
    expect(mergeKnownProperties({ name: 'Old', id: 'example.com' }, { name: 'New' }, KNOWN_RP_KEYS)).toEqual({ name: 'New' });
  });

  it('does not bring back a member that looks like a variant of a known one', () => {
    expect(mergeKnownProperties({ displayNameOld: 'Bob' }, { name: 'alice' }, KNOWN_USER_KEYS)).toEqual({ name: 'alice' });
  });

  it('gives a copy of the latest object when there is no existing object', () => {
    const latest = { name: 'New' };
    const merged = mergeKnownProperties(undefined, latest, KNOWN_RP_KEYS);
    expect(merged).toEqual({ name: 'New' });
    expect(merged).not.toBe(latest);
    expect(mergeKnownProperties(['policyUrl'], latest, KNOWN_RP_KEYS)).toEqual({ name: 'New' });
  });

  it('starts from an empty object when the latest value is not an object', () => {
    expect(mergeKnownProperties({ policyUrl: 'kept' }, null, KNOWN_RP_KEYS)).toEqual({ policyUrl: 'kept' });
    expect(mergeKnownProperties(null, 'New', KNOWN_RP_KEYS)).toEqual({});
  });

  it('brings back every existing member when the known keys are not a set', () => {
    expect(mergeKnownProperties({ name: 'Old', policyUrl: 'kept' }, {}, ['name'])).toEqual({ name: 'Old', policyUrl: 'kept' });
  });
});

describe('mergePublicKey', () => {
  it('copies the existing request when the latest is not an object', () => {
    const existing = registration();
    const merged = mergePublicKey(existing, null, 'registration');
    expect(merged).toEqual(registration());
    expect(merged).not.toBe(existing);
  });

  it('is empty when neither request is an object', () => {
    expect(mergePublicKey(null, undefined, 'registration')).toEqual({});
  });

  it('treats an existing request that is not an object as empty', () => {
    expect(mergePublicKey('edited', registration(), 'registration')).toEqual(registration());
  });

  it('keeps the latest request, and a member only the existing one has that a request does not define', () => {
    const latest = { ...registration(), attestation: 'none' };
    expect(mergePublicKey({ ...registration(), customFlag: true }, latest, 'registration')).toEqual({
      ...latest,
      customFlag: true,
    });
  });

  it('does not bring back a member the latest request left out', () => {
    const latest = registration();
    delete latest.attestation;
    expect(mergePublicKey(registration(), latest, 'registration')).not.toHaveProperty('attestation');
  });

  it('does not bring back a member that looks like a variant of a known one', () => {
    expect(mergePublicKey({ ...registration(), timeoutMs: 5000 }, registration(), 'registration')).toEqual(registration());
  });

  it('keeps an unknown member of the relying party, the user and the authenticator selection in a registration', () => {
    const existing = registration();
    existing.rp.policyUrl = 'https://example.com/policy';
    existing.user.avatarUrl = 'https://example.com/alice.png';
    existing.authenticatorSelection.customPreference = 'kept';
    const merged = mergePublicKey(existing, registration(), 'registration');
    expect(merged.rp).toEqual({ ...registration().rp, policyUrl: 'https://example.com/policy' });
    expect(merged.user).toEqual({ ...registration().user, avatarUrl: 'https://example.com/alice.png' });
    expect(merged.authenticatorSelection).toEqual({ ...registration().authenticatorSelection, customPreference: 'kept' });
  });

  it('does not bring back the relying party, the user or the selection the latest registration left out', () => {
    const { challenge } = registration();
    expect(mergePublicKey(registration(), { challenge }, 'registration')).toEqual({ challenge });
  });

  it('merges no member of the user in an authentication request', () => {
    const merged = mergePublicKey(
      { ...authentication(), user: { name: 'bob', avatarUrl: 'https://example.com/bob.png' } },
      { ...authentication(), user: { name: 'alice' } },
      'authentication',
    );
    expect(merged.user).toEqual({ name: 'alice' });
  });

  it('merges a registration\'s extensions, largeBlob, prf and prf.eval by the registration members', () => {
    const existing = registration();
    existing.extensions = {
      credProps: true,
      devicePubKey: {},
      largeBlob: { support: 'required', read: true },
      prf: { eval: { first: { $hex: '01' }, third: { $hex: '03' } }, evalByCredential: {} },
    };
    const latest = registration();
    latest.extensions = {
      credProps: false,
      largeBlob: { support: 'preferred' },
      prf: { eval: { first: { $hex: '02' } } },
    };
    expect(mergePublicKey(existing, latest, 'registration').extensions).toEqual({
      credProps: false,
      devicePubKey: {},
      largeBlob: { support: 'preferred', read: true },
      prf: { eval: { first: { $hex: '02' }, third: { $hex: '03' } }, evalByCredential: {} },
    });
  });

  it('merges an authentication\'s extensions and largeBlob by the authentication members', () => {
    const existing = { ...authentication(), extensions: { credProps: true, largeBlob: { read: true, support: 'required' } } };
    const latest = { ...authentication(), extensions: { largeBlob: { write: { $hex: '0102' } } } };
    expect(mergePublicKey(existing, latest, 'authentication').extensions).toEqual({
      credProps: true,
      largeBlob: { write: { $hex: '0102' }, support: 'required' },
    });
  });

  it('takes the latest extensions as they are when the existing request has none', () => {
    const existing = registration();
    delete existing.extensions;
    const latest = registration();
    latest.extensions = { largeBlob: { support: 'required' }, prf: { eval: { first: { $hex: '01' } } } };
    expect(mergePublicKey(existing, latest, 'registration').extensions).toEqual(latest.extensions);
  });

  it('takes the latest prf as it is when the existing extensions have none', () => {
    const latest = registration();
    latest.extensions = { prf: { eval: { first: { $hex: '01' } } } };
    expect(mergePublicKey(registration(), latest, 'registration').extensions).toEqual({ prf: { eval: { first: { $hex: '01' } } } });
  });

  it('does not bring back an eval the latest prf left out', () => {
    const existing = registration();
    existing.extensions = { prf: { eval: { first: { $hex: '01' } }, evalByCredential: {} } };
    const latest = registration();
    latest.extensions = { prf: {} };
    expect(mergePublicKey(existing, latest, 'registration').extensions).toEqual({ prf: { evalByCredential: {} } });
  });

  it('turns extensions that are not an object into an object holding the existing unknown ones', () => {
    const existing = registration();
    existing.extensions = { devicePubKey: {} };
    const latest = registration();
    latest.extensions = ['credProps'];
    expect(mergePublicKey(existing, latest, 'registration').extensions).toEqual({ devicePubKey: {} });
  });

  it('keeps an empty allow list the latest authentication request left out', () => {
    const { challenge } = authentication();
    expect(mergePublicKey({ challenge, allowCredentials: [] }, { challenge }, 'authentication')).toEqual({
      challenge,
      allowCredentials: [],
    });
  });

  it('empties an allow list that is not an array when the existing one was empty', () => {
    const { challenge } = authentication();
    expect(mergePublicKey({ challenge, allowCredentials: [] }, { challenge, allowCredentials: 'none' }, 'authentication'))
      .toEqual({ challenge, allowCredentials: [] });
  });

  it('keeps the latest allow list when it is an array', () => {
    const latest = authentication();
    expect(mergePublicKey({ ...authentication(), allowCredentials: [] }, latest, 'authentication').allowCredentials)
      .toEqual(authentication().allowCredentials);
  });

  it('does not bring back an allow list that was not empty, or not an array', () => {
    const { challenge } = authentication();
    expect(mergePublicKey(authentication(), { challenge }, 'authentication')).toEqual({ challenge });
    expect(mergePublicKey({ challenge, allowCredentials: 'none' }, { challenge }, 'authentication')).toEqual({ challenge });
  });
});

describe('pruneUnsupportedProperties', () => {
  it('does nothing to a value that is not an object', () => {
    expect(() => pruneUnsupportedProperties(null, 'registration')).not.toThrow();
    const list = ['customFlag'];
    pruneUnsupportedProperties(list, 'registration');
    expect(list).toEqual(['customFlag']);
  });

  it('leaves a valid registration request as it is', () => {
    const publicKey = registration();
    pruneUnsupportedProperties(publicKey, 'registration');
    expect(publicKey).toEqual(registration());
  });

  it('removes the members a registration request does not define, at every level', () => {
    const publicKey = registration();
    publicKey.customFlag = true;
    publicKey.rp.icon = 'https://example.com/icon.png';
    publicKey.user.icon = 'https://example.com/alice.png';
    publicKey.authenticatorSelection.hints = ['hybrid'];
    publicKey.extensions = {
      credProps: true,
      appidExclude: 'https://example.com',
      largeBlob: { support: 'required', read: true },
      prf: { eval: { first: { $hex: '01' }, third: { $hex: '03' } }, evalByCredential: {} },
    };
    pruneUnsupportedProperties(publicKey, 'registration');
    expect(publicKey).toEqual({
      ...registration(),
      extensions: { credProps: true, largeBlob: { support: 'required' }, prf: { eval: { first: { $hex: '01' } } } },
    });
  });

  it('removes the members an authentication request does not define, by the authentication members', () => {
    const publicKey = {
      ...authentication(),
      rp: { name: 'Example' },
      extensions: { credProps: true, largeBlob: { read: true, support: 'required' } },
    };
    pruneUnsupportedProperties(publicKey, 'authentication');
    expect(publicKey).toEqual({ ...authentication(), extensions: { largeBlob: { read: true } } });
  });

  it('removes every unsupported member one error names', () => {
    const publicKey = { ...registration(), mediation: 'conditional', signal: {} };
    pruneUnsupportedProperties(publicKey, 'registration');
    expect(publicKey).toEqual(registration());
  });

  it('prunes by the registration members when no scope is given', () => {
    const publicKey = { ...registration(), rpId: 'localhost' };
    pruneUnsupportedProperties(publicKey);
    expect(publicKey).toEqual(registration());
  });

  it('rethrows an error that is not about unsupported members', () => {
    const publicKey = registration();
    delete publicKey.challenge;
    expect(() => pruneUnsupportedProperties(publicKey, 'registration')).toThrow('publicKey.challenge is required.');
  });

  it('keeps the removals made before an error it rethrows', () => {
    const publicKey = { ...registration(), customFlag: true, attestation: 'full' };
    expect(() => pruneUnsupportedProperties(publicKey, 'registration')).toThrow(
      'publicKey.attestation must be none, indirect, direct, or enterprise.',
    );
    expect(publicKey).not.toHaveProperty('customFlag');
  });

  it('rethrows when the unsupported member\'s name is only spaces, leaving it in place', () => {
    const publicKey = { ...registration(), ' ': 1 };
    expect(() => pruneUnsupportedProperties(publicKey, 'registration')).toThrow(
      new Error('publicKey contains unsupported properties:  '),
    );
    expect(publicKey).toHaveProperty([' '], 1);
  });

  it('gives up after ten attempts when an unsupported member\'s name holds a comma, leaving it in place', () => {
    const publicKey = { ...registration(), 'a,b': 1 };
    expect(pruneUnsupportedProperties(publicKey, 'registration')).toBeUndefined();
    expect(publicKey).toEqual({ ...registration(), 'a,b': 1 });
  });
});
