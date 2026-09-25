import { describe, expect, it } from 'vitest';

import {
  AUTHENTICATOR_FACTS,
  CLIENT_CAPABILITY_LABELS,
  STATE_TEXT,
  WEBAUTHN_FACTS,
  gatherWebAuthnFacts,
} from '../../../../frontend/static/scripts/shared/browser/webauthn-facts.js';
import { CHROMIUM_152_CAPABILITIES } from './chromium-152.js';

function makePublicKeyCredential(statics = {}, prototype = { toJSON() {} }) {
  function PublicKeyCredential() {}
  Object.defineProperties(PublicKeyCredential, Object.getOwnPropertyDescriptors(statics));
  Object.defineProperties(PublicKeyCredential.prototype, Object.getOwnPropertyDescriptors(prototype));
  return PublicKeyCredential;
}

function fullPublicKeyCredential(overrides = {}) {
  return makePublicKeyCredential({
    isUserVerifyingPlatformAuthenticatorAvailable: async () => true,
    isConditionalMediationAvailable: async () => true,
    getClientCapabilities: async () => ({ ...CHROMIUM_152_CAPABILITIES }),
    parseCreationOptionsFromJSON() {},
    parseRequestOptionsFromJSON() {},
    ...overrides,
  });
}

function makeScope(options = {}) {
  return {
    isSecureContext: 'secure' in options ? options.secure : true,
    PublicKeyCredential: 'publicKeyCredential' in options ? options.publicKeyCredential : fullPublicKeyCredential(),
    navigator: { credentials: options.credentials ?? { create() {}, get() {} } },
  };
}

function throwingGetter(target, name, error = new Error(`${name} exploded`)) {
  Object.defineProperty(target, name, {
    configurable: true,
    get() {
      throw error;
    },
  });
  return target;
}

describe('WebAuthn facts', () => {
  it('gives every fact a label and names the API it asks', () => {
    expect(WEBAUTHN_FACTS.map((fact) => fact.id)).toEqual([
      'secureContext',
      'webauthnApi',
      'conditionalMediation',
      'parseCreationOptionsFromJSON',
      'parseRequestOptionsFromJSON',
      'toJSON',
    ]);
    expect(AUTHENTICATOR_FACTS.map((fact) => fact.id)).toEqual(['userVerifyingPlatformAuthenticator', 'hybridTransport']);
    expect(Object.keys(STATE_TEXT)).toEqual(['yes', 'no', 'unavailable', 'undetermined']);
    expect(Object.values(STATE_TEXT)).not.toContain('Unknown');
  });

  it('reports a browser that offers everything', async () => {
    const { facts, clientCapabilities } = await gatherWebAuthnFacts(makeScope());

    expect(facts).toEqual({
      secureContext: { state: 'yes' },
      webauthnApi: { state: 'yes' },
      conditionalMediation: { state: 'yes' },
      parseCreationOptionsFromJSON: { state: 'yes' },
      parseRequestOptionsFromJSON: { state: 'yes' },
      toJSON: { state: 'yes' },
      userVerifyingPlatformAuthenticator: { state: 'yes' },
      hybridTransport: { state: 'yes' },
    });
    expect(clientCapabilities.state).toBe('yes');
    expect(clientCapabilities.returned).toEqual(CHROMIUM_152_CAPABILITIES);
    expect(clientCapabilities.omitted).toEqual([]);
  });

  describe('secure context', () => {
    it.each([
      [true, { state: 'yes' }],
      [false, { state: 'no', note: 'WebAuthn works only over HTTPS or on localhost.' }],
      [undefined, { state: 'unavailable' }],
    ])('isSecureContext %s', async (value, expected) => {
      const { facts } = await gatherWebAuthnFacts(makeScope({ secure: value }));
      expect(facts.secureContext).toEqual(expected);
    });

    it('could not be determined when reading it throws', async () => {
      const scope = throwingGetter(makeScope(), 'isSecureContext');
      const { facts } = await gatherWebAuthnFacts(scope);
      expect(facts.secureContext).toEqual({ state: 'undetermined', note: 'Error: isSecureContext exploded' });
    });
  });

  describe('the WebAuthn API', () => {
    it('is not available without PublicKeyCredential, and says a secure context is needed', async () => {
      const { facts, clientCapabilities } = await gatherWebAuthnFacts(
        makeScope({ secure: false, publicKeyCredential: undefined, credentials: {} }),
      );

      expect(facts.webauthnApi).toEqual({
        state: 'unavailable',
        note:
          'Missing: PublicKeyCredential; navigator.credentials.create() and get(). ' +
          'Browsers offer WebAuthn only in a secure context.',
      });
      const withoutWebAuthn = { state: 'unavailable', note: 'The WebAuthn API is not available on this page.' };
      for (const id of [
        'conditionalMediation',
        'parseCreationOptionsFromJSON',
        'parseRequestOptionsFromJSON',
        'toJSON',
        'userVerifyingPlatformAuthenticator',
        'hybridTransport',
      ]) {
        expect(facts[id], id).toEqual(withoutWebAuthn);
      }
      expect(clientCapabilities).toEqual({ ...withoutWebAuthn, returned: null, capabilities: [], omitted: [] });
    });

    it('is not available when navigator.credentials cannot create', async () => {
      const { facts } = await gatherWebAuthnFacts(makeScope({ credentials: { get() {} } }));
      expect(facts.webauthnApi).toEqual({ state: 'unavailable', note: 'Missing: navigator.credentials.create() and get().' });
    });

    it('could not be determined when reading PublicKeyCredential throws', async () => {
      const scope = throwingGetter(makeScope(), 'PublicKeyCredential');
      const { facts } = await gatherWebAuthnFacts(scope);
      expect(facts.webauthnApi).toEqual({ state: 'undetermined', note: 'Error: PublicKeyCredential exploded' });
      expect(facts.conditionalMediation.state).toBe('unavailable');
    });
  });

  describe.each([
    ['conditionalMediation', 'isConditionalMediationAvailable'],
    ['userVerifyingPlatformAuthenticator', 'isUserVerifyingPlatformAuthenticatorAvailable'],
  ])('%s, from %s()', (id, method) => {
    async function factWith(implementation) {
      const statics = implementation === undefined ? { [method]: undefined } : { [method]: implementation };
      const { facts } = await gatherWebAuthnFacts(makeScope({ publicKeyCredential: fullPublicKeyCredential(statics) }));
      return facts[id];
    }

    it('yes', async () => {
      expect(await factWith(async () => true)).toEqual({ state: 'yes' });
    });

    it('no', async () => {
      expect(await factWith(async () => false)).toEqual({ state: 'no' });
    });

    it('not available when the method is missing', async () => {
      expect(await factWith(undefined)).toEqual({ state: 'unavailable' });
    });

    it('could not be determined when the call rejects, saying why', async () => {
      expect(
        await factWith(async () => {
          throw new DOMException('The operation is insecure.', 'SecurityError');
        }),
      ).toEqual({ state: 'undetermined', note: 'SecurityError: The operation is insecure.' });
    });

    it('could not be determined when the answer is not a boolean', async () => {
      expect(await factWith(async () => 'maybe')).toEqual({
        state: 'undetermined',
        note: 'The browser answered "maybe", not true or false.',
      });
    });

    it('could not be determined when reading the method throws', async () => {
      const publicKeyCredential = throwingGetter(fullPublicKeyCredential(), method);
      const { facts } = await gatherWebAuthnFacts(makeScope({ publicKeyCredential }));
      expect(facts[id]).toEqual({ state: 'undetermined', note: `Error: ${method} exploded` });
    });
  });

  describe.each([
    ['parseCreationOptionsFromJSON', (pkc) => pkc],
    ['parseRequestOptionsFromJSON', (pkc) => pkc],
    ['toJSON', (pkc) => pkc.prototype],
  ])('JSON helper %s', (id, owner) => {
    it('yes when the browser offers it', async () => {
      const { facts } = await gatherWebAuthnFacts(makeScope());
      expect(facts[id]).toEqual({ state: 'yes' });
    });

    it('not available when the browser does not', async () => {
      const publicKeyCredential = fullPublicKeyCredential();
      delete owner(publicKeyCredential)[id];
      const { facts } = await gatherWebAuthnFacts(makeScope({ publicKeyCredential }));
      expect(facts[id]).toEqual({ state: 'unavailable' });
    });

    it('could not be determined when reading it throws', async () => {
      const publicKeyCredential = fullPublicKeyCredential();
      throwingGetter(owner(publicKeyCredential), id);
      const { facts } = await gatherWebAuthnFacts(makeScope({ publicKeyCredential }));
      expect(facts[id]).toEqual({ state: 'undetermined', note: `Error: ${id} exploded` });
    });
  });
});

describe('client capabilities', () => {
  async function gatherWith(getClientCapabilities) {
    const publicKeyCredential = fullPublicKeyCredential({ getClientCapabilities });
    return gatherWebAuthnFacts(makeScope({ publicKeyCredential }));
  }

  it('shows every key the browser returns: defined ones labelled, extensions grouped, others verbatim', async () => {
    const { clientCapabilities, facts } = await gatherWith(async () => ({ ...CHROMIUM_152_CAPABILITIES }));

    expect(clientCapabilities.capabilities).toHaveLength(24);
    const byKind = (kind) => clientCapabilities.capabilities.filter((entry) => entry.kind === kind);
    expect(byKind('defined').map((entry) => entry.key).sort()).toEqual(Object.keys(CLIENT_CAPABILITY_LABELS).sort());
    expect(byKind('extension').map((entry) => entry.label)).toEqual([
      'appid',
      'appidExclude',
      'cmtgKey',
      'credBlob',
      'credProps',
      'credentialProtectionPolicy',
      'crossDeviceFallbackUrl',
      'enforceCredentialProtectionPolicy',
      'getCredBlob',
      'hmacCreateSecret',
      'largeBlob',
      'minPinLength',
      'payment',
      'prf',
    ]);
    expect(byKind('unrecognised')).toEqual([{ key: 'immediateGet', kind: 'unrecognised', label: 'immediateGet', state: 'yes' }]);
    expect(clientCapabilities.capabilities.find((entry) => entry.key === 'extension:cmtgKey').state).toBe('no');
    expect(clientCapabilities.capabilities.find((entry) => entry.key === 'conditionalGet')).toEqual({
      key: 'conditionalGet',
      kind: 'defined',
      label: 'Passkey autofill (conditional get)',
      state: 'yes',
    });
    expect(facts.hybridTransport).toEqual({ state: 'yes' });
  });

  it('names the defined capabilities the browser left out, whose availability the spec says is not known', async () => {
    const { clientCapabilities, facts } = await gatherWith(async () => ({ conditionalGet: false, 'extension:prf': true }));

    expect(clientCapabilities.omitted).toEqual([
      'conditionalCreate',
      'hybridTransport',
      'passkeyPlatformAuthenticator',
      'userVerifyingPlatformAuthenticator',
      'relatedOrigins',
      'signalAllAcceptedCredentials',
      'signalCurrentUserDetails',
      'signalUnknownCredential',
    ]);
    expect(facts.hybridTransport).toEqual({
      state: 'undetermined',
      note: 'getClientCapabilities() did not include hybridTransport, so its availability is not known.',
    });
  });

  it('reads hybrid as no when the browser says so, and a value that is not a boolean as undetermined', async () => {
    const no = await gatherWith(async () => ({ hybridTransport: false }));
    expect(no.facts.hybridTransport).toEqual({ state: 'no' });

    const odd = await gatherWith(async () => ({ hybridTransport: 'sometimes', relatedOrigins: 1 }));
    expect(odd.facts.hybridTransport).toEqual({
      state: 'undetermined',
      note: 'The browser answered "sometimes", not true or false.',
    });
    expect(odd.clientCapabilities.returned).toEqual({ hybridTransport: 'sometimes', relatedOrigins: 1 });
  });

  it('accepts a Map', async () => {
    const { clientCapabilities } = await gatherWith(async () => new Map([['hybridTransport', true]]));
    expect(clientCapabilities.returned).toEqual({ hybridTransport: true });
  });

  it('says getClientCapabilities is a Level 3 feature this browser does not offer when it is missing', async () => {
    const { clientCapabilities, facts } = await gatherWith(undefined);
    const note = 'getClientCapabilities() is a WebAuthn Level 3 feature this browser does not offer.';

    expect(clientCapabilities).toEqual({ state: 'unavailable', note, returned: null, capabilities: [], omitted: [] });
    expect(facts.hybridTransport).toEqual({ state: 'unavailable', note });
  });

  it('could not be determined when it throws, and says why', async () => {
    const { clientCapabilities, facts } = await gatherWith(async () => {
      throw new DOMException('Document is not focused.', 'NotAllowedError');
    });

    expect(clientCapabilities).toEqual({
      state: 'undetermined',
      note: 'NotAllowedError: Document is not focused.',
      returned: null,
      capabilities: [],
      omitted: [],
    });
    expect(facts.hybridTransport).toEqual({ state: 'undetermined', note: 'NotAllowedError: Document is not focused.' });
  });

  it('could not be determined when the answer is not a record, or reading the method throws', async () => {
    const { clientCapabilities } = await gatherWith(async () => null);
    expect(clientCapabilities.state).toBe('undetermined');
    expect(clientCapabilities.note).toBe('The browser answered null, not a record.');

    const publicKeyCredential = throwingGetter(fullPublicKeyCredential(), 'getClientCapabilities');
    const thrown = await gatherWebAuthnFacts(makeScope({ publicKeyCredential }));
    expect(thrown.clientCapabilities.note).toBe('Error: getClientCapabilities exploded');
  });

  it('describes a thrown value that is not an Error', async () => {
    const { clientCapabilities } = await gatherWith(async () => {
      throw 'plain string';
    });
    expect(clientCapabilities.note).toBe('plain string');

    const unnamed = await gatherWith(async () => {
      throw { name: '', message: '' };
    });
    expect(unnamed.clientCapabilities.note).toBe('Error');
  });

  it('describes an answer JSON cannot write', async () => {
    const { facts } = await gatherWebAuthnFacts(
      makeScope({
        publicKeyCredential: fullPublicKeyCredential({
          isConditionalMediationAvailable: async () => 10n,
          isUserVerifyingPlatformAuthenticatorAvailable: async () => undefined,
        }),
      }),
    );
    expect(facts.conditionalMediation.note).toBe('The browser answered 10, not true or false.');
    expect(facts.userVerifyingPlatformAuthenticator.note).toBe('The browser answered undefined, not true or false.');
  });
});
