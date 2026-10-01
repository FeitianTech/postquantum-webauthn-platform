import { describe, expect, it, vi } from 'vitest';

import {
  UPDATE_BROWSER_TEXT,
  UnsupportedBrowserError,
  createCredential,
  getAssertion,
  nativeJsonSupported,
  parseCreationOptions,
  parseRequestOptions,
  requireNativeJson,
} from './native-json.js';

function credentialClass({ statics = {}, toJSON = () => ({}) } = {}) {
  function PublicKeyCredential() {}
  Object.assign(PublicKeyCredential, {
    parseCreationOptionsFromJSON: (json) => ({ parsed: 'creation', json }),
    parseRequestOptionsFromJSON: (json) => ({ parsed: 'request', json }),
    ...statics,
  });
  if (toJSON) PublicKeyCredential.prototype.toJSON = toJSON;
  return PublicKeyCredential;
}

function browser(options = {}) {
  const credential = { toJSON: () => ({ id: 'AQID', clientExtensionResults: { prf: { enabled: true } } }) };
  return {
    PublicKeyCredential: credentialClass(options),
    navigator: { credentials: { create: vi.fn(async () => credential), get: vi.fn(async () => credential) } },
  };
}

describe('the browser\'s own WebAuthn JSON', () => {
  it('is there when both parsers and toJSON are functions', () => {
    expect(nativeJsonSupported(browser())).toBe(true);
    expect(requireNativeJson(browser())).toBeTypeOf('function');
  });

  it.each([
    ['no PublicKeyCredential', { PublicKeyCredential: undefined }],
    ['no creation parser', browser({ statics: { parseCreationOptionsFromJSON: undefined } })],
    ['no request parser', browser({ statics: { parseRequestOptionsFromJSON: undefined } })],
    ['no toJSON', browser({ toJSON: null })],
  ])('is missing with %s, and asks for an update', (_name, scope) => {
    expect(nativeJsonSupported(scope)).toBe(false);
    expect(() => requireNativeJson(scope)).toThrow(UnsupportedBrowserError);
    expect(() => parseCreationOptions({}, scope)).toThrow(UPDATE_BROWSER_TEXT);
    expect(() => parseRequestOptions({}, scope)).toThrow(UPDATE_BROWSER_TEXT);
  });

  it('reads the page\'s own global unless given another scope', () => {
    expect(nativeJsonSupported()).toBe(typeof globalThis.PublicKeyCredential === 'function'
      && typeof globalThis.PublicKeyCredential.parseCreationOptionsFromJSON === 'function');
  });

  it('names the browsers that have it in its error', () => {
    const error = new UnsupportedBrowserError();
    expect(error.name).toBe('UnsupportedBrowserError');
    expect(error.message).toBe(UPDATE_BROWSER_TEXT);
    expect(UPDATE_BROWSER_TEXT).toContain('Chrome or Edge 129, Firefox 119, Safari 18.4');
  });

  it('reads options with the browser\'s parsers', () => {
    const scope = browser();
    expect(parseCreationOptions({ challenge: 'AA' }, scope)).toEqual({ parsed: 'creation', json: { challenge: 'AA' } });
    expect(parseRequestOptions({ challenge: 'AA' }, scope)).toEqual({ parsed: 'request', json: { challenge: 'AA' } });
  });

  it('gives the credential the authenticator made and its own JSON', async () => {
    const scope = browser();
    const created = await createCredential({ challenge: 'parsed' }, scope);
    const asserted = await getAssertion({ challenge: 'parsed' }, scope);

    expect(scope.navigator.credentials.create).toHaveBeenCalledWith({ publicKey: { challenge: 'parsed' } });
    expect(scope.navigator.credentials.get).toHaveBeenCalledWith({ publicKey: { challenge: 'parsed' } });
    expect(created.json).toEqual({ id: 'AQID', clientExtensionResults: { prf: { enabled: true } } });
    expect(asserted.credential).toBe(created.credential);
  });
});
