import { describe, expect, it } from 'vitest';

import {
  SOURCE_TEXT,
  determineIdentity,
  readIdentityInputs,
} from '../../../../frontend/static/scripts/shared/browser/identity.js';
import { IDENTITY_MATRIX } from './identity-matrix.js';

async function identify(navigatorLike) {
  return determineIdentity(await readIdentityInputs(navigatorLike));
}

describe('browser identity matrix', () => {
  it.each(IDENTITY_MATRIX.map((entry) => [entry.label, entry]))('%s', async (_label, entry) => {
    const identity = await identify(entry.navigator);

    expect({
      name: identity.name,
      version: identity.version,
      engine: identity.engine,
      system: identity.system,
      sources: identity.sources,
    }).toEqual(entry.expected);
    expect(identity.onAppleWebKit).toBe(entry.expected.system === 'iOS' || entry.expected.system === 'iPadOS');
  });

  it('describes every source it uses', () => {
    const used = new Set(IDENTITY_MATRIX.flatMap((entry) => Object.values(entry.expected.sources)));
    for (const source of used) {
      expect(SOURCE_TEXT[source], source).toEqual(expect.any(String));
    }
  });
});

describe('browser identity edge cases', () => {
  const CHROME_UA =
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.7977.130 Safari/537.36';

  it('says Chromium-based when another product shares a user-agent string that says Chrome', async () => {
    const identity = await identify({
      userAgent: CHROME_UA.replace('Chrome/', 'Claude/2.9939.2 Chrome/'),
      platform: 'MacIntel',
      maxTouchPoints: 0,
    });

    expect(identity).toMatchObject({ name: 'Chromium-based browser', version: '152.0.7977.130', engine: 'Blink' });
    expect(identity.sources.name).toBe('user-agent');
  });

  it('names Android WebView from its user-agent marker', async () => {
    const identity = await identify({
      userAgent:
        'Mozilla/5.0 (Linux; Android 14; Pixel 8; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/140.0.7339.128 Mobile Safari/537.36',
      platform: 'Linux aarch64',
      maxTouchPoints: 5,
    });

    expect(identity).toMatchObject({ name: 'Android WebView', version: '140.0.7339.128', engine: 'Blink', system: 'Android' });
  });

  it('does not call an iOS in-app browser Safari', async () => {
    const identity = await identify({
      userAgent:
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 GSA/380.0.1 Mobile/15E148 Safari/604.1',
      platform: 'iPhone',
      maxTouchPoints: 5,
    });

    expect(identity).toMatchObject({ name: null, version: null, engine: 'WebKit', system: 'iOS' });
    expect(identity.sources).toMatchObject({ name: 'not-reported', version: 'not-reported', engine: 'apple-webkit' });
  });

  it('reports nothing it cannot read', async () => {
    const identity = await identify({ userAgent: 'CustomAgent', platform: '', maxTouchPoints: 0 });

    expect(identity).toEqual({
      name: null,
      version: null,
      engine: null,
      system: null,
      sources: { name: 'not-reported', version: 'not-reported', engine: 'not-reported', system: 'not-reported' },
      onAppleWebKit: false,
    });
  });

  it('names a BSD as it is written and a WebKit browser it does not know as WebKit', async () => {
    const identity = await identify({
      userAgent: 'Mozilla/5.0 (X11; FreeBSD amd64) AppleWebKit/605.1.15 (KHTML, like Gecko) Epiphany/605.1.15',
      platform: 'FreeBSD amd64',
      maxTouchPoints: 0,
    });

    expect(identity).toMatchObject({ name: null, engine: 'WebKit', system: 'FreeBSD' });
  });

  it('copies the inputs it read, including Client Hints and navigator.brave', async () => {
    const inputs = await readIdentityInputs({
      userAgent: CHROME_UA,
      platform: 'MacIntel',
      maxTouchPoints: 0,
      userAgentData: {
        brands: [{ brand: 'Chromium', version: 152 }, { brand: 'Not?A_Brand', version: '24' }],
        mobile: false,
        platform: 'macOS',
        getHighEntropyValues: async (hints) => {
          expect(hints).toEqual(['fullVersionList', 'platformVersion']);
          return { fullVersionList: [{ brand: 'Chromium', version: '152.0.7977.130' }], platformVersion: '27.2.0' };
        },
      },
      brave: { isBrave: async () => false },
    });

    expect(inputs).toEqual({
      userAgent: CHROME_UA,
      platform: 'MacIntel',
      maxTouchPoints: 0,
      userAgentData: {
        brands: [{ brand: 'Chromium', version: '152' }, { brand: 'Not?A_Brand', version: '24' }],
        mobile: false,
        platform: 'macOS',
      },
      highEntropyValues: {
        fullVersionList: [{ brand: 'Chromium', version: '152.0.7977.130' }],
        platformVersion: '27.2.0',
      },
      brave: { isBrave: false },
    });
  });

  it('records what failed when Client Hints or navigator.brave throw', async () => {
    const userAgentData = { platform: 'Linux' };
    Object.defineProperty(userAgentData, 'brands', {
      get() {
        throw new Error('brand access failed');
      },
    });
    userAgentData.getHighEntropyValues = async () => {
      throw new DOMException('denied', 'NotAllowedError');
    };

    const inputs = await readIdentityInputs({
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
      platform: 'Linux x86_64',
      maxTouchPoints: 0,
      userAgentData,
      brave: {
        isBrave: async () => {
          throw new Error('shields down');
        },
      },
    });

    expect(inputs.userAgentData).toEqual({
      brands: null,
      mobile: null,
      platform: 'Linux',
      errors: { brands: 'Error: brand access failed' },
    });
    expect(inputs.highEntropyValues).toEqual({ error: 'NotAllowedError: denied' });
    expect(inputs.brave).toEqual({ error: 'Error: shields down' });

    // With no brand to read, the name comes from the user-agent string; the system still from Client Hints.
    expect(determineIdentity(inputs)).toMatchObject({
      name: 'Google Chrome',
      version: '140',
      system: 'Linux',
      sources: { name: 'user-agent', system: 'client-hints' },
    });
  });

  it('records a navigator.userAgentData that throws, and a navigator.brave without isBrave', async () => {
    const nav = { userAgent: CHROME_UA, platform: 'MacIntel', maxTouchPoints: 0, brave: {} };
    Object.defineProperty(nav, 'userAgentData', {
      get() {
        throw new TypeError('not here');
      },
    });

    const inputs = await readIdentityInputs(nav);

    expect(inputs.userAgentData).toEqual({ error: 'TypeError: not here' });
    expect(inputs.highEntropyValues).toBeNull();
    expect(inputs.brave).toEqual({ isBrave: null });
  });

  it('records a getHighEntropyValues or navigator.brave that throws when read', async () => {
    const userAgentData = { brands: [], mobile: false, platform: 'Windows' };
    Object.defineProperty(userAgentData, 'getHighEntropyValues', {
      get() {
        throw new Error('no hints');
      },
    });
    const nav = { userAgent: '', platform: 'Win32', maxTouchPoints: 0, userAgentData };
    Object.defineProperty(nav, 'brave', {
      get() {
        throw new Error('no brave');
      },
    });

    const inputs = await readIdentityInputs(nav);

    expect(inputs.highEntropyValues).toEqual({ error: 'Error: no hints' });
    expect(inputs.brave).toEqual({ error: 'Error: no brave' });
  });

  it('takes an Unknown Client Hints platform as not reported and uses a brand from fullVersionList alone', async () => {
    const identity = await identify({
      userAgent: '',
      platform: '',
      maxTouchPoints: 0,
      userAgentData: {
        brands: [],
        mobile: false,
        platform: 'Unknown',
        getHighEntropyValues: async () => ({ fullVersionList: [{ brand: 'Microsoft Edge', version: '140.0.3485.66' }] }),
      },
    });

    expect(identity).toMatchObject({ name: 'Microsoft Edge', version: '140.0.3485.66', system: null });
    expect(identity.sources.system).toBe('not-reported');
  });

  it('takes the major version from the brand list when getHighEntropyValues is not offered', async () => {
    const inputs = await readIdentityInputs({
      userAgent: CHROME_UA,
      platform: 'MacIntel',
      maxTouchPoints: 0,
      userAgentData: { brands: [{ brand: 'Google Chrome', version: '152' }], mobile: false, platform: 'macOS' },
    });

    expect(inputs.highEntropyValues).toBeNull();
    expect(determineIdentity(inputs)).toMatchObject({ name: 'Google Chrome', version: '152' });
  });

  it('reads nothing from a missing navigator', async () => {
    await expect(readIdentityInputs(null)).resolves.toEqual({
      userAgent: null,
      platform: null,
      maxTouchPoints: null,
      userAgentData: null,
      highEntropyValues: null,
      brave: null,
    });
  });
});
