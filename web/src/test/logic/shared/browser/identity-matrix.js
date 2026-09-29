// Real user-agent strings, with the Client Hints each browser sends, and what the
// Analyze Browser panel must say about each. Versions differ between brands on
// purpose, so a version taken from the wrong brand shows.

const CH = 'client-hints';
const UA = 'user-agent';

function clientHints({ brands, fullVersionList, platform, mobile = false, highEntropy = true }) {
  return {
    brands,
    mobile,
    platform,
    getHighEntropyValues: async () => {
      if (!highEntropy) {
        throw new DOMException('High-entropy values are not available', 'NotAllowedError');
      }
      return { brands, mobile, platform, fullVersionList, platformVersion: '15.0.0' };
    },
  };
}

const CHROME_BRANDS = [
  { brand: 'Chromium', version: '140' },
  { brand: 'Not=A?Brand', version: '24' },
  { brand: 'Google Chrome', version: '140' },
];
const CHROME_FULL = [
  { brand: 'Chromium', version: '140.0.7339.128' },
  { brand: 'Not=A?Brand', version: '24.0.0.0' },
  { brand: 'Google Chrome', version: '140.0.7339.128' },
];

function chrome(platform) {
  return clientHints({ brands: CHROME_BRANDS, fullVersionList: CHROME_FULL, platform, mobile: platform === 'Android' });
}

const CHROME_EXPECTED = { name: 'Google Chrome', version: '140.0.7339.128', engine: 'Blink' };
const ALL_CH = { name: CH, version: CH, engine: CH, system: CH };

const IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko)';
const MAC_SAFARI =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15';
const ON_IOS = { name: UA, version: UA, engine: 'apple-webkit', system: UA };

export const IDENTITY_MATRIX = [
  {
    label: 'Chrome on Windows',
    navigator: {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
      platform: 'Win32',
      maxTouchPoints: 0,
      userAgentData: chrome('Windows'),
    },
    expected: { ...CHROME_EXPECTED, system: 'Windows', sources: ALL_CH },
  },
  {
    label: 'Chrome on macOS',
    navigator: {
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
      platform: 'MacIntel',
      maxTouchPoints: 0,
      userAgentData: chrome('macOS'),
    },
    expected: { ...CHROME_EXPECTED, system: 'macOS', sources: ALL_CH },
  },
  {
    label: 'Chrome on Linux',
    navigator: {
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
      platform: 'Linux x86_64',
      maxTouchPoints: 0,
      userAgentData: chrome('Linux'),
    },
    expected: { ...CHROME_EXPECTED, system: 'Linux', sources: ALL_CH },
  },
  {
    label: 'Chrome on Android',
    navigator: {
      userAgent: 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36',
      platform: 'Linux armv81',
      maxTouchPoints: 5,
      userAgentData: chrome('Android'),
    },
    expected: { ...CHROME_EXPECTED, system: 'Android', sources: ALL_CH },
  },
  {
    label: 'Chrome on ChromeOS',
    navigator: {
      userAgent: 'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
      platform: 'Linux x86_64',
      maxTouchPoints: 0,
      userAgentData: chrome('Chrome OS'),
    },
    expected: { ...CHROME_EXPECTED, system: 'ChromeOS', sources: ALL_CH },
  },
  {
    // The tech lead's browser: a Chromium build whose brand list is only "Chromium".
    label: 'Chromium-only brand list',
    navigator: {
      userAgent:
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Claude/2.9939.2 Chrome/152.0.7977.130 Safari/537.36',
      platform: 'MacIntel',
      maxTouchPoints: 0,
      userAgentData: clientHints({
        brands: [{ brand: 'Not?A_Brand', version: '24' }, { brand: 'Chromium', version: '152' }],
        fullVersionList: [{ brand: 'Not?A_Brand', version: '24.0.0.0' }, { brand: 'Chromium', version: '152.0.7977.130' }],
        platform: 'macOS',
      }),
    },
    expected: { name: 'Chromium-based browser', version: '152.0.7977.130', engine: 'Blink', system: 'macOS', sources: ALL_CH },
  },
  {
    label: 'Chromium-only brand list, full versions not granted',
    navigator: {
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
      platform: 'Linux x86_64',
      maxTouchPoints: 0,
      userAgentData: clientHints({
        brands: [{ brand: 'Chromium', version: '140' }, { brand: 'Not=A?Brand', version: '24' }],
        platform: 'Linux',
        highEntropy: false,
      }),
    },
    expected: { name: 'Chromium-based browser', version: '140', engine: 'Blink', system: 'Linux', sources: ALL_CH },
  },
  {
    label: 'Microsoft Edge on Windows',
    navigator: {
      userAgent:
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0',
      platform: 'Win32',
      maxTouchPoints: 0,
      userAgentData: clientHints({
        brands: [
          { brand: 'Chromium', version: '140' },
          { brand: 'Not=A?Brand', version: '24' },
          { brand: 'Microsoft Edge', version: '140' },
        ],
        fullVersionList: [
          { brand: 'Chromium', version: '140.0.7339.128' },
          { brand: 'Not=A?Brand', version: '24.0.0.0' },
          { brand: 'Microsoft Edge', version: '140.0.3485.66' },
        ],
        platform: 'Windows',
      }),
    },
    expected: { name: 'Microsoft Edge', version: '140.0.3485.66', engine: 'Blink', system: 'Windows', sources: ALL_CH },
  },
  {
    label: 'Brave, named in the brand list',
    navigator: {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
      platform: 'Win32',
      maxTouchPoints: 0,
      userAgentData: clientHints({
        brands: [
          { brand: 'Chromium', version: '140' },
          { brand: 'Not=A?Brand', version: '24' },
          { brand: 'Brave', version: '140' },
        ],
        fullVersionList: [
          { brand: 'Chromium', version: '140.0.7339.128' },
          { brand: 'Not=A?Brand', version: '24.0.0.0' },
          { brand: 'Brave', version: '140.0.7339.128' },
        ],
        platform: 'Windows',
      }),
      brave: { isBrave: async () => true },
    },
    expected: {
      name: 'Brave',
      version: '140.0.7339.128',
      engine: 'Blink',
      system: 'Windows',
      sources: { name: 'brave-api', version: CH, engine: CH, system: CH },
    },
  },
  {
    label: 'Brave, known only by navigator.brave',
    navigator: {
      userAgent:
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
      platform: 'MacIntel',
      maxTouchPoints: 0,
      userAgentData: clientHints({
        brands: [{ brand: 'Chromium', version: '140' }, { brand: 'Not=A?Brand', version: '24' }],
        fullVersionList: [{ brand: 'Chromium', version: '140.0.7339.128' }, { brand: 'Not=A?Brand', version: '24.0.0.0' }],
        platform: 'macOS',
      }),
      brave: { isBrave: async () => true },
    },
    expected: {
      name: 'Brave',
      version: null,
      engine: 'Blink',
      system: 'macOS',
      sources: { name: 'brave-api', version: 'not-reported', engine: CH, system: CH },
    },
  },
  {
    label: 'Opera on Windows',
    navigator: {
      userAgent:
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 OPR/123.0.0.0',
      platform: 'Win32',
      maxTouchPoints: 0,
      userAgentData: clientHints({
        brands: [
          { brand: 'Chromium', version: '139' },
          { brand: 'Opera', version: '123' },
          { brand: 'Not;A=Brand', version: '99' },
        ],
        fullVersionList: [
          { brand: 'Chromium', version: '139.0.7258.155' },
          { brand: 'Opera', version: '123.0.5669.23' },
          { brand: 'Not;A=Brand', version: '99.0.0.0' },
        ],
        platform: 'Windows',
      }),
    },
    expected: { name: 'Opera', version: '123.0.5669.23', engine: 'Blink', system: 'Windows', sources: ALL_CH },
  },
  {
    label: 'Samsung Internet on Android',
    navigator: {
      userAgent:
        'Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/28.0 Chrome/130.0.0.0 Mobile Safari/537.36',
      platform: 'Linux armv81',
      maxTouchPoints: 5,
      userAgentData: clientHints({
        brands: [
          { brand: 'Chromium', version: '130' },
          { brand: 'Samsung Internet', version: '28' },
          { brand: 'Not?A_Brand', version: '99' },
        ],
        platform: 'Android',
        mobile: true,
        highEntropy: false,
      }),
    },
    expected: { name: 'Samsung Internet', version: '28', engine: 'Blink', system: 'Android', sources: ALL_CH },
  },
  {
    label: 'Samsung Internet, Chromium-only brand list',
    navigator: {
      userAgent:
        'Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/28.0 Chrome/130.0.0.0 Mobile Safari/537.36',
      platform: 'Linux armv81',
      maxTouchPoints: 5,
      userAgentData: clientHints({
        brands: [{ brand: 'Chromium', version: '130' }, { brand: 'Not?A_Brand', version: '99' }],
        fullVersionList: [{ brand: 'Chromium', version: '130.0.6723.86' }, { brand: 'Not?A_Brand', version: '99.0.0.0' }],
        platform: 'Android',
        mobile: true,
      }),
    },
    expected: {
      name: 'Samsung Internet',
      version: '28.0',
      engine: 'Blink',
      system: 'Android',
      sources: { name: UA, version: UA, engine: CH, system: CH },
    },
  },
  {
    label: 'Firefox on Windows',
    navigator: {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0',
      platform: 'Win32',
      maxTouchPoints: 0,
    },
    expected: {
      name: 'Mozilla Firefox',
      version: '143.0',
      engine: 'Gecko',
      system: 'Windows',
      sources: { name: UA, version: UA, engine: UA, system: UA },
    },
  },
  {
    label: 'Firefox on Android',
    navigator: {
      userAgent: 'Mozilla/5.0 (Android 15; Mobile; rv:143.0) Gecko/143.0 Firefox/143.0',
      platform: 'Linux aarch64',
      maxTouchPoints: 5,
    },
    expected: {
      name: 'Mozilla Firefox',
      version: '143.0',
      engine: 'Gecko',
      system: 'Android',
      sources: { name: UA, version: UA, engine: UA, system: UA },
    },
  },
  {
    label: 'Safari on macOS',
    navigator: { userAgent: MAC_SAFARI, platform: 'MacIntel', maxTouchPoints: 0 },
    expected: {
      name: 'Safari',
      version: '26.0',
      engine: 'WebKit',
      system: 'macOS',
      sources: { name: UA, version: UA, engine: UA, system: UA },
    },
  },
  {
    label: 'iPadOS Safari, desktop mode',
    navigator: { userAgent: MAC_SAFARI, platform: 'MacIntel', maxTouchPoints: 5 },
    expected: {
      name: 'Safari',
      version: '26.0',
      engine: 'WebKit',
      system: 'iPadOS',
      sources: { name: UA, version: UA, engine: 'apple-webkit', system: 'platform-touch' },
    },
  },
  {
    label: 'Safari on iPhone',
    navigator: {
      userAgent: `${IPHONE} Version/26.0 Mobile/15E148 Safari/604.1`,
      platform: 'iPhone',
      maxTouchPoints: 5,
    },
    expected: { name: 'Safari', version: '26.0', engine: 'WebKit', system: 'iOS', sources: ON_IOS },
  },
  {
    label: 'Chrome on iOS (CriOS)',
    navigator: {
      userAgent: `${IPHONE} CriOS/140.0.7339.101 Mobile/15E148 Safari/604.1`,
      platform: 'iPhone',
      maxTouchPoints: 5,
    },
    expected: { name: 'Google Chrome', version: '140.0.7339.101', engine: 'WebKit', system: 'iOS', sources: ON_IOS },
  },
  {
    label: 'Firefox on iOS (FxiOS)',
    navigator: {
      userAgent: `${IPHONE} FxiOS/143.0 Mobile/15E148 Safari/605.1.15`,
      platform: 'iPhone',
      maxTouchPoints: 5,
    },
    expected: { name: 'Mozilla Firefox', version: '143.0', engine: 'WebKit', system: 'iOS', sources: ON_IOS },
  },
  {
    label: 'Edge on iOS (EdgiOS)',
    navigator: {
      userAgent: `${IPHONE} Version/26.0 EdgiOS/140.0.3485.94 Mobile/15E148 Safari/605.1.15`,
      platform: 'iPhone',
      maxTouchPoints: 5,
    },
    expected: { name: 'Microsoft Edge', version: '140.0.3485.94', engine: 'WebKit', system: 'iOS', sources: ON_IOS },
  },
  {
    label: 'Chrome without Client Hints (not a secure context)',
    navigator: {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
      platform: 'Win32',
      maxTouchPoints: 0,
    },
    expected: {
      name: 'Google Chrome',
      version: '140',
      engine: 'Blink',
      system: 'Windows',
      sources: { name: UA, version: UA, engine: UA, system: UA },
    },
  },
  {
    label: 'Edge without Client Hints',
    navigator: {
      userAgent:
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0',
      platform: 'Win32',
      maxTouchPoints: 0,
    },
    expected: {
      name: 'Microsoft Edge',
      version: '140',
      engine: 'Blink',
      system: 'Windows',
      sources: { name: UA, version: UA, engine: UA, system: UA },
    },
  },
];
