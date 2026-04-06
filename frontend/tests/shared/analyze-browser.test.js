import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../static/scripts/shared/ui.js', () => ({
  updateGlobalScrollLock: vi.fn(),
}));

import { updateGlobalScrollLock } from '../../static/scripts/shared/ui.js';

async function loadAnalyzeBrowser() {
  vi.resetModules();
  return import('../../static/scripts/shared/analyze-browser.js');
}

function buildAnalyzeDom() {
  document.body.innerHTML = `
    <button data-analyze-browser-trigger>Analyze</button>
    <div id="analyze-browser-panel" hidden aria-hidden="true">
      <div class="analyze-browser-panel__content"></div>
      <button data-action="close">Close</button>
      <div id="analyze-browser-name"></div>
      <div id="analyze-browser-version"></div>
      <div id="analyze-browser-system"></div>
      <ul data-role="feature-list">
        <li data-feature="webauthn"><span class="analyze-browser-panel__feature-value"></span></li>
        <li data-feature="platform"><span class="analyze-browser-panel__feature-value"></span></li>
        <li data-feature="cross-platform"><span class="analyze-browser-panel__feature-value"></span></li>
      </ul>
      <ul data-role="transport-list"></ul>
    </div>
  `;
}

describe('analyze-browser', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('is a no-op when required DOM nodes are missing', async () => {
    const { initializeAnalyzeBrowser } = await loadAnalyzeBrowser();
    document.body.innerHTML = '<div></div>';

    expect(() => initializeAnalyzeBrowser()).not.toThrow();
  });

  it('initializes, gathers analysis, and opens/closes panel', async () => {
    vi.useFakeTimers();
    buildAnalyzeDom();

    Object.defineProperty(navigator, 'userAgentData', {
      configurable: true,
      value: {
        brands: [
          { brand: 'Not A Brand', version: '99' },
          { brand: 'Chromium', version: '123.0.0.0' },
        ],
        platform: 'macOS',
        getHighEntropyValues: vi.fn(async () => ({
          platform: 'macOS',
          platformVersion: '14.0.0',
          fullVersionList: [{ brand: 'Chromium', version: '123.1.2.3' }],
        })),
      },
    });
    Object.defineProperty(navigator, 'usb', { configurable: true, value: {} });
    Object.defineProperty(navigator, 'hid', { configurable: true, value: {} });

    globalThis.PublicKeyCredential = {
      isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => true),
      isConditionalMediationAvailable: vi.fn(async () => false),
    };

    const { initializeAnalyzeBrowser } = await loadAnalyzeBrowser();
    initializeAnalyzeBrowser();

    const trigger = document.querySelector('[data-analyze-browser-trigger]');
    trigger.click();
    await vi.runAllTimersAsync();

    const panel = document.getElementById('analyze-browser-panel');
    expect(panel.hidden).toBe(false);
    expect(panel.classList.contains('is-open')).toBe(true);
    expect(trigger.disabled).toBe(false);

    expect(document.getElementById('analyze-browser-name').textContent).toBe('Chromium');
    expect(document.getElementById('analyze-browser-version').textContent).toBe('123.1.2.3');
    expect(document.getElementById('analyze-browser-system').textContent).toBe('macOS');

    const values = [...panel.querySelectorAll('.analyze-browser-panel__feature-value')].map((el) => ({
      status: el.dataset.status,
      text: el.textContent,
    }));
    expect(values[0].status).toBe('true');
    expect(values[1].status).toBe('true');
    expect(values[2].status).toBe('true');

    const transportText = panel.querySelector('[data-role="transport-list"]').textContent;
    expect(transportText).toContain('Internal');
    expect(transportText).toContain('USB');
    expect(transportText).toContain('HID');

    const content = panel.querySelector('.analyze-browser-panel__content');
    content.scrollTop = 128;

    panel.querySelector('[data-action="close"]').click();
    expect(content.scrollTop).toBe(0);
    expect(panel.hidden).toBe(true);
    expect(panel.classList.contains('is-closing')).toBe(false);
    await vi.runAllTimersAsync();
    expect(panel.hidden).toBe(true);

    trigger.click();
    await vi.runAllTimersAsync();
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await vi.runAllTimersAsync();
    expect(panel.hidden).toBe(true);

    expect(updateGlobalScrollLock).toHaveBeenCalled();
  });

  it('reuses cached analysis results on subsequent opens in the same page session', async () => {
    vi.useFakeTimers();
    buildAnalyzeDom();

    Object.defineProperty(navigator, 'userAgentData', {
      configurable: true,
      value: {
        brands: [{ brand: 'Chromium', version: '123.0.0.0' }],
        platform: 'macOS',
        getHighEntropyValues: vi.fn(async () => ({
          platform: 'macOS',
          fullVersionList: [{ brand: 'Chromium', version: '123.0.0.0' }],
        })),
      },
    });

    globalThis.PublicKeyCredential = {
      isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => true),
      isConditionalMediationAvailable: vi.fn(async () => false),
    };

    const { initializeAnalyzeBrowser } = await loadAnalyzeBrowser();
    initializeAnalyzeBrowser();

    const trigger = document.querySelector('[data-analyze-browser-trigger]');
    const panel = document.getElementById('analyze-browser-panel');

    trigger.click();
    await vi.runAllTimersAsync();
    expect(panel.hidden).toBe(false);
    expect(globalThis.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable).toHaveBeenCalledTimes(1);

    panel.querySelector('[data-action="close"]').click();
    await vi.runAllTimersAsync();
    expect(panel.hidden).toBe(true);

    trigger.click();
    await vi.runAllTimersAsync();
    expect(globalThis.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable).toHaveBeenCalledTimes(1);
    expect(panel.hidden).toBe(false);
  });

  it('handles browser capability fallback paths', async () => {
    vi.useFakeTimers();
    buildAnalyzeDom();

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    // Ensure transport probes do not accidentally pass due prior test state.
    delete navigator.usb;
    delete navigator.hid;
    delete navigator.nfc;
    delete navigator.bluetooth;
    delete navigator.serial;

    Object.defineProperty(navigator, 'userAgentData', {
      configurable: true,
      value: {
        brands: [{ brand: 'Chromium', version: '123.0.0.0' }],
        platform: 'Linux',
        getHighEntropyValues: vi.fn(async () => {
          throw new Error('entropy unavailable');
        }),
      },
    });

    globalThis.PublicKeyCredential = {
      isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => {
        throw new Error('uv unavailable');
      }),
      // intentionally omit isConditionalMediationAvailable to hit fallback branch
    };

    const { initializeAnalyzeBrowser } = await loadAnalyzeBrowser();
    initializeAnalyzeBrowser();

    document.querySelector('[data-analyze-browser-trigger]').click();
    await vi.runAllTimersAsync();

    const panel = document.getElementById('analyze-browser-panel');
    expect(panel.hidden).toBe(false);

    const transportsText = panel.querySelector('[data-role="transport-list"]').textContent;
    expect(transportsText).toContain('No supported transports detected');

    const crossPlatformValue = panel
      .querySelector('[data-feature="cross-platform"] .analyze-browser-panel__feature-value');
    expect(crossPlatformValue.dataset.status).toBe('unknown');
    expect(crossPlatformValue.textContent).toBe('Unknown');

    expect(warnSpy).toHaveBeenCalled();

    warnSpy.mockRestore();
  });

  it('normalizes major browser brands and falls back to UA parsing when client hints are unavailable', async () => {
    vi.useFakeTimers();

    globalThis.PublicKeyCredential = {
      isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => false),
      isConditionalMediationAvailable: vi.fn(async () => false),
    };

    const brandCases = [
      { brand: 'Edg', expected: 'Microsoft Edge' },
      { brand: 'Chrome', expected: 'Google Chrome' },
      { brand: 'Safari', expected: 'Safari' },
      { brand: 'Firefox', expected: 'Mozilla Firefox' },
      { brand: 'Brave', expected: 'Brave' },
    ];

    for (const { brand, expected } of brandCases) {
      buildAnalyzeDom();

      const { initializeAnalyzeBrowser } = await loadAnalyzeBrowser();
      initializeAnalyzeBrowser();

      Object.defineProperty(navigator, 'userAgent', {
        configurable: true,
        value: 'CustomAgent/1.0',
      });

      Object.defineProperty(navigator, 'userAgentData', {
        configurable: true,
        value: {
          brands: [{ brand: 'Not A Brand', version: '99' }, { brand, version: '120.0.0.0' }],
          platform: 'TestOS',
          getHighEntropyValues: vi.fn(async () => ({
            platform: 'TestOS',
            fullVersionList: [{ brand, version: '120.1.2.3' }],
          })),
        },
      });

      const trigger = document.querySelector('[data-analyze-browser-trigger]');
      trigger.click();
      await vi.runAllTimersAsync();

      expect(document.getElementById('analyze-browser-name').textContent).toBe(expected);
    }

    buildAnalyzeDom();

    const { initializeAnalyzeBrowser } = await loadAnalyzeBrowser();
    initializeAnalyzeBrowser();

    Object.defineProperty(navigator, 'userAgent', {
      configurable: true,
      value: 'Mozilla/5.0 Firefox/124.0',
    });
    Object.defineProperty(navigator, 'userAgentData', {
      configurable: true,
      value: {
        brands: [{ brand: 'Firefox', version: '124.0.0.0' }],
        platform: 'Linux',
        // No getHighEntropyValues: should use fallback brand selection path.
      },
    });

    const trigger = document.querySelector('[data-analyze-browser-trigger]');
    trigger.click();
    await vi.runAllTimersAsync();

    expect(document.getElementById('analyze-browser-name').textContent).toBe('Mozilla Firefox');
    expect(document.getElementById('analyze-browser-version').textContent).toBe('124.0.0.0');
  });

  it('normalizes system names across major browser platform hints', async () => {
    vi.useFakeTimers();

    const cases = [
      {
        ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15',
        platform: 'MacIntel',
        maxTouchPoints: 0,
        expectedSystem: 'macOS',
      },
      {
        ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Version/17.4 Mobile/15E148 Safari/604.1',
        platform: 'iPhone',
        maxTouchPoints: 5,
        expectedSystem: 'iOS',
      },
      {
        ua: 'Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Version/17.4 Mobile/15E148 Safari/604.1',
        platform: 'MacIntel',
        maxTouchPoints: 5,
        expectedSystem: 'iPadOS',
      },
      {
        ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
        platform: 'Win32',
        maxTouchPoints: 0,
        expectedSystem: 'Windows',
      },
      {
        ua: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36',
        platform: 'Linux x86_64',
        maxTouchPoints: 0,
        expectedSystem: 'Linux',
      },
    ];

    for (const platformCase of cases) {
      buildAnalyzeDom();

      const { initializeAnalyzeBrowser } = await loadAnalyzeBrowser();
      initializeAnalyzeBrowser();

      Object.defineProperty(navigator, 'userAgent', {
        configurable: true,
        value: platformCase.ua,
      });
      Object.defineProperty(navigator, 'platform', {
        configurable: true,
        value: platformCase.platform,
      });
      Object.defineProperty(navigator, 'maxTouchPoints', {
        configurable: true,
        value: platformCase.maxTouchPoints,
      });
      Object.defineProperty(navigator, 'userAgentData', {
        configurable: true,
        value: undefined,
      });

      globalThis.PublicKeyCredential = {
        isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => false),
        isConditionalMediationAvailable: vi.fn(async () => false),
      };

      const trigger = document.querySelector('[data-analyze-browser-trigger]');
      trigger.click();
      await vi.runAllTimersAsync();

      expect(document.getElementById('analyze-browser-system').textContent).toBe(platformCase.expectedSystem);
    }
  });

  it('handles sparse panel markup and close interactions before panel is open', async () => {
    vi.useFakeTimers();
    buildAnalyzeDom();

    // Remove one feature container entirely and strip the value element from another.
    document.querySelector('[data-feature="platform"]').remove();
    document
      .querySelector('[data-feature="cross-platform"] .analyze-browser-panel__feature-value')
      .remove();

    // Remove transport list so rendering function no-ops safely.
    document.querySelector('[data-role="transport-list"]').remove();

    globalThis.PublicKeyCredential = {
      isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => false),
      isConditionalMediationAvailable: vi.fn(async () => false),
    };

    const { initializeAnalyzeBrowser } = await loadAnalyzeBrowser();
    initializeAnalyzeBrowser();

    const panel = document.getElementById('analyze-browser-panel');
    const closeButton = panel.querySelector('[data-action="close"]');
    const trigger = document.querySelector('[data-analyze-browser-trigger]');

    // Exercise close path when panel is not currently open.
    closeButton.click();
    await vi.runAllTimersAsync();

    // Exercise click delegation guard for non-HTMLElement targets.
    const textNode = document.createTextNode('text-node-click-target');
    panel.appendChild(textNode);
    textNode.dispatchEvent(new MouseEvent('click', { bubbles: true }));

    trigger.click();
    await vi.runAllTimersAsync();

    expect(panel.hidden).toBe(false);
    expect(panel.classList.contains('is-open')).toBe(true);
  });

  it('falls back safely when analysis throws and ignores concurrent trigger clicks', async () => {
    vi.useFakeTimers();
    buildAnalyzeDom();

    const badUaData = { platform: 'ErrOS' };
    Object.defineProperty(badUaData, 'brands', {
      configurable: true,
      get() {
        throw new Error('brand access failed');
      },
    });

    Object.defineProperty(navigator, 'userAgentData', {
      configurable: true,
      value: badUaData,
    });

    globalThis.PublicKeyCredential = {
      isConditionalMediationAvailable: vi.fn(async () => false),
    };

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const { initializeAnalyzeBrowser } = await loadAnalyzeBrowser();
    initializeAnalyzeBrowser();

    const trigger = document.querySelector('[data-analyze-browser-trigger]');

    trigger.click();
    trigger.click(); // should be ignored while first run is active
    await vi.runAllTimersAsync();

    expect(trigger.disabled).toBe(false);
    expect(document.getElementById('analyze-browser-name').textContent).toMatch(/Google Chrome|Chromium|Unknown Browser/);
    expect(document.getElementById('analyze-browser-system').textContent).toMatch(
      /Unknown System|Linux|Windows|macOS|iOS|iPadOS|Android|ChromeOS|BSD/,
    );
    expect(warnSpy).toHaveBeenCalled();

    warnSpy.mockRestore();
  });
});
