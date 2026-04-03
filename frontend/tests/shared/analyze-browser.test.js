import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../static/scripts/shared/ui.js', () => ({
  updateGlobalScrollLock: vi.fn(),
}));

import { updateGlobalScrollLock } from '../../static/scripts/shared/ui.js';

async function loadAnalyzeBrowser() {
  vi.resetModules();
  return import('../../static/scripts/shared/analyze-browser.js');
}

function buildAnalyzeDom({ coseSource = '/cose.json' } = {}) {
  document.body.innerHTML = `
    <button data-analyze-browser-trigger>Analyze</button>
    <div id="analyze-browser-loader" hidden aria-hidden="true"></div>
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
      <table data-role="cose-table" data-cose-source="${coseSource}">
        <thead>
          <tr data-role="cose-table-header-row"><th>Algorithm</th></tr>
        </thead>
        <tbody data-role="cose-table-body"></tbody>
      </table>
    </div>
  `;
}

function mockSuccessfulFetchResponse() {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      browsers: [
        { key: 'chrome', label: 'Chrome', subtitle: 'desktop' },
      ],
      algorithms: [
        {
          id: -7,
          label: 'ES256',
          note: 'recommended',
          support: {
            chrome: { status: 'yes', note: 'default' },
          },
        },
      ],
    }),
  };
}

describe('analyze-browser', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('is a no-op when required DOM nodes are missing', async () => {
    const { initializeAnalyzeBrowser } = await loadAnalyzeBrowser();
    document.body.innerHTML = '<div></div>';

    expect(() => initializeAnalyzeBrowser()).not.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('initializes, gathers analysis, renders COSE table, and opens/closes panel', async () => {
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

    fetch.mockResolvedValue(mockSuccessfulFetchResponse());

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
    expect(values[2].status).toBe('false');

    const transportText = panel.querySelector('[data-role="transport-list"]').textContent;
    expect(transportText).toContain('Internal');
    expect(transportText).toContain('USB');
    expect(transportText).toContain('HID');

    const coseTable = panel.querySelector('[data-role="cose-table"]');
    expect(coseTable.dataset.rendered).toBe('true');
    expect(panel.querySelector('[data-role="cose-table-body"]').textContent).toContain('ES256');

    panel.querySelector('[data-action="close"]').click();
    await vi.runAllTimersAsync();
    expect(panel.hidden).toBe(true);

    trigger.click();
    await vi.runAllTimersAsync();
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await vi.runAllTimersAsync();
    expect(panel.hidden).toBe(true);

    expect(updateGlobalScrollLock).toHaveBeenCalled();
  });

  it('handles COSE fetch failures and browser capability fallback paths', async () => {
    vi.useFakeTimers();
    buildAnalyzeDom({ coseSource: '/broken.json' });

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

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

    fetch.mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({}),
    });

    const { initializeAnalyzeBrowser } = await loadAnalyzeBrowser();
    initializeAnalyzeBrowser();

    document.querySelector('[data-analyze-browser-trigger]').click();
    await vi.runAllTimersAsync();

    const panel = document.getElementById('analyze-browser-panel');
    expect(panel.hidden).toBe(false);
    expect(panel.querySelector('[data-role="cose-table-body"]').textContent).toContain(
      'No COSE algorithm data available.',
    );

    const crossPlatformValue = panel
      .querySelector('[data-feature="cross-platform"] .analyze-browser-panel__feature-value');
    expect(crossPlatformValue.dataset.status).toBe('unknown');
    expect(crossPlatformValue.textContent).toBe('Unknown');

    expect(warnSpy).toHaveBeenCalled();
    expect(errorSpy).toHaveBeenCalled();

    warnSpy.mockRestore();
    errorSpy.mockRestore();
  });
});
