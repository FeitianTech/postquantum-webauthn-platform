import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { CHROMIUM_152_CAPABILITIES } from '../browser/chromium-152.js';
import { IDENTITY_MATRIX } from '../browser/identity-matrix.js';

vi.mock('../../../../frontend/static/scripts/shared/ui/core.js', () => ({
  updateGlobalScrollLock: vi.fn(),
}));

import { updateGlobalScrollLock } from '../../../../frontend/static/scripts/shared/ui/core.js';

// vitest runs from the repository root.
const PANEL_TEMPLATE = readFileSync('frontend/templates/shared/analyze-browser.html', 'utf8');

const CHROMIUM_ONLY = IDENTITY_MATRIX.find((entry) => entry.label === 'Chromium-only brand list').navigator;
const IPHONE_SAFARI = IDENTITY_MATRIX.find((entry) => entry.label === 'Safari on iPhone').navigator;

const installed = [];

function install(target, name, value) {
  installed.push([target, name]);
  Object.defineProperty(target, name, { configurable: true, writable: true, value });
}

function makePublicKeyCredential(statics = {}) {
  function PublicKeyCredential() {}
  Object.assign(PublicKeyCredential, {
    isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => true),
    isConditionalMediationAvailable: vi.fn(async () => true),
    getClientCapabilities: vi.fn(async () => ({ ...CHROMIUM_152_CAPABILITIES })),
    parseCreationOptionsFromJSON() {},
    parseRequestOptionsFromJSON() {},
    ...statics,
  });
  PublicKeyCredential.prototype.toJSON = function toJSON() {};
  return PublicKeyCredential;
}

// Makes jsdom's window and navigator look like the browser described.
function installBrowser(options = {}) {
  const identity = options.identity ?? CHROMIUM_ONLY;
  const publicKeyCredential = 'publicKeyCredential' in options ? options.publicKeyCredential : makePublicKeyCredential();
  const secure = 'secure' in options ? options.secure : true;
  for (const name of ['userAgent', 'platform', 'maxTouchPoints']) {
    install(navigator, name, identity[name]);
  }
  install(navigator, 'userAgentData', identity.userAgentData);
  install(navigator, 'brave', identity.brave);
  install(navigator, 'credentials', { create() {}, get() {} });
  install(window, 'isSecureContext', secure);
  install(window, 'PublicKeyCredential', publicKeyCredential);
  return publicKeyCredential;
}

async function loadAnalyzeBrowser() {
  vi.resetModules();
  return import('../../../../frontend/static/scripts/shared/browser/analyze.js');
}

function buildAnalyzeDom() {
  document.body.innerHTML = `<button data-analyze-browser-trigger>Analyze Browser</button>${PANEL_TEMPLATE}`;
  return {
    trigger: document.querySelector('[data-analyze-browser-trigger]'),
    panel: document.getElementById('analyze-browser-panel'),
  };
}

async function openAnalyzedPanel() {
  const dom = buildAnalyzeDom();
  const { initializeAnalyzeBrowser } = await loadAnalyzeBrowser();
  initializeAnalyzeBrowser();
  dom.trigger.click();
  await vi.runAllTimersAsync();
  return dom;
}

function identityShown(panel) {
  return Object.fromEntries(
    [...panel.querySelectorAll('[data-identity]')].map((item) => [
      item.dataset.identity,
      {
        value: item.querySelector('[data-role="value"]').textContent,
        source: item.querySelector('[data-role="source"]').textContent,
      },
    ]),
  );
}

const SECTION_OF = {
  userVerifyingPlatformAuthenticator: 'authenticator-facts',
  hybridTransport: 'authenticator-facts',
};

// A fact as the WebAuthn or Authenticators section shows it, or as `container` does.
function factShown(panel, id, container = panel.querySelector(`[data-role="${SECTION_OF[id] ?? 'webauthn-facts'}"]`)) {
  const item = container.querySelector(`[data-fact="${id}"]`);
  const value = item.querySelector('.analyze-browser-panel__feature-value');
  return {
    state: value.dataset.state,
    text: value.textContent,
    note: item.querySelector('.analyze-browser-panel__feature-note')?.textContent ?? null,
  };
}

describe('analyze-browser panel', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    // Each test initializes a panel with its own document listener; close them all so
    // none still traps Tab in a later test.
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    while (installed.length > 0) {
      const [target, name] = installed.pop();
      delete target[name];
    }
  });

  it('is a no-op when required DOM nodes are missing', async () => {
    const { initializeAnalyzeBrowser } = await loadAnalyzeBrowser();
    document.body.innerHTML = '<div></div>';

    expect(() => initializeAnalyzeBrowser()).not.toThrow();
  });

  it("reports the tech lead's Chromium-only browser as what it says it is", async () => {
    installBrowser();
    const { panel, trigger } = await openAnalyzedPanel();

    expect(panel.hidden).toBe(false);
    expect(panel.classList.contains('is-open')).toBe(true);
    expect(trigger.disabled).toBe(false);
    expect(identityShown(panel)).toEqual({
      name: { value: 'Chromium-based browser', source: 'from User-Agent Client Hints' },
      version: { value: '152.0.7977.130', source: 'from User-Agent Client Hints' },
      engine: { value: 'Blink', source: 'from User-Agent Client Hints' },
      system: { value: 'macOS', source: 'from User-Agent Client Hints' },
    });
    expect(panel.querySelector('[data-role="apple-webkit-note"]').hidden).toBe(true);

    for (const id of [
      'secureContext',
      'webauthnApi',
      'conditionalMediation',
      'parseCreationOptionsFromJSON',
      'parseRequestOptionsFromJSON',
      'toJSON',
      'userVerifyingPlatformAuthenticator',
      'hybridTransport',
    ]) {
      expect(factShown(panel, id), id).toEqual({ state: 'yes', text: 'Yes', note: null });
    }

    const capabilities = panel.querySelector('[data-role="client-capabilities"]');
    const groupKeys = (kind) =>
      [...capabilities.querySelectorAll(`[data-group="${kind}"] [data-fact]`)].map((item) => item.dataset.fact);
    expect(groupKeys('defined')).toEqual([
      'conditionalCreate',
      'conditionalGet',
      'hybridTransport',
      'passkeyPlatformAuthenticator',
      'userVerifyingPlatformAuthenticator',
      'relatedOrigins',
      'signalAllAcceptedCredentials',
      'signalCurrentUserDetails',
      'signalUnknownCredential',
    ]);
    expect(groupKeys('extension')).toHaveLength(14);
    expect(groupKeys('unrecognised')).toEqual(['immediateGet']);
    expect(capabilities.querySelectorAll('[data-fact]')).toHaveLength(24);
    expect(factShown(panel, 'extension:cmtgKey', capabilities)).toMatchObject({ state: 'no', text: 'No' });
    expect(capabilities.querySelector('[data-fact="extension:prf"]').textContent).toContain('prf');
    expect(capabilities.querySelector('[data-fact="conditionalGet"]').textContent).toContain(
      'Passkey autofill (conditional get)',
    );

    const text = panel.textContent.replace(/\s+/g, ' ');
    expect(text).not.toMatch(/\bUnknown\b/);
    expect(text).not.toMatch(/Supported Transports|Cable \/ Serial|\bHID\b|\bBLE\b/);
    expect(text).toContain('USB, NFC and Bluetooth security keys are handled by the browser and the operating system');
    expect(text).toMatch(/-48 ML-DSA-44, -49 ML-DSA-65, -50 ML-DSA-87/);
    expect(updateGlobalScrollLock).toHaveBeenCalled();
  });

  it('says that every browser on iOS is WebKit with Safari\'s WebAuthn', async () => {
    installBrowser({ identity: IPHONE_SAFARI, publicKeyCredential: makePublicKeyCredential({ getClientCapabilities: undefined }) });
    const { panel } = await openAnalyzedPanel();

    expect(identityShown(panel)).toMatchObject({
      name: { value: 'Safari', source: 'from the user-agent string, which browsers reduce and can be spoofed' },
      engine: { value: 'WebKit', source: 'every browser on iOS and iPadOS uses WebKit' },
      system: { value: 'iOS' },
    });
    const note = panel.querySelector('[data-role="apple-webkit-note"]');
    expect(note.hidden).toBe(false);
    expect(note.textContent.replace(/\s+/g, ' ')).toContain("so WebAuthn here is Safari's, whichever browser this is.");
  });

  it('says what the browser does not report instead of guessing', async () => {
    installBrowser({ identity: { userAgent: 'CustomAgent', platform: '', maxTouchPoints: 0 } });
    const { panel } = await openAnalyzedPanel();

    for (const field of ['name', 'version', 'engine', 'system']) {
      expect(identityShown(panel)[field], field).toEqual({
        value: 'Not reported',
        source: 'the browser does not report this',
      });
    }
  });

  it('shows each of the four states with its words, and why when it could not be determined', async () => {
    installBrowser({
      secure: true,
      publicKeyCredential: makePublicKeyCredential({
        isConditionalMediationAvailable: async () => false,
        isUserVerifyingPlatformAuthenticatorAvailable: async () => {
          throw new DOMException('The operation is insecure.', 'SecurityError');
        },
        parseCreationOptionsFromJSON: undefined,
      }),
    });
    const { panel } = await openAnalyzedPanel();

    expect(factShown(panel, 'secureContext')).toEqual({ state: 'yes', text: 'Yes', note: null });
    expect(factShown(panel, 'conditionalMediation')).toEqual({ state: 'no', text: 'No', note: null });
    expect(factShown(panel, 'parseCreationOptionsFromJSON')).toEqual({
      state: 'unavailable',
      text: 'Not available in this browser',
      note: null,
    });
    expect(factShown(panel, 'userVerifyingPlatformAuthenticator')).toEqual({
      state: 'undetermined',
      text: 'Could not be determined',
      note: 'SecurityError: The operation is insecure.',
    });
  });

  it('explains a page that is not a secure context', async () => {
    installBrowser({ secure: false, publicKeyCredential: undefined });
    const { panel } = await openAnalyzedPanel();

    expect(factShown(panel, 'secureContext')).toEqual({
      state: 'no',
      text: 'No',
      note: 'WebAuthn works only over HTTPS or on localhost.',
    });
    expect(factShown(panel, 'webauthnApi')).toMatchObject({
      state: 'unavailable',
      note: 'Missing: PublicKeyCredential. Browsers offer WebAuthn only in a secure context.',
    });
    expect(factShown(panel, 'hybridTransport')).toMatchObject({
      state: 'unavailable',
      note: 'The WebAuthn API is not available on this page.',
    });
  });

  it('says getClientCapabilities is a Level 3 feature this browser does not offer', async () => {
    installBrowser({ publicKeyCredential: makePublicKeyCredential({ getClientCapabilities: undefined }) });
    const { panel } = await openAnalyzedPanel();

    const capabilities = panel.querySelector('[data-role="client-capabilities"]');
    expect(capabilities.querySelector('[data-state]').textContent).toBe('Not available in this browser');
    expect(capabilities.textContent).toContain(
      'getClientCapabilities() is a WebAuthn Level 3 feature this browser does not offer.',
    );
    expect(factShown(panel, 'hybridTransport')).toMatchObject({ state: 'unavailable', text: 'Not available in this browser' });
  });

  it('shows why getClientCapabilities could not be read when it throws', async () => {
    installBrowser({
      publicKeyCredential: makePublicKeyCredential({
        getClientCapabilities: async () => {
          throw new DOMException('Document is not focused.', 'NotAllowedError');
        },
      }),
    });
    const { panel } = await openAnalyzedPanel();

    const capabilities = panel.querySelector('[data-role="client-capabilities"]');
    expect(capabilities.querySelector('[data-state]').dataset.state).toBe('undetermined');
    expect(capabilities.textContent).toContain('Could not be determined');
    expect(capabilities.textContent).toContain('NotAllowedError: Document is not focused.');
  });

  it('shows capability keys it does not recognise verbatim, and names the defined ones left out', async () => {
    installBrowser({
      publicKeyCredential: makePublicKeyCredential({
        getClientCapabilities: async () => ({ 'future:thing': true, 'extension:prf': true, conditionalGet: 'soon' }),
      }),
    });
    const { panel } = await openAnalyzedPanel();

    const capabilities = panel.querySelector('[data-role="client-capabilities"]');
    const unrecognised = capabilities.querySelector('[data-group="unrecognised"]');
    expect(unrecognised.querySelector('[data-fact="future:thing"]').textContent).toContain('future:thing');
    expect(factShown(panel, 'conditionalGet', capabilities)).toMatchObject({
      state: 'undetermined',
      note: 'The browser answered "soon", not true or false.',
    });
    expect(capabilities.textContent).toContain('Left out by the browser, so not known: conditionalCreate, hybridTransport,');
    expect(factShown(panel, 'hybridTransport')).toMatchObject({
      state: 'undetermined',
      note: 'getClientCapabilities() did not include hybridTransport, so its availability is not known.',
    });
  });

  it('says so when the browser returns no capabilities', async () => {
    installBrowser({ publicKeyCredential: makePublicKeyCredential({ getClientCapabilities: async () => ({}) }) });
    const { panel } = await openAnalyzedPanel();

    expect(panel.querySelector('[data-role="client-capabilities"]').textContent).toContain(
      'The browser returned no capabilities.',
    );
  });

  it('asks once per page and reuses the answers', async () => {
    const publicKeyCredential = installBrowser();
    const { panel, trigger } = await openAnalyzedPanel();
    expect(publicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable).toHaveBeenCalledTimes(1);

    panel.querySelector('.mds-custom-panel__close').click();
    expect(panel.hidden).toBe(true);

    trigger.click();
    await vi.runAllTimersAsync();
    expect(panel.hidden).toBe(false);
    expect(publicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable).toHaveBeenCalledTimes(1);
  });

  it('ignores a second click while the first analysis runs', async () => {
    const publicKeyCredential = installBrowser();
    const { trigger } = buildAnalyzeDom();
    const { initializeAnalyzeBrowser } = await loadAnalyzeBrowser();
    initializeAnalyzeBrowser();

    trigger.click();
    expect(trigger.disabled).toBe(true);
    trigger.click();
    await vi.runAllTimersAsync();

    expect(trigger.disabled).toBe(false);
    expect(publicKeyCredential.getClientCapabilities).toHaveBeenCalledTimes(1);
  });

  describe('Copy report', () => {
    async function copyWith(clipboard) {
      installBrowser();
      install(navigator, 'clipboard', clipboard);
      const { panel } = await openAnalyzedPanel();
      panel.querySelector('[data-action="copy-report"]').click();
      await vi.runAllTimersAsync();
      return {
        panel,
        status: panel.querySelector('[data-role="copy-status"]'),
        fallback: panel.querySelector('[data-role="report-text"]'),
      };
    }

    it('copies the raw findings as JSON and says so in a live region', async () => {
      const writeText = vi.fn(async () => {});
      const { status, fallback } = await copyWith({ writeText });

      expect(status.getAttribute('role')).toBe('status');
      expect(status.getAttribute('aria-live')).toBe('polite');
      expect(status.textContent).toBe('Report copied to the clipboard.');
      expect(status.dataset.outcome).toBe('copied');
      expect(fallback.hidden).toBe(true);
      expect(writeText).toHaveBeenCalledTimes(1);

      const report = JSON.parse(writeText.mock.calls[0][0]);
      expect(report).toMatchObject({
        report: 'Analyze Browser',
        page: 'http://localhost',
        identity: {
          name: 'Chromium-based browser',
          version: '152.0.7977.130',
          engine: 'Blink',
          system: 'macOS',
          sources: { name: 'client-hints', version: 'client-hints', engine: 'client-hints', system: 'client-hints' },
          inputs: {
            userAgent: CHROMIUM_ONLY.userAgent,
            platform: 'MacIntel',
            maxTouchPoints: 0,
            userAgentData: {
              brands: [{ brand: 'Not?A_Brand', version: '24' }, { brand: 'Chromium', version: '152' }],
              mobile: false,
              platform: 'macOS',
            },
            highEntropyValues: {
              fullVersionList: [
                { brand: 'Not?A_Brand', version: '24.0.0.0' },
                { brand: 'Chromium', version: '152.0.7977.130' },
              ],
              platformVersion: '15.0.0',
            },
            brave: null,
          },
        },
        webauthn: {
          facts: {
            secureContext: { state: 'yes' },
            webauthnApi: { state: 'yes' },
            conditionalMediation: { state: 'yes' },
            parseCreationOptionsFromJSON: { state: 'yes' },
            parseRequestOptionsFromJSON: { state: 'yes' },
            toJSON: { state: 'yes' },
            userVerifyingPlatformAuthenticator: { state: 'yes' },
            hybridTransport: { state: 'yes' },
          },
          clientCapabilities: { state: 'yes', returned: CHROMIUM_152_CAPABILITIES, omitted: [] },
        },
      });
      expect(Number.isNaN(Date.parse(report.generatedAt))).toBe(false);
    });

    it('says why copying failed and shows the report selected, to copy by hand', async () => {
      const writeText = vi.fn(async () => {
        throw new DOMException('Write permission denied.', 'NotAllowedError');
      });
      const { status, fallback } = await copyWith({ writeText });

      expect(status.dataset.outcome).toBe('failed');
      expect(status.textContent).toBe(
        'Could not copy the report: NotAllowedError: Write permission denied. The report is below, selected, to copy by hand.',
      );
      expect(fallback.hidden).toBe(false);
      expect(document.activeElement).toBe(fallback);
      expect(fallback.selectionStart).toBe(0);
      expect(fallback.selectionEnd).toBe(fallback.value.length);
      expect(JSON.parse(fallback.value).identity.name).toBe('Chromium-based browser');
    });

    it('says the clipboard is not available when the page has none, and hides the fallback after a later success', async () => {
      const { panel, status, fallback } = await copyWith(undefined);

      expect(status.textContent).toBe(
        'Could not copy the report: the clipboard is not available on this page. The report is below, selected, to copy by hand.',
      );
      expect(fallback.hidden).toBe(false);

      install(navigator, 'clipboard', { writeText: vi.fn(async () => {}) });
      panel.querySelector('[data-action="copy-report"]').click();
      await vi.runAllTimersAsync();
      expect(status.textContent).toBe('Report copied to the clipboard.');
      expect(fallback.hidden).toBe(true);
    });
  });

  describe('as a dialog', () => {
    function pressTab(shiftKey = false) {
      const event = new KeyboardEvent('keydown', { key: 'Tab', shiftKey, bubbles: true, cancelable: true });
      document.activeElement.dispatchEvent(event);
      return event.defaultPrevented;
    }

    it('is a labelled modal dialog that takes focus when it opens', async () => {
      installBrowser();
      const { panel } = await openAnalyzedPanel();
      const dialog = panel.querySelector('[role="dialog"]');

      expect(dialog.getAttribute('aria-modal')).toBe('true');
      expect(document.getElementById(dialog.getAttribute('aria-labelledby')).textContent).toBe('Browser Analysis');
      expect(document.activeElement).toBe(dialog);
    });

    it('gives focus back to the Analyze Browser button when it closes, by Escape or by the close button', async () => {
      installBrowser();
      const { panel, trigger } = await openAnalyzedPanel();

      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
      expect(panel.hidden).toBe(true);
      expect(document.activeElement).toBe(trigger);

      trigger.click();
      await vi.runAllTimersAsync();
      expect(document.activeElement).toBe(panel.querySelector('[role="dialog"]'));
      panel.querySelector('.mds-custom-panel__close').click();
      expect(document.activeElement).toBe(trigger);
    });

    it('keeps Tab and Shift+Tab inside the dialog', async () => {
      installBrowser();
      const { panel } = await openAnalyzedPanel();
      const close = panel.querySelector('.mds-custom-panel__close');
      const copy = panel.querySelector('[data-action="copy-report"]');

      // From the dialog itself: Shift+Tab goes to the last control, Tab to the first.
      expect(pressTab(true)).toBe(true);
      expect(document.activeElement).toBe(copy);
      expect(pressTab()).toBe(true);
      expect(document.activeElement).toBe(close);
      expect(pressTab(true)).toBe(true);
      expect(document.activeElement).toBe(copy);

      // Between the first and the last, the browser moves focus as usual.
      close.focus();
      expect(pressTab()).toBe(false);
      copy.focus();
      expect(pressTab(true)).toBe(false);

      // Focus that has left the dialog is brought back.
      document.body.focus();
      const outside = document.createElement('button');
      document.body.appendChild(outside);
      outside.focus();
      expect(pressTab()).toBe(true);
      expect(document.activeElement).toBe(close);
    });

    it('counts the report text among the controls once it is shown', async () => {
      installBrowser();
      install(navigator, 'clipboard', undefined);
      const { panel } = await openAnalyzedPanel();
      panel.querySelector('[data-action="copy-report"]').click();
      await vi.runAllTimersAsync();

      const fallback = panel.querySelector('[data-role="report-text"]');
      expect(document.activeElement).toBe(fallback);
      expect(pressTab()).toBe(true);
      expect(document.activeElement).toBe(panel.querySelector('.mds-custom-panel__close'));
    });

    it('leaves Tab alone while it is closed', async () => {
      installBrowser();
      buildAnalyzeDom();
      const { initializeAnalyzeBrowser } = await loadAnalyzeBrowser();
      initializeAnalyzeBrowser();

      document.querySelector('[data-analyze-browser-trigger]').focus();
      expect(pressTab()).toBe(false);
    });
  });

  it('closes from the close button, the backdrop and Escape, and ignores other clicks', async () => {
    installBrowser();
    const { panel, trigger } = await openAnalyzedPanel();
    const content = panel.querySelector('.analyze-browser-panel__content');

    content.scrollTop = 128;
    panel.querySelector('.analyze-browser-panel__heading').click();
    panel.appendChild(document.createTextNode('text')).dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(panel.hidden).toBe(false);

    panel.querySelector('.mds-custom-panel__close svg').dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(panel.hidden).toBe(true);
    expect(panel.getAttribute('aria-hidden')).toBe('true');
    expect(content.scrollTop).toBe(0);

    trigger.click();
    await vi.runAllTimersAsync();
    panel.querySelector('.mds-custom-panel__backdrop').click();
    expect(panel.hidden).toBe(true);

    trigger.click();
    await vi.runAllTimersAsync();
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    expect(panel.hidden).toBe(true);

    // Escape with the panel closed does nothing.
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    expect(panel.hidden).toBe(true);
  });
});
