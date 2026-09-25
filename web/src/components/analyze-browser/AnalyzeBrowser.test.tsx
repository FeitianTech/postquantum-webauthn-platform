// The Analyze Browser panel in the new UI, held to what the current panel shows
// and does: every case of tests/frontend/shared/ui/analyze-browser.test.js, over
// the same fixtures (imported, not copied). The AB-… ids are the items of
// docs/ui-parity/analyze-browser.md.
import { CHROMIUM_152_CAPABILITIES } from '@legacy-tests/shared/browser/chromium-152.js';
import { IDENTITY_MATRIX } from '@legacy-tests/shared/browser/identity-matrix.js';
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { AppShell } from '@/components/shell/AppShell';
import { renderPage } from '@/test/page';

type Navigatorish = Record<string, unknown>;
const matrixEntry = (label: string) =>
  (IDENTITY_MATRIX as Array<{ label: string; navigator: Navigatorish }>).find((entry) => entry.label === label)!.navigator;
const CHROMIUM_ONLY = matrixEntry('Chromium-only brand list');
const IPHONE_SAFARI = matrixEntry('Safari on iPhone');

const installed: Array<[object, string]> = [];

function install(target: object, name: string, value: unknown) {
  installed.push([target, name]);
  Object.defineProperty(target, name, { configurable: true, writable: true, value });
}

function makePublicKeyCredential(statics: Record<string, unknown> = {}) {
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
  return PublicKeyCredential as unknown as Record<string, ReturnType<typeof vi.fn>>;
}

// Makes jsdom's window and navigator look like the browser described.
function installBrowser(options: { identity?: Navigatorish; publicKeyCredential?: unknown; secure?: boolean } = {}) {
  const identity = options.identity ?? CHROMIUM_ONLY;
  const publicKeyCredential = 'publicKeyCredential' in options ? options.publicKeyCredential : makePublicKeyCredential();
  for (const name of ['userAgent', 'platform', 'maxTouchPoints']) install(navigator, name, identity[name]);
  install(navigator, 'userAgentData', identity.userAgentData);
  install(navigator, 'brave', identity.brave);
  install(navigator, 'credentials', { create() {}, get() {} });
  install(window, 'isSecureContext', 'secure' in options ? options.secure : true);
  install(window, 'PublicKeyCredential', publicKeyCredential);
  return publicKeyCredential as Record<string, ReturnType<typeof vi.fn>>;
}

afterEach(() => {
  while (installed.length > 0) {
    const [target, name] = installed.pop()!;
    Reflect.deleteProperty(target, name);
  }
  vi.restoreAllMocks();
});

const trigger = () => screen.getByRole('button', { name: 'Analyze Browser' });
const panelRoot = () => document.getElementById('analyze-browser-panel')!;

async function openPanel() {
  renderPage(<AppShell />);
  await userEvent.click(trigger());
  const dialog = await screen.findByRole('dialog', { name: 'Browser Analysis' });
  await waitFor(() => expect(dialog).toHaveFocus());
  return dialog;
}

function identityShown(dialog: HTMLElement) {
  return Object.fromEntries(
    ['name', 'version', 'engine', 'system'].map((field) => {
      const item = dialog.querySelector(`[data-item="${field}"]`)!;
      return [
        field,
        {
          label: item.querySelector('dt')!.textContent,
          value: item.querySelector('[data-role="value"]')!.textContent,
          source: item.querySelector('[data-role="hint"]')!.textContent,
        },
      ];
    }),
  );
}

function section(dialog: HTMLElement, title: string) {
  return within(dialog).getByRole('region', { name: title });
}

// A fact as a section shows it: its state, the state's words, its note and API.
function factShown(container: HTMLElement, id: string) {
  const item = container.querySelector(`[data-fact="${id}"]`)!;
  const chip = item.querySelector('[data-state]')!;
  return {
    state: chip.getAttribute('data-state'),
    text: chip.firstElementChild!.textContent,
    note: item.querySelector('[data-role="note"]')?.textContent ?? null,
  };
}

describe('Analyze Browser, as the current panel reports it', () => {
  it("reports the tech lead's Chromium-only browser as what it says it is (AB-I1, AB-I3, AB-W1–6, AB-A1–3, AB-C4–6, AB-P1)", async () => {
    installBrowser();
    const dialog = await openPanel();

    expect(trigger()).toBeEnabled();
    expect(identityShown(dialog)).toEqual({
      name: { label: 'Browser', value: 'Chromium-based browser', source: 'from User-Agent Client Hints' },
      version: { label: 'Version', value: '152.0.7977.130', source: 'from User-Agent Client Hints' },
      engine: { label: 'Engine', value: 'Blink', source: 'from User-Agent Client Hints' },
      system: { label: 'System', value: 'macOS', source: 'from User-Agent Client Hints' },
    });
    expect(dialog.querySelector('[data-role="apple-webkit-note"]')).toBeNull();

    const webauthn = section(dialog, 'WebAuthn');
    const authenticators = section(dialog, 'Authenticators');
    for (const id of ['secureContext', 'webauthnApi', 'conditionalMediation', 'parseCreationOptionsFromJSON', 'parseRequestOptionsFromJSON', 'toJSON']) {
      expect(factShown(webauthn, id), id).toEqual({ state: 'yes', text: 'Yes', note: null });
    }
    for (const id of ['userVerifyingPlatformAuthenticator', 'hybridTransport']) {
      expect(factShown(authenticators, id), id).toEqual({ state: 'yes', text: 'Yes', note: null });
    }
    expect(within(webauthn).getByText('Passkey autofill (conditional mediation)')).toBeInTheDocument();
    expect(within(webauthn).getByText('PublicKeyCredential.isConditionalMediationAvailable()').tagName).toBe('CODE');
    expect(within(authenticators).getByText('getClientCapabilities().hybridTransport').tagName).toBe('CODE');

    const capabilities = section(dialog, 'Client capabilities');
    const groupKeys = (kind: string) =>
      [...capabilities.querySelectorAll(`[data-group="${kind}"] [data-fact]`)].map((item) => item.getAttribute('data-fact'));
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
    expect(factShown(capabilities, 'extension:cmtgKey')).toMatchObject({ state: 'no', text: 'No' });
    expect(capabilities.querySelector('[data-fact="extension:prf"] [data-role="label"]')!.textContent).toBe('prf');
    expect(capabilities.querySelector('[data-fact="extension:prf"] [data-role="api"]')).toBeNull();
    expect(capabilities.querySelector('[data-fact="immediateGet"] [data-role="api"]')).toBeNull();
    expect(capabilities.querySelector('[data-fact="conditionalGet"] [data-role="label"]')!.textContent).toBe(
      'Passkey autofill (conditional get)',
    );
    expect(capabilities.querySelector('[data-fact="conditionalGet"] [data-role="api"]')!.textContent).toBe('conditionalGet');
    expect(within(capabilities).getByRole('heading', { level: 4, name: 'Defined by WebAuthn Level 3' })).toBeInTheDocument();
    expect(within(capabilities).getByRole('heading', { level: 4, name: 'Extensions' })).toBeInTheDocument();
    expect(
      within(capabilities).getByRole('heading', { level: 4, name: 'Not recognised by this page, as the browser wrote them' }),
    ).toBeInTheDocument();
    expect(capabilities).toHaveTextContent('What PublicKeyCredential.getClientCapabilities() returned (WebAuthn Level 3).');
    expect(within(capabilities).getByText('PublicKeyCredential.getClientCapabilities()').tagName).toBe('CODE');

    const text = dialog.textContent!.replace(/\s+/g, ' ');
    expect(text).not.toMatch(/\bUnknown\b/);
    expect(text).not.toMatch(/Supported Transports|Cable \/ Serial|\bHID\b|\bBLE\b/);
    expect(text).toContain(
      'A web page cannot ask which authenticator transports a browser supports. USB, NFC and Bluetooth security keys are handled by the browser and the operating system and cannot be detected here; the only way to know is to try one.',
    );
    expect(section(dialog, 'Post-quantum').textContent!.replace(/\s+/g, ' ')).toBe(
      "Post-quantumThe browser passes the algorithms a site offers on to the authenticator, ML-DSA included (COSE -48 ML-DSA-44, -49 ML-DSA-65, -50 ML-DSA-87). Whether a credential uses ML-DSA depends on the authenticator, and only a registration can show it: offer ML-DSA in the Advanced Authentication tab and read the new credential's algorithm.",
    );
  });

  it("says that every browser on iOS is WebKit with Safari's WebAuthn (AB-I5)", async () => {
    installBrowser({ identity: IPHONE_SAFARI, publicKeyCredential: makePublicKeyCredential({ getClientCapabilities: undefined }) });
    const dialog = await openPanel();

    expect(identityShown(dialog)).toMatchObject({
      name: { value: 'Safari', source: 'from the user-agent string, which browsers reduce and can be spoofed' },
      engine: { value: 'WebKit', source: 'every browser on iOS and iPadOS uses WebKit' },
      system: { value: 'iOS' },
    });
    expect(dialog.querySelector('[data-role="apple-webkit-note"]')!.textContent!.replace(/\s+/g, ' ')).toBe(
      "On iOS and iPadOS every browser uses Apple's WebKit engine, so WebAuthn here is Safari's, whichever browser this is.",
    );
  });

  it('says what the browser does not report instead of guessing (AB-I2)', async () => {
    installBrowser({ identity: { userAgent: 'CustomAgent', platform: '', maxTouchPoints: 0 } });
    const dialog = await openPanel();

    for (const [field, shown] of Object.entries(identityShown(dialog))) {
      expect(shown, field).toMatchObject({ value: 'Not reported', source: 'the browser does not report this' });
    }
  });

  it('shows each of the four states with its words, and why when it could not be determined (AB-S1–5)', async () => {
    installBrowser({
      publicKeyCredential: makePublicKeyCredential({
        isConditionalMediationAvailable: async () => false,
        isUserVerifyingPlatformAuthenticatorAvailable: async () => {
          throw new DOMException('The operation is insecure.', 'SecurityError');
        },
        parseCreationOptionsFromJSON: undefined,
      }),
    });
    const dialog = await openPanel();
    const webauthn = section(dialog, 'WebAuthn');

    expect(factShown(webauthn, 'secureContext')).toEqual({ state: 'yes', text: 'Yes', note: null });
    expect(factShown(webauthn, 'conditionalMediation')).toEqual({ state: 'no', text: 'No', note: null });
    expect(factShown(webauthn, 'parseCreationOptionsFromJSON')).toEqual({
      state: 'unavailable',
      text: 'Not available in this browser',
      note: null,
    });
    expect(factShown(section(dialog, 'Authenticators'), 'userVerifyingPlatformAuthenticator')).toEqual({
      state: 'undetermined',
      text: 'Could not be determined',
      note: 'SecurityError: The operation is insecure.',
    });
    const marks = (state: string) => webauthn.querySelector(`[data-state="${state}"]`)!.textContent;
    expect(marks('yes')).toBe('Yes✓');
    expect(marks('no')).toBe('No✕');
    expect(marks('unavailable')).toBe('Not available in this browser–');
    expect(section(dialog, 'Authenticators').querySelector('[data-state="undetermined"]')!.textContent).toBe(
      'Could not be determined!',
    );
  });

  it('explains a page that is not a secure context (AB-W1, AB-W2, AB-A2)', async () => {
    installBrowser({ secure: false, publicKeyCredential: undefined });
    const dialog = await openPanel();

    expect(factShown(section(dialog, 'WebAuthn'), 'secureContext')).toEqual({
      state: 'no',
      text: 'No',
      note: 'WebAuthn works only over HTTPS or on localhost.',
    });
    expect(factShown(section(dialog, 'WebAuthn'), 'webauthnApi')).toMatchObject({
      state: 'unavailable',
      note: 'Missing: PublicKeyCredential. Browsers offer WebAuthn only in a secure context.',
    });
    expect(factShown(section(dialog, 'Authenticators'), 'hybridTransport')).toMatchObject({
      state: 'unavailable',
      note: 'The WebAuthn API is not available on this page.',
    });
  });

  it('says getClientCapabilities is a Level 3 feature this browser does not offer (AB-C2)', async () => {
    installBrowser({ publicKeyCredential: makePublicKeyCredential({ getClientCapabilities: undefined }) });
    const dialog = await openPanel();
    const capabilities = section(dialog, 'Client capabilities');

    const status = capabilities.querySelector('[data-role="capabilities-status"]')!;
    expect(status.querySelector('[data-state]')!.getAttribute('data-state')).toBe('unavailable');
    expect(status).toHaveTextContent('Not available in this browser');
    expect(status).toHaveTextContent('getClientCapabilities() is a WebAuthn Level 3 feature this browser does not offer.');
    expect(factShown(section(dialog, 'Authenticators'), 'hybridTransport')).toMatchObject({
      state: 'unavailable',
      text: 'Not available in this browser',
    });
  });

  it('shows why getClientCapabilities could not be read when it throws (AB-C2)', async () => {
    installBrowser({
      publicKeyCredential: makePublicKeyCredential({
        getClientCapabilities: async () => {
          throw new DOMException('Document is not focused.', 'NotAllowedError');
        },
      }),
    });
    const dialog = await openPanel();
    const capabilities = section(dialog, 'Client capabilities');

    expect(capabilities.querySelector('[data-state]')!.getAttribute('data-state')).toBe('undetermined');
    expect(capabilities).toHaveTextContent('Could not be determined');
    expect(capabilities).toHaveTextContent('NotAllowedError: Document is not focused.');
  });

  it('shows capability keys it does not recognise verbatim, and names the defined ones left out (AB-C6, AB-C8, AB-C9, AB-A2)', async () => {
    installBrowser({
      publicKeyCredential: makePublicKeyCredential({
        getClientCapabilities: async () => ({ 'future:thing': true, 'extension:prf': true, conditionalGet: 'soon' }),
      }),
    });
    const dialog = await openPanel();
    const capabilities = section(dialog, 'Client capabilities');

    expect(capabilities.querySelector('[data-group="unrecognised"] [data-fact="future:thing"]')).toHaveTextContent('future:thing');
    expect(factShown(capabilities, 'conditionalGet')).toMatchObject({
      state: 'undetermined',
      note: 'The browser answered "soon", not true or false.',
    });
    expect(capabilities).toHaveTextContent(
      'Left out by the browser, so not known: conditionalCreate, hybridTransport, passkeyPlatformAuthenticator, userVerifyingPlatformAuthenticator, relatedOrigins, signalAllAcceptedCredentials, signalCurrentUserDetails, signalUnknownCredential.',
    );
    expect(factShown(section(dialog, 'Authenticators'), 'hybridTransport')).toMatchObject({
      state: 'undetermined',
      note: 'getClientCapabilities() did not include hybridTransport, so its availability is not known.',
    });
  });

  it('says so when the browser returns no capabilities, and shows no empty group (AB-C3, AB-C7)', async () => {
    installBrowser({ publicKeyCredential: makePublicKeyCredential({ getClientCapabilities: async () => ({}) }) });
    const dialog = await openPanel();
    const capabilities = section(dialog, 'Client capabilities');

    expect(capabilities).toHaveTextContent('The browser returned no capabilities.');
    expect(capabilities.querySelector('[data-group]')).toBeNull();
  });
});

describe('the trigger', () => {
  it('asks once per page and reuses the answers (AB-T2, AB-T4)', async () => {
    const publicKeyCredential = installBrowser();
    await openPanel();
    expect(publicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable).toHaveBeenCalledTimes(1);

    await userEvent.click(screen.getByRole('button', { name: 'Close browser analysis' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Browser Analysis' })).toBeNull());
    await userEvent.click(trigger());
    expect(await screen.findByRole('dialog', { name: 'Browser Analysis' })).toBeInTheDocument();
    expect(publicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable).toHaveBeenCalledTimes(1);
  });

  it('is disabled while the analysis runs and ignores a second click (AB-T3)', async () => {
    let answer!: (value: unknown) => void;
    const publicKeyCredential = installBrowser({
      publicKeyCredential: makePublicKeyCredential({
        getClientCapabilities: vi.fn(() => new Promise((resolve) => (answer = resolve))),
      }),
    });
    renderPage(<AppShell />);

    await userEvent.click(trigger());
    expect(trigger()).toBeDisabled();
    expect(trigger().className).toContain('disabled:opacity-45');
    fireEvent.click(trigger());
    await act(async () => answer({}));

    expect(await screen.findByRole('dialog', { name: 'Browser Analysis' })).toBeInTheDocument();
    expect(trigger()).toBeEnabled();
    expect(publicKeyCredential.getClientCapabilities).toHaveBeenCalledTimes(1);
  });
});

describe('Copy report', () => {
  async function copyWith(clipboard: unknown) {
    installBrowser();
    install(navigator, 'clipboard', clipboard);
    const dialog = await openPanel();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Copy report' }));
    const status = dialog.querySelector<HTMLElement>('[data-role="copy-status"]')!;
    const fallback = dialog.querySelector<HTMLTextAreaElement>('[data-role="report-text"]')!;
    return { dialog, status, fallback };
  }

  it('copies the raw findings as JSON and says so in a live region (AB-R1–R4)', async () => {
    const writeText = vi.fn(async (_text: string) => {});
    const { status, fallback } = await copyWith({ writeText });

    expect(status).toHaveAttribute('role', 'status');
    expect(status).toHaveAttribute('aria-live', 'polite');
    await waitFor(() => expect(status).toHaveTextContent('Report copied to the clipboard.'));
    expect(status).toHaveAttribute('data-outcome', 'copied');
    expect(fallback).not.toBeVisible();
    expect(writeText).toHaveBeenCalledTimes(1);

    const text = writeText.mock.calls[0][0];
    expect(text).toContain('\n  "report": "Analyze Browser",\n  "generatedAt"');
    const report = JSON.parse(text);
    expect(Object.keys(report)).toEqual(['report', 'generatedAt', 'page', 'identity', 'webauthn']);
    expect(report).toMatchObject({
      report: 'Analyze Browser',
      page: 'http://localhost',
      identity: {
        name: 'Chromium-based browser',
        version: '152.0.7977.130',
        engine: 'Blink',
        system: 'macOS',
        sources: { name: 'client-hints', version: 'client-hints', engine: 'client-hints', system: 'client-hints' },
        inputs: { userAgent: CHROMIUM_ONLY.userAgent, platform: 'MacIntel', maxTouchPoints: 0, brave: null },
      },
      webauthn: {
        facts: { secureContext: { state: 'yes' }, hybridTransport: { state: 'yes' } },
        clientCapabilities: { state: 'yes', returned: CHROMIUM_152_CAPABILITIES, omitted: [] },
      },
    });
    expect(Object.keys(report.webauthn.facts)).toHaveLength(8);
  });

  it('says why copying failed, in red, and shows the report selected, to copy by hand (AB-R5, AB-R6)', async () => {
    const writeText = vi.fn(async () => {
      throw new DOMException('Write permission denied.', 'NotAllowedError');
    });
    const { status, fallback } = await copyWith({ writeText });

    await waitFor(() => expect(status).toHaveAttribute('data-outcome', 'failed'));
    expect(status.textContent).toBe(
      'Could not copy the report: NotAllowedError: Write permission denied. The report is below, selected, to copy by hand.',
    );
    expect(status.className).toContain('text-danger');
    expect(fallback).toBeVisible();
    expect(fallback).toHaveAccessibleName('Browser analysis report, as JSON');
    expect(fallback).toHaveAttribute('readonly');
    expect(fallback).toHaveAttribute('rows', '10');
    expect(fallback).toHaveFocus();
    expect(fallback.selectionStart).toBe(0);
    expect(fallback.selectionEnd).toBe(fallback.value.length);
    expect(JSON.parse(fallback.value).identity.name).toBe('Chromium-based browser');
  });

  it('says the clipboard is not available, hides the report after a later success, and keeps the status across reopening (AB-R5, AB-R7)', async () => {
    const { dialog, status, fallback } = await copyWith(undefined);

    await waitFor(() =>
      expect(status.textContent).toBe(
        'Could not copy the report: the clipboard is not available on this page. The report is below, selected, to copy by hand.',
      ),
    );
    expect(fallback).toBeVisible();

    install(navigator, 'clipboard', { writeText: vi.fn(async () => {}) });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Copy report' }));
    await waitFor(() => expect(status.textContent).toBe('Report copied to the clipboard.'));
    expect(fallback).not.toBeVisible();

    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Browser Analysis' })).toBeNull());
    await userEvent.click(trigger());
    const reopened = await screen.findByRole('dialog', { name: 'Browser Analysis' });
    expect(reopened.querySelector('[data-role="copy-status"]')).toHaveTextContent('Report copied to the clipboard.');
  });

  it('keeps the empty status line out of the layout until the first copy (AB-R7)', async () => {
    installBrowser();
    const dialog = await openPanel();
    const status = dialog.querySelector('[data-role="copy-status"]')!;
    expect(status).toBeEmptyDOMElement();
    expect(status.className).toContain('sr-only');
  });
});

describe('as a dialog', () => {
  it('is a labelled modal dialog that takes focus when it opens, named by the trigger (AB-D1, AB-D2)', async () => {
    installBrowser();
    const dialog = await openPanel();

    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(document.getElementById(dialog.getAttribute('aria-labelledby')!)!.textContent).toBe('Browser Analysis');
    expect(within(dialog).getByRole('heading', { level: 2, name: 'Browser Analysis' })).toBeInTheDocument();
    expect(panelRoot()).toContainElement(dialog);
    expect(document.getElementById('app-root')).toHaveAttribute('inert');
  });

  it('gives focus back to the Analyze Browser button when it closes, by Escape or by the close button (AB-D6, AB-D7, AB-D9)', async () => {
    installBrowser();
    await openPanel();

    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(trigger()).toHaveFocus());

    await userEvent.click(trigger());
    await waitFor(() => expect(screen.getByRole('dialog', { name: 'Browser Analysis' })).toHaveFocus());
    await userEvent.click(screen.getByRole('button', { name: 'Close browser analysis' }));
    await waitFor(() => expect(trigger()).toHaveFocus());
  });

  it('keeps Tab and Shift+Tab inside the dialog, counting the report text once it is shown (AB-D3, AB-D4)', async () => {
    installBrowser();
    install(navigator, 'clipboard', undefined);
    const dialog = await openPanel();
    const copy = within(dialog).getByRole('button', { name: 'Copy report' });
    const close = within(dialog).getByRole('button', { name: 'Close browser analysis' });

    await userEvent.tab({ shift: true });
    expect(close).toHaveFocus();
    await userEvent.tab();
    expect(copy).toHaveFocus();
    await userEvent.tab();
    expect(close).toHaveFocus();

    await userEvent.click(copy);
    const fallback = dialog.querySelector<HTMLTextAreaElement>('[data-role="report-text"]')!;
    await waitFor(() => expect(fallback).toHaveFocus());
    await userEvent.tab();
    expect(copy).toHaveFocus();
    await userEvent.tab({ shift: true });
    expect(fallback).toHaveFocus();
  });

  it('leaves Tab alone while it is closed (AB-D5)', async () => {
    installBrowser();
    renderPage(<AppShell />);
    trigger().focus();
    const event = new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true });
    trigger().dispatchEvent(event);
    expect(event.defaultPrevented).toBe(false);
  });

  it('closes from the close button, the backdrop and Escape, ignores other clicks, and opens scrolled to the top (AB-D2, AB-D8, AB-D10)', async () => {
    installBrowser();
    const dialog = await openPanel();
    const body = dialog.querySelector<HTMLElement>('[data-overlay-scroll]')!;

    body.scrollTop = 128;
    await userEvent.click(within(dialog).getByRole('heading', { name: 'Browser Analysis' }));
    expect(screen.getByRole('dialog', { name: 'Browser Analysis' })).toBeInTheDocument();
    expect(document.documentElement.style.overflow).toBe('');
    expect(document.body.style.overflow).toBe('');

    fireEvent.click(panelRoot().querySelector('[data-overlay-backdrop]')!);
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Browser Analysis' })).toBeNull());

    await userEvent.click(trigger());
    const reopened = await screen.findByRole('dialog', { name: 'Browser Analysis' });
    expect(reopened.querySelector<HTMLElement>('[data-overlay-scroll]')!.scrollTop).toBe(0);
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Browser Analysis' })).toBeNull());
  });

  it('opens from the phone menu, and gives focus back to the Menu button', async () => {
    installBrowser();
    renderPage(<AppShell />);
    const menu = screen.getByRole('button', { name: 'Menu' });

    await userEvent.click(menu);
    const sheet = await screen.findByRole('dialog', { name: 'Menu' });
    await userEvent.click(within(sheet).getByRole('button', { name: 'Analyze Browser' }));
    const dialog = await screen.findByRole('dialog', { name: 'Browser Analysis' });
    await waitFor(() => expect(dialog).toHaveFocus());
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Menu' })).toBeNull());

    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(menu).toHaveFocus());
  });
});
