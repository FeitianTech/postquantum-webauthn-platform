import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../static/scripts/advanced/forms.js', () => ({
  randomizeChallenge: vi.fn(),
  validatePrfInputs: vi.fn(),
  updateAuthenticationExtensionAvailability: vi.fn(),
}));

vi.mock('../../../static/scripts/shared/username.js', () => ({
  randomizeUserIdentity: vi.fn(),
}));

vi.mock('../../../static/scripts/advanced/json-editor.js', () => ({
  updateJsonEditor: vi.fn(),
}));

vi.mock('../../../static/scripts/advanced/exclude-credentials.js', () => ({
  clearFakeExcludeCredentials: vi.fn(),
  clearFakeAllowCredentials: vi.fn(),
}));

vi.mock('../../../static/scripts/advanced/credential-display.js', () => ({
  updateAllowCredentialsDropdown: vi.fn(),
}));

import {
  randomizeChallenge,
  updateAuthenticationExtensionAvailability,
  validatePrfInputs,
} from '../../../static/scripts/advanced/forms.js';
import {
  clearFakeAllowCredentials,
  clearFakeExcludeCredentials,
} from '../../../static/scripts/advanced/exclude-credentials.js';
import { updateAllowCredentialsDropdown } from '../../../static/scripts/advanced/credential-display.js';
import { updateJsonEditor } from '../../../static/scripts/advanced/json-editor.js';
import { randomizeUserIdentity } from '../../../static/scripts/shared/username.js';
import {
  resetAuthenticationForm,
  resetRegistrationForm,
} from '../../../static/scripts/advanced/resets.js';
import { initializeAdvancedSettingsNavigation } from '../../../static/scripts/advanced/settings-nav.js';
import { state } from '../../../static/scripts/shared/state.js';

function buildResetDom() {
  document.body.innerHTML = `
    <input id="authenticator-attachment" value="platform" />
    <input id="resident-key" value="required" />
    <input id="user-verification-reg" value="required" />
    <input id="attestation" value="none" />
    <input id="exclude-credentials" type="checkbox" />
    <input id="fake-cred-length-reg" value="1" />
    <input id="timeout-reg" value="1" />

    <input id="param-eddsa" type="checkbox" />
    <input id="param-es256" type="checkbox" />
    <input id="param-rs256" type="checkbox" />
    <input id="param-es384" type="checkbox" />
    <input id="param-es512" type="checkbox" />
    <input id="param-rs384" type="checkbox" />
    <input id="param-rs512" type="checkbox" />
    <input id="param-rs1" type="checkbox" />
    <input id="param-ed25519" type="checkbox" />
    <input id="param-es256k" type="checkbox" />
    <input id="param-esp256" type="checkbox" />
    <input id="param-esp384" type="checkbox" />
    <input id="param-esp512" type="checkbox" />
    <input id="param-ps256" type="checkbox" />
    <input id="param-ps384" type="checkbox" />
    <input id="param-ps512" type="checkbox" />
    <input id="param-ed448" type="checkbox" />
    <input id="param-mldsa44" type="checkbox" />
    <input id="param-mldsa65" type="checkbox" />
    <input id="param-mldsa87" type="checkbox" />

    <input id="hint-client-device" type="checkbox" />
    <input id="hint-hybrid" type="checkbox" />
    <input id="hint-security-key" type="checkbox" />

    <input id="cred-props" type="checkbox" />
    <input id="min-pin-length" type="checkbox" />
    <input id="cred-protect" value="some-value" />
    <input id="enforce-cred-protect" type="checkbox" />
    <input id="large-blob-reg" value="supported" />
    <input id="prf-reg" type="checkbox" />
    <input id="prf-eval-first-reg" value="aa" />
    <input id="prf-eval-second-reg" value="bb" />

    <input id="user-verification-auth" value="required" />
    <select id="allow-credentials"><option value="all">all</option></select>
    <input id="fake-cred-length-auth" value="1" />
    <input id="timeout-auth" value="1" />

    <input id="hint-client-device-auth" type="checkbox" />
    <input id="hint-hybrid-auth" type="checkbox" />
    <input id="hint-security-key-auth" type="checkbox" />

    <input id="large-blob-auth" value="read" />
    <input id="large-blob-write" value="abc" />
    <input id="prf-eval-first-auth" value="cc" />
    <input id="prf-eval-second-auth" value="dd" />
  `;
}

function buildSettingsNavDom() {
  document.body.innerHTML = `
    <nav class="settings-nav">
      <a class="settings-nav__item" href="#" data-registration-target="reg-a" data-authentication-target="auth-a">A</a>
      <a class="settings-nav__item" href="#" data-registration-target="reg-b" data-authentication-target="auth-b">B</a>
    </nav>

    <section id="reg-a"></section>
    <section id="reg-b" data-scroll-target="reg-b-scroll"></section>
    <div id="reg-b-scroll"></div>

    <section id="auth-a"></section>
    <section id="auth-b"></section>
  `;
}

describe('resets', () => {
  beforeEach(() => {
    buildResetDom();
  });

  it('resets registration defaults and invokes dependent helpers', () => {
    resetRegistrationForm();

    expect(randomizeUserIdentity).toHaveBeenCalledTimes(1);
    expect(randomizeChallenge).toHaveBeenCalledWith('reg');
    expect(clearFakeExcludeCredentials).toHaveBeenCalledTimes(1);
    expect(updateAllowCredentialsDropdown).toHaveBeenCalledTimes(1);
    expect(updateJsonEditor).toHaveBeenCalledTimes(1);

    expect(document.getElementById('authenticator-attachment').value).toBe('cross-platform');
    expect(document.getElementById('resident-key').value).toBe('discouraged');
    expect(document.getElementById('attestation').value).toBe('direct');
    expect(document.getElementById('exclude-credentials').checked).toBe(true);
    expect(document.getElementById('timeout-reg').value).toBe('90000');

    expect(document.getElementById('param-eddsa').checked).toBe(true);
    expect(document.getElementById('param-es256').checked).toBe(true);
    expect(document.getElementById('param-rs256').checked).toBe(true);
    expect(document.getElementById('param-es384').checked).toBe(false);
    expect(document.getElementById('param-mldsa44').checked).toBe(true);
    expect(document.getElementById('param-mldsa65').checked).toBe(true);
    expect(document.getElementById('param-mldsa87').checked).toBe(true);

    expect(document.getElementById('cred-props').checked).toBe(true);
    expect(document.getElementById('min-pin-length').checked).toBe(false);
    expect(document.getElementById('enforce-cred-protect').disabled).toBe(true);
    expect(document.getElementById('prf-eval-second-reg').disabled).toBe(true);
  });

  it('resets authentication defaults and triggers extension validators', () => {
    resetAuthenticationForm();

    expect(randomizeChallenge).toHaveBeenCalledWith('auth');
    expect(clearFakeAllowCredentials).toHaveBeenCalledTimes(1);
    expect(validatePrfInputs).toHaveBeenCalledWith('reg');
    expect(validatePrfInputs).toHaveBeenCalledWith('auth');
    expect(updateAuthenticationExtensionAvailability).toHaveBeenCalledTimes(1);
    expect(updateJsonEditor).toHaveBeenCalledTimes(1);

    expect(document.getElementById('user-verification-auth').value).toBe('preferred');
    expect(document.getElementById('allow-credentials').value).toBe('all');
    expect(document.getElementById('fake-cred-length-auth').value).toBe('256');
    expect(document.getElementById('timeout-auth').value).toBe('90000');
    expect(document.getElementById('large-blob-write').disabled).toBe(true);
    expect(document.getElementById('prf-eval-second-auth').disabled).toBe(true);

    expect(document.getElementById('param-mldsa44').checked).toBe(true);
    expect(document.getElementById('param-mldsa65').checked).toBe(true);
    expect(document.getElementById('param-mldsa87').checked).toBe(true);
  });
});

describe('settings-nav', () => {
  beforeEach(() => {
    buildSettingsNavDom();
  });

  it('no-ops when nav is missing or when nav has no items', () => {
    document.body.innerHTML = '';
    expect(() => initializeAdvancedSettingsNavigation()).not.toThrow();

    document.body.innerHTML = '<nav class="settings-nav"></nav>';
    expect(() => initializeAdvancedSettingsNavigation()).not.toThrow();
  });

  it('activates sections, handles clicks, and reacts to intersection updates', () => {
    const observers = [];
    class FakeIntersectionObserver {
      constructor(callback, options) {
        this.callback = callback;
        this.options = options;
        this.observed = [];
        observers.push(this);
      }

      observe(element) {
        this.observed.push(element);
      }

      disconnect() {}
    }

    globalThis.IntersectionObserver = FakeIntersectionObserver;
    const scrollSpy = vi.spyOn(HTMLElement.prototype, 'scrollIntoView').mockImplementation(() => {});

    state.currentSubTab = 'registration';
    initializeAdvancedSettingsNavigation();

    const navItems = Array.from(document.querySelectorAll('.settings-nav__item'));
    expect(navItems[0].classList.contains('settings-nav__item--active')).toBe(true);

    navItems[1].dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(scrollSpy).toHaveBeenCalled();
    expect(navItems[1].classList.contains('settings-nav__item--active')).toBe(true);

    observers[0].callback([
      {
        isIntersecting: true,
        boundingClientRect: { top: 1 },
        target: document.getElementById('reg-a'),
      },
    ]);
    expect(navItems[0].classList.contains('settings-nav__item--active')).toBe(true);

    scrollSpy.mockRestore();
  });

  it('uses authentication targets when the authentication sub-tab is active', () => {
    const observers = [];
    class FakeIntersectionObserver {
      constructor(callback) {
        this.callback = callback;
        observers.push(this);
      }

      observe() {}
      disconnect() {}
    }

    globalThis.IntersectionObserver = FakeIntersectionObserver;

    state.currentSubTab = 'authentication';
    initializeAdvancedSettingsNavigation();

    const navItems = Array.from(document.querySelectorAll('.settings-nav__item'));
    const authA = document.getElementById('auth-a');

    observers[0].callback([
      {
        isIntersecting: true,
        boundingClientRect: { top: 2 },
        target: authA,
      },
    ]);

    expect(navItems[0].classList.contains('settings-nav__item--active')).toBe(true);
  });

  it('ignores empty intersections and missing click targets while reacting to tab events', () => {
    const observers = [];
    class FakeIntersectionObserver {
      constructor(callback) {
        this.callback = callback;
        observers.push(this);
      }

      observe() {}
      disconnect() {}
    }

    globalThis.IntersectionObserver = FakeIntersectionObserver;

    state.currentSubTab = 'registration';
    initializeAdvancedSettingsNavigation();

    const navItems = Array.from(document.querySelectorAll('.settings-nav__item'));

    // visible.length === 0 branch
    observers[0].callback([
      {
        isIntersecting: false,
        boundingClientRect: { top: 5 },
        target: document.getElementById('reg-a'),
      },
    ]);

    // missing sentinel branch
    navItems[1].dataset.registrationTarget = 'missing-target';
    navItems[1].dispatchEvent(new MouseEvent('click', { bubbles: true }));

    // missing targetId branch
    delete navItems[1].dataset.registrationTarget;
    delete navItems[1].dataset.authenticationTarget;
    navItems[1].dispatchEvent(new MouseEvent('click', { bubbles: true }));

    // event listeners around observeSections
    document.dispatchEvent(new CustomEvent('advanced:subtab-changed', { detail: { subTab: 'registration' } }));
    document.dispatchEvent(new CustomEvent('tab:changed', { detail: { tab: 'simple' } }));
    document.dispatchEvent(new CustomEvent('tab:changed', { detail: { tab: 'advanced' } }));

    expect(navItems[0].classList.contains('settings-nav__item--active')).toBe(true);
  });

  it('deduplicates observed sections when multiple items point to the same target', () => {
    buildSettingsNavDom();
    const observers = [];
    class FakeIntersectionObserver {
      constructor(callback) {
        this.callback = callback;
        this.observed = [];
        observers.push(this);
      }

      observe(element) {
        this.observed.push(element);
      }
      disconnect() {}
    }

    globalThis.IntersectionObserver = FakeIntersectionObserver;
    state.currentSubTab = 'registration';

    const navItems = Array.from(document.querySelectorAll('.settings-nav__item'));
    navItems[1].dataset.registrationTarget = navItems[0].dataset.registrationTarget;

    initializeAdvancedSettingsNavigation();

    expect(observers[0].observed).toHaveLength(1);
  });
});
