import { beforeEach, describe, expect, it, vi } from 'vitest';

import { updateCredentialsDisplayRuntime } from '../../../../frontend/static/scripts/advanced/credential-display/list-render.js';

const IMG_PAYLOAD = '<img src=x onerror="window.__xss=1">';
const ATTRIBUTE_PAYLOAD = '" onmouseover="window.__xss=1';

function buildDom() {
  document.body.innerHTML = '<div data-credentials-list></div>';
}

function getList() {
  return document.querySelector('[data-credentials-list]');
}

function createDeps(storedCredentials, overrides = {}) {
  return {
    state: { storedCredentials },
    getCredentialIdHex: (cred) => cred.credentialIdHex || '',
    readPendingCredentialFlash: () => null,
    isCredentialDeletionInProgress: () => false,
    checkLargeBlobCapability: vi.fn(),
    updateAllowCredentialsDropdown: vi.fn(),
    updateAuthenticationExtensionAvailability: vi.fn(),
    clearCredentialFlashQueue: vi.fn(),
    describeCredentialAlgorithmTag: () => 'ES256',
    deriveCredentialStatusIndicators: () => ({
      signatureStatus: true,
      rootStatus: true,
      rpidStatus: true,
      aaguidStatus: true,
      metadataAvailable: true,
      aaguidGuid: '00112233-4455-6677-8899-aabbccddeeff',
    }),
    handleCredentialMdsClick: vi.fn(),
    triggerCredentialFlash: vi.fn(),
    showCredentialDetails: vi.fn(),
    deleteCredential: vi.fn(),
    ...overrides,
  };
}

describe('credential list rendering shows untrusted values as text', () => {
  beforeEach(() => {
    buildDom();
    delete window.__xss;
  });

  // Positive control: proves the assertions below are sensitive. Parsing the
  // payload as markup really does create an <img> element in jsdom, so a
  // regression that builds the cards from strings would fail the tests that follow.
  it('would detect an unescaped interpolation', () => {
    getList().innerHTML = `<div class="credential-item"><div>${IMG_PAYLOAD}</div></div>`;

    expect(getList().querySelector('img')).not.toBeNull();
    expect(getList().textContent).not.toContain(IMG_PAYLOAD);
  });

  it('renders a script-bearing userName as text instead of an element', () => {
    updateCredentialsDisplayRuntime(createDeps([
      { userName: IMG_PAYLOAD, credentialIdHex: 'aabb' },
    ]));

    const list = getList();
    expect(list.querySelector('img')).toBeNull();
    expect(list.textContent).toContain(IMG_PAYLOAD);
    expect(window.__xss).toBeUndefined();
  });

  it.each([
    ['username', { username: IMG_PAYLOAD }],
    ['email', { email: IMG_PAYLOAD }],
  ])('renders a script-bearing %s fallback as text instead of an element', (_label, credFields) => {
    updateCredentialsDisplayRuntime(createDeps([
      { ...credFields, credentialIdHex: 'aabb' },
    ]));

    const list = getList();
    expect(list.querySelector('img')).toBeNull();
    expect(list.textContent).toContain(IMG_PAYLOAD);
  });

  it('does not let a quote-bearing userName break out into an attribute', () => {
    updateCredentialsDisplayRuntime(createDeps([
      { userName: ATTRIBUTE_PAYLOAD, credentialIdHex: 'aabb' },
    ]));

    const item = getList().querySelector('.credential-item');
    expect(item.getAttribute('onmouseover')).toBeNull();
    expect(item.textContent).toContain(ATTRIBUTE_PAYLOAD);
  });

  it('still renders ordinary usernames, feature tags and status colours', () => {
    updateCredentialsDisplayRuntime(createDeps([
      { userName: 'alice@example.com', credentialIdHex: 'AABB', residentKey: true },
      { username: 'bob', credentialIdHex: 'ccdd' },
      { email: 'carol@example.com', credentialIdHex: 'eeff' },
      { credentialIdHex: '0011' },
    ]));

    const list = getList();
    const items = list.querySelectorAll('.credential-item');
    expect(items.length).toBe(4);
    expect(items[0].textContent).toContain('alice@example.com');
    expect(items[1].textContent).toContain('bob');
    expect(items[2].textContent).toContain('carol@example.com');
    expect(items[3].textContent).toContain('Unknown User');

    expect(items[0].getAttribute('data-credential-id')).toBe('aabb');
    expect(items[0].querySelectorAll('.credential-feature-tag').length).toBe(2);
    expect(list.querySelectorAll('.credential-delete-button').length).toBe(4);
  });

  it('renders the empty state when there are no credentials', () => {
    updateCredentialsDisplayRuntime(createDeps([]));

    expect(getList().textContent).toContain('No credentials registered yet.');
  });
});

describe('credential list uses listener bindings instead of inline handlers', () => {
  beforeEach(() => {
    buildDom();
  });

  it('emits no inline event-handler attributes', () => {
    updateCredentialsDisplayRuntime(createDeps([
      { userName: 'alice', credentialIdHex: 'aabb' },
    ]));

    const list = getList();
    expect(list.innerHTML).not.toContain('onclick=');
    expect(list.innerHTML).not.toContain('onkeydown=');

    const item = list.querySelector('.credential-item');
    expect(item.getAttribute('onclick')).toBeNull();
    expect(item.getAttribute('onkeydown')).toBeNull();
    expect(list.querySelector('.credential-delete-button').getAttribute('onclick')).toBeNull();
  });

  it('opens credential details when an item is clicked', () => {
    const deps = createDeps([
      { userName: 'alice', credentialIdHex: 'aabb' },
      { userName: 'bob', credentialIdHex: 'ccdd' },
    ]);
    updateCredentialsDisplayRuntime(deps);

    const items = getList().querySelectorAll('.credential-item');
    items[1].dispatchEvent(new window.MouseEvent('click', { bubbles: true }));

    expect(deps.showCredentialDetails).toHaveBeenCalledTimes(1);
    expect(deps.showCredentialDetails).toHaveBeenCalledWith(1);
  });

  it.each(['Enter', ' '])('opens credential details on %s keydown', (key) => {
    const deps = createDeps([{ userName: 'alice', credentialIdHex: 'aabb' }]);
    updateCredentialsDisplayRuntime(deps);

    const item = getList().querySelector('.credential-item');
    const event = new window.KeyboardEvent('keydown', { key, bubbles: true, cancelable: true });
    item.dispatchEvent(event);

    expect(deps.showCredentialDetails).toHaveBeenCalledWith(0);
    expect(event.defaultPrevented).toBe(true);
  });

  it('ignores unrelated keys', () => {
    const deps = createDeps([{ userName: 'alice', credentialIdHex: 'aabb' }]);
    updateCredentialsDisplayRuntime(deps);

    getList()
      .querySelector('.credential-item')
      .dispatchEvent(new window.KeyboardEvent('keydown', { key: 'a', bubbles: true }));

    expect(deps.showCredentialDetails).not.toHaveBeenCalled();
  });

  it('deletes the credential without also opening the detail modal', () => {
    const deps = createDeps([
      { userName: 'alice', credentialIdHex: 'aabb' },
      { userName: 'bob', credentialIdHex: 'ccdd' },
    ]);
    updateCredentialsDisplayRuntime(deps);

    const buttons = getList().querySelectorAll('.credential-delete-button');
    buttons[1].dispatchEvent(new window.MouseEvent('click', { bubbles: true }));

    expect(deps.deleteCredential).toHaveBeenCalledTimes(1);
    expect(deps.deleteCredential).toHaveBeenCalledWith(1);
    expect(deps.showCredentialDetails).not.toHaveBeenCalled();
  });

  it('keeps the MDS button binding working', () => {
    const deps = createDeps([{ userName: 'alice', credentialIdHex: 'aabb' }]);
    updateCredentialsDisplayRuntime(deps);

    const mdsButton = getList().querySelector('.credential-mds-button');
    expect(mdsButton).not.toBeNull();
    mdsButton.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));

    expect(deps.handleCredentialMdsClick).toHaveBeenCalledTimes(1);
    expect(deps.deleteCredential).not.toHaveBeenCalled();
  });

  it('falls back to the global handlers when none are injected', () => {
    const globalDetails = vi.fn();
    const globalDelete = vi.fn();
    window.showCredentialDetails = globalDetails;
    window.deleteCredential = globalDelete;

    const deps = createDeps([{ userName: 'alice', credentialIdHex: 'aabb' }], {
      showCredentialDetails: undefined,
      deleteCredential: undefined,
    });
    updateCredentialsDisplayRuntime(deps);

    const list = getList();
    list.querySelector('.credential-item').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
    list.querySelector('.credential-delete-button').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));

    expect(globalDetails).toHaveBeenCalledWith(0);
    expect(globalDelete).toHaveBeenCalledWith(0);

    delete window.showCredentialDetails;
    delete window.deleteCredential;
  });
});
