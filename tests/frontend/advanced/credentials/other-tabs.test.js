import { beforeEach, describe, expect, it, vi } from 'vitest';

// The current UI's saved credentials follow another tab: a registration, a
// deletion or Clear All made in another tab of this origin (either interface)
// shows here without a reload. The list and the storage are real; only the
// editor and the forms the list's drawing also updates are stubbed.

vi.mock('../../../../frontend/static/scripts/advanced/editor/index.js', () => ({
  updateJsonEditor: vi.fn(),
}));

vi.mock('../../../../frontend/static/scripts/advanced/auth/forms.js', () => ({
  checkLargeBlobCapability: vi.fn(),
  updateAuthenticationExtensionAvailability: vi.fn(),
}));

const SHARED = 'postquantum-webauthn.credentials';

async function load() {
  const credentials = await import('../../../../frontend/static/scripts/advanced/credentials/index.js');
  // The current UI's barrel seeds the records from the page data the tests give
  // (tests/frontend/setup.js): take that away, so the storage is read.
  const storage = await import('../../../../frontend/static/scripts/shared/storage/local/storage-core.js');
  storage.seedUnifiedCredentialRecords(null);
  return credentials;
}

function cards() {
  return Array.from(document.querySelectorAll('#simple-credentials-list .credential-item')).map((card) => card.textContent);
}

describe('another tab\'s change to the saved credentials', () => {
  beforeEach(() => {
    vi.resetModules();
    window.localStorage.clear();
    document.body.innerHTML = '<div id="simple-credentials-list" data-credentials-list></div>';
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{"artifacts":{}}', { headers: { 'Content-Type': 'application/json' } })));
  });

  it('is drawn here without a reload', async () => {
    window.localStorage.setItem(SHARED, JSON.stringify([{ type: 'simple', credentialId: 'AQID', email: 'here' }]));
    const credentials = await load();
    credentials.bindCredentialActions();
    await credentials.loadSavedCredentials();
    expect(cards()).toEqual([expect.stringContaining('here')]);

    window.localStorage.setItem(SHARED, JSON.stringify([
      { type: 'simple', credentialId: 'AQID', email: 'here' },
      { type: 'simple', credentialId: 'BAUG', email: 'elsewhere' },
    ]));
    window.dispatchEvent(new StorageEvent('storage', { key: SHARED }));

    await vi.waitFor(() => expect(cards()).toHaveLength(2));
    expect(cards()[1]).toContain('elsewhere');
  });
});
