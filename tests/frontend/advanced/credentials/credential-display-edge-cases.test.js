import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../frontend/static/scripts/shared/utils/binary.js', () => ({
  base64ToBase64Url: vi.fn((value) => String(value || '').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')),
  base64ToHex: vi.fn(() => ''),
  base64ToUint8Array: vi.fn(() => null),
  base64UrlToHex: vi.fn(() => ''),
  base64UrlToJson: vi.fn(() => null),
  base64UrlToUint8Array: vi.fn(() => null),
  base64UrlToUtf8String: vi.fn(() => ''),
  bytesToHex: vi.fn(() => ''),
  hexToGuid: vi.fn((hex) => {
    const clean = String(hex || '').replace(/[^0-9a-f]/gi, '').toLowerCase();
    if (clean.length !== 32) {
      return '';
    }
    return `${clean.slice(0, 8)}-${clean.slice(8, 12)}-${clean.slice(12, 16)}-${clean.slice(16, 20)}-${clean.slice(20)}`;
  }),
  hexToUint8Array: vi.fn(() => null),
  normalizeToHex: vi.fn((value) => String(value || '').replace(/[^0-9a-f]/gi, '').toLowerCase()),
}));

vi.mock('../../../../frontend/static/scripts/advanced/display-utils.js', () => ({
  describeCoseAlgorithm: vi.fn((alg) => `ALG(${String(alg)})`),
  describeCoseKeyType: vi.fn((type) => `KEYTYPE(${String(type)})`),
  describeMldsaParameterSet: vi.fn(() => ''),
  escapeHtml: vi.fn((value) => String(value || '')),
  formatBoolean: vi.fn((value) => (value ? 'Yes' : 'No')),
  renderAttestationResultRow: vi.fn((label, value) => `<div>${label}:${String(value)}</div>`),
}));

vi.mock('../../../../frontend/static/scripts/advanced/credential-utils.js', () => ({
  deriveAaguidDisplayValues: vi.fn(() => ({ aaguidHex: '', aaguidB64: '', aaguidB64u: '' })),
  deriveAaguidFromCredentialData: vi.fn(() => ''),
  extractMinPinLengthValue: vi.fn(() => null),
  getCoseMapValue: vi.fn(() => undefined),
  getCredentialIdHex: vi.fn((cred) => cred?.credentialIdHex || ''),
  getCredentialUserHandleHex: vi.fn((cred) => cred?.userHandleHex || ''),
  getStoredCredentialAttachment: vi.fn((cred) => cred?.attachment || cred?.authenticatorAttachment || null),
  normaliseAaguidValue: vi.fn((value) => {
    const clean = String(value || '').replace(/[^0-9a-f]/gi, '').toLowerCase();
    return clean.length === 32 ? clean : '';
  }),
}));

vi.mock('../../../../frontend/static/scripts/shared/ui/core.js', () => ({
  closeModal: vi.fn(),
  openModal: vi.fn(),
}));

vi.mock('../../../../frontend/static/scripts/shared/ui/status.js', () => ({
  dismissAllTransientMessages: vi.fn(),
  hideProgress: vi.fn(),
  showProgress: vi.fn(),
  showStatus: vi.fn(),
}));

vi.mock('../../../../frontend/static/scripts/advanced/json-editor.js', () => ({
  updateJsonEditor: vi.fn(),
}));

vi.mock('../../../../frontend/static/scripts/advanced/forms.js', () => ({
  checkLargeBlobCapability: vi.fn(),
  updateAuthenticationExtensionAvailability: vi.fn(),
}));

vi.mock('../../../../frontend/static/scripts/advanced/hints.js', () => ({
  collectSelectedHints: vi.fn(() => []),
  deriveAllowedAttachmentsFromHints: vi.fn(() => []),
}));

vi.mock('../../../../frontend/static/scripts/advanced/constants.js', () => ({
  ATTACHMENT_LABELS: {
    platform: 'Platform',
    'cross-platform': 'Cross-platform',
  },
}));

vi.mock('../../../../frontend/static/scripts/shared/storage/local.js', () => ({
  clearAdvancedCredentials: vi.fn(),
  clearSimpleCredentials: vi.fn(),
  ensureAdvancedCredentialArtifactsSynced: vi.fn().mockResolvedValue(false),
  ensureAdvancedCredentialSnapshotsPrefetched: vi.fn().mockResolvedValue(false),
  getAllAdvancedCredentials: vi.fn(() => []),
  getAllSimpleCredentials: vi.fn(() => []),
  getAllStoredCredentialsInOrder: vi.fn(() => []),
  removeAdvancedCredential: vi.fn(() => true),
  removeSimpleCredential: vi.fn(() => true),
  updateAdvancedCredentialRegistrationSnapshot: vi.fn().mockResolvedValue(false),
}));

vi.mock('../../../../frontend/static/scripts/shared/storage/artifacts-client.js', () => ({
  deleteCredentialArtifact: vi.fn().mockResolvedValue({ ok: true, status: 'deleted', httpStatus: 200 }),
  fetchCredentialArtifact: vi.fn().mockResolvedValue(null),
}));

import { openModal } from '../../../../frontend/static/scripts/shared/ui/core.js';
import { showStatus } from '../../../../frontend/static/scripts/shared/ui/status.js';
import {
  getAllAdvancedCredentials,
  getAllSimpleCredentials,
  removeAdvancedCredential,
  removeSimpleCredential,
} from '../../../../frontend/static/scripts/shared/storage/local.js';
import { deleteCredentialArtifact } from '../../../../frontend/static/scripts/shared/storage/artifacts-client.js';
import { state } from '../../../../frontend/static/scripts/shared/state.js';
import {
  clearAllCredentials,
  deleteCredential,
  navigateToMdsAuthenticator,
  showCredentialDetails,
  showRegistrationResultModal,
} from '../../../../frontend/static/scripts/advanced/credential-display.js';

function buildDom() {
  document.body.innerHTML = `
    <div id="advanced-tab" class="tab-content active">
      <button data-credentials-clear>Clear</button>
      <div data-credentials-list></div>
      <select id="allow-credentials"><option value="all">All credentials</option></select>
      <select id="authenticator-attachment"><option value="cross-platform">Cross-platform</option></select>
    </div>
    <div id="simple-tab" class="tab-content">
      <button data-credentials-clear>Clear</button>
      <div data-credentials-list></div>
    </div>
    <div id="credentialModal"></div>
    <div id="modalBody"></div>
    <div id="registrationResultModal"></div>
    <div id="registrationResultBody"></div>
    <div id="registrationDetailModal"></div>
    <h3 id="registrationDetailModalTitle"></h3>
    <div id="registrationDetailModalBody"></div>
  `;
}

describe('credential-display edge cases', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    buildDom();

    state.storedCredentials = [];
    globalThis.confirm = vi.fn(() => true);
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: vi.fn().mockResolvedValue({ data: {} }),
      text: vi.fn().mockResolvedValue('{}'),
    });

    window.switchTab = vi.fn();
    window.highlightMdsAuthenticatorRow = vi.fn(() => ({ highlighted: true, entry: { aaguid: '00112233445566778899aabbccddeeff' } }));
    window.resolveMdsEntryByAaguid = vi.fn().mockResolvedValue({ aaguid: '00112233445566778899aabbccddeeff' });
    window.finaliseMdsAuthenticatorHighlight = vi.fn(() => true);
  });

  it('reports shared error status when simple or advanced deletion fails', async () => {
    state.storedCredentials = [
      {
        type: 'simple',
        userName: 'Simple User',
        credentialIdBase64Url: 'simple-id',
        credentialId: 'simple-id',
        email: 'simple@example.com',
      },
      {
        type: 'advanced',
        userName: 'Advanced User',
        credentialIdBase64Url: 'advanced-id',
        credentialId: 'advanced-id',
        storageId: 'advanced-storage',
      },
    ];

    removeSimpleCredential.mockReturnValueOnce(false);
    removeAdvancedCredential.mockReturnValueOnce(false);
    deleteCredentialArtifact.mockResolvedValueOnce({ ok: true, status: 'deleted', httpStatus: 200 });

    await deleteCredential(0);
    await deleteCredential(1);

    expect(showStatus).toHaveBeenCalledWith('advanced', 'Unable to remove credential from this browser.', 'error');
    expect(showStatus).toHaveBeenCalledWith('simple', 'Unable to remove credential from this browser.', 'error');
    expect(showStatus).toHaveBeenCalledWith('advanced', 'Credential was deleted from server but could not be removed locally.', 'error');
    expect(showStatus).toHaveBeenCalledWith('simple', 'Credential was deleted from server but could not be removed locally.', 'error');
    expect(deleteCredentialArtifact).toHaveBeenCalledWith('advanced-storage');
  });

  it('keeps failed advanced deletions local during clear-all and reports error status', async () => {
    getAllSimpleCredentials.mockReturnValue([]);
    getAllAdvancedCredentials.mockReturnValue([
      { storageId: 'adv-storage-1', credentialIdBase64Url: 'adv-id-1' },
      { credentialIdBase64Url: 'local-only-id' },
    ]);
    deleteCredentialArtifact.mockResolvedValueOnce({
      ok: false,
      status: 'failed',
      httpStatus: null,
      error: 'network-failure',
    });

    await clearAllCredentials();

    expect(deleteCredentialArtifact).toHaveBeenCalledWith('adv-storage-1');
    expect(removeAdvancedCredential).toHaveBeenCalledWith('local-only-id', null);
    expect(removeAdvancedCredential).not.toHaveBeenCalledWith('adv-id-1', 'adv-storage-1');
    expect(showStatus).toHaveBeenCalledWith(
      'advanced',
      expect.stringContaining('Clearing completed with issues'),
      'error',
    );
    expect(showStatus).toHaveBeenCalledWith(
      'simple',
      expect.stringContaining('Clearing completed with issues'),
      'error',
    );
  });

  it('shows metadata lookup fallback status and clears it after timeout', async () => {
    vi.useFakeTimers();
    document.getElementById('modalBody').innerHTML = `
      <div class="credential-aaguid-status">
        <span class="credential-aaguid-spinner" hidden></span>
        <span class="credential-aaguid-status-text"></span>
      </div>
    `;

    window.resolveMdsEntryByAaguid = vi.fn().mockResolvedValueOnce(null);

    const missingResult = await navigateToMdsAuthenticator('00112233-4455-6677-8899-aabbccddeeff');
    expect(missingResult).toEqual({ highlighted: false, entry: null });
    expect(document.querySelector('.credential-aaguid-status-text')?.textContent).toContain('Authenticator metadata not found.');

    vi.advanceTimersByTime(4100);
    expect(document.querySelector('.credential-aaguid-status-text')?.textContent).toBe('');
  });

  it('returns highlighted=false with error payload when tab switch throws during metadata navigation', async () => {
    document.getElementById('modalBody').innerHTML = `
      <div class="credential-aaguid-status">
        <span class="credential-aaguid-spinner" hidden></span>
        <span class="credential-aaguid-status-text"></span>
      </div>
    `;

    window.switchTab = vi.fn(() => {
      throw new Error('tab-switch-failed');
    });

    const result = await navigateToMdsAuthenticator('00112233-4455-6677-8899-aabbccddeeff');

    expect(result).toEqual(
      expect.objectContaining({
        highlighted: false,
        entry: null,
        error: expect.any(Error),
      }),
    );
    expect(document.querySelector('.credential-aaguid-status-text')?.textContent).toContain('Unable to open authenticator metadata.');
  });

  it('skips opening detail/result modals when modal containers are missing', async () => {
    state.storedCredentials = [
      {
        type: 'simple',
        userName: 'No Modal User',
        credentialId: 'AQID',
        credentialIdHex: '010203',
      },
    ];

    document.getElementById('modalBody')?.remove();
    await showCredentialDetails(0);

    document.getElementById('registrationResultBody')?.remove();
    await showRegistrationResultModal({ response: {} }, {});

    expect(openModal).not.toHaveBeenCalledWith('credentialModal');
    expect(openModal).not.toHaveBeenCalledWith('registrationResultModal');
  });
});
