import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../frontend/static/scripts/shared/utils/binary.js', () => {
  const toBytesFromBase64 = (input) => {
    if (typeof input !== 'string' || !input.trim()) {
      return null;
    }
    let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    try {
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    } catch (error) {
      return null;
    }
  };

  const bytesToHex = (bytes) => Array.from(bytes || []).map((byte) => byte.toString(16).padStart(2, '0')).join('');

  const hexToBytes = (value) => {
    if (typeof value !== 'string') {
      return null;
    }
    const clean = value.replace(/[^0-9a-f]/gi, '').toLowerCase();
    if (!clean || clean.length % 2 !== 0) {
      return null;
    }
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
      const parsed = Number.parseInt(clean.slice(i, i + 2), 16);
      if (Number.isNaN(parsed)) {
        return null;
      }
      bytes[i / 2] = parsed;
    }
    return bytes;
  };

  return {
    base64ToBase64Url: vi.fn((value) => String(value || '').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')),
    base64ToHex: vi.fn((value) => {
      const bytes = toBytesFromBase64(value);
      return bytes ? bytesToHex(bytes) : '';
    }),
    base64ToUint8Array: vi.fn((value) => toBytesFromBase64(value)),
    base64UrlToHex: vi.fn((value) => {
      const bytes = toBytesFromBase64(value);
      return bytes ? bytesToHex(bytes) : '';
    }),
    base64UrlToJson: vi.fn((value) => {
      const bytes = toBytesFromBase64(value);
      if (!bytes) {
        return null;
      }
      try {
        const text = new TextDecoder().decode(bytes);
        return JSON.parse(text);
      } catch (error) {
        return null;
      }
    }),
    base64UrlToUint8Array: vi.fn((value) => toBytesFromBase64(value)),
    base64UrlToUtf8String: vi.fn((value) => {
      const bytes = toBytesFromBase64(value);
      return bytes ? new TextDecoder().decode(bytes) : null;
    }),
    bytesToHex: vi.fn((value) => bytesToHex(value)),
    hexToGuid: vi.fn((hex) => {
      const clean = String(hex || '').replace(/[^0-9a-f]/gi, '').toLowerCase();
      if (clean.length !== 32) {
        return '';
      }
      return `${clean.slice(0, 8)}-${clean.slice(8, 12)}-${clean.slice(12, 16)}-${clean.slice(16, 20)}-${clean.slice(20)}`;
    }),
    hexToUint8Array: vi.fn((hex) => hexToBytes(hex)),
    normalizeToHex: vi.fn((value) => {
      if (typeof value !== 'string') {
        return '';
      }
      const clean = value.replace(/[^0-9a-f]/gi, '').toLowerCase();
      return clean || '';
    }),
  };
});

vi.mock('../../../../frontend/static/scripts/advanced/display-utils.js', () => ({
  describeCoseAlgorithm: vi.fn((alg) => `ALG(${String(alg)})`),
  describeCoseKeyType: vi.fn((value) => `KEYTYPE(${String(value)})`),
  describeMldsaParameterSet: vi.fn(() => ''),
  escapeHtml: vi.fn((value) => String(value || '').replaceAll('<', '&lt;').replaceAll('>', '&gt;')),
  formatBoolean: vi.fn((value) => (value ? 'Yes' : 'No')),
  renderAttestationResultRow: vi.fn((label, value, suffix = '') => `<div>${label}:${String(value)}${suffix}</div>`),
}));

vi.mock('../../../../frontend/static/scripts/advanced/credential-utils.js', () => ({
  deriveAaguidDisplayValues: vi.fn((value) => {
    const clean = typeof value === 'string' ? value.replace(/[^0-9a-f]/gi, '').toLowerCase() : '';
    if (clean.length !== 32) {
      return { aaguidHex: '', aaguidB64: '', aaguidB64u: '' };
    }
    const bytes = new Uint8Array(clean.match(/.{2}/g).map((part) => Number.parseInt(part, 16)));
    const b64 = btoa(String.fromCharCode(...bytes));
    const b64u = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    return { aaguidHex: clean, aaguidB64: b64, aaguidB64u: b64u };
  }),
  deriveAaguidFromCredentialData: vi.fn((cred) => cred?.aaguidHex || ''),
  extractMinPinLengthValue: vi.fn((cred) => (typeof cred?.minPinLength === 'number' ? cred.minPinLength : null)),
  getCoseMapValue: vi.fn((map, key) => (map && typeof map === 'object' ? map[key] ?? map[String(key)] : undefined)),
  getCredentialIdHex: vi.fn((cred) => cred?.credentialIdHex || ''),
  getCredentialUserHandleHex: vi.fn((cred) => cred?.userHandleHex || ''),
  getStoredCredentialAttachment: vi.fn((cred) => cred?.attachment || cred?.authenticatorAttachment || null),
  normaliseAaguidValue: vi.fn((value) => {
    if (typeof value !== 'string') {
      return '';
    }
    const clean = value.replace(/[^0-9a-f]/gi, '').toLowerCase();
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

import { deriveAllowedAttachmentsFromHints } from '../../../../frontend/static/scripts/advanced/hints.js';
import { checkLargeBlobCapability, updateAuthenticationExtensionAvailability } from '../../../../frontend/static/scripts/advanced/forms.js';
import { closeModal, openModal } from '../../../../frontend/static/scripts/shared/ui/core.js';
import { showStatus } from '../../../../frontend/static/scripts/shared/ui/status.js';
import {
  clearSimpleCredentials,
  ensureAdvancedCredentialArtifactsSynced,
  getAllAdvancedCredentials,
  getAllSimpleCredentials,
  getAllStoredCredentialsInOrder,
  removeAdvancedCredential,
  removeSimpleCredential,
  updateAdvancedCredentialRegistrationSnapshot,
} from '../../../../frontend/static/scripts/shared/storage/local.js';
import { deleteCredentialArtifact, fetchCredentialArtifact } from '../../../../frontend/static/scripts/shared/storage/artifacts-client.js';
import { updateJsonEditor } from '../../../../frontend/static/scripts/advanced/json-editor.js';
import { state } from '../../../../frontend/static/scripts/shared/state.js';
import {
  autoResizeCertificateTextareas,
  clearAllCredentials,
  closeCredentialModal,
  closeRegistrationDetailModal,
  closeRegistrationResultModal,
  deleteCredential,
  formatCertificateDetails,
  loadSavedCredentials,
  navigateToMdsAuthenticator,
  queueAuthenticatedCredentialFlash,
  queueFailedCredentialFlash,
  showCredentialDetails,
  showRegistrationResultModal,
  updateAllowCredentialsDropdown,
  updateCredentialsDisplay,
} from '../../../../frontend/static/scripts/advanced/credential-display.js';

function buildDom() {
  document.body.innerHTML = `
    <div id="advanced-tab" class="tab-content active">
      <select id="allow-credentials">
        <option value="all">All credentials</option>
      </select>
      <select id="authenticator-attachment">
        <option value="">Any</option>
        <option value="platform">Platform</option>
        <option value="cross-platform">Cross-platform</option>
      </select>
      <button data-credentials-clear>Clear</button>
      <div data-credentials-list></div>
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

function decodeResponse(payload) {
  return {
    ok: true,
    json: vi.fn().mockResolvedValue(payload),
    text: vi.fn().mockResolvedValue(JSON.stringify(payload)),
  };
}

describe('credential-display', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    buildDom();

    state.storedCredentials = [];
    window.switchTab = vi.fn();
    window.highlightMdsAuthenticatorRow = vi.fn(() => ({ highlighted: true, entry: { aaguid: '00112233445566778899aabbccddeeff' } }));
    window.finaliseMdsAuthenticatorHighlight = vi.fn(() => true);
    window.resolveMdsEntryByAaguid = vi.fn().mockResolvedValue({ aaguid: '00112233445566778899aabbccddeeff' });

    globalThis.fetch = vi.fn().mockResolvedValue(
      decodeResponse({
        data: {
          attestationObject: {
            fmt: 'packed',
            attStmt: {
              x5c: [
                {
                  parsedX5c: {
                    subject: 'CN=Example',
                    issuer: 'CN=Issuer',
                  },
                },
              ],
            },
          },
          authenticatorData: {
            raw: '0011',
          },
        },
      }),
    );

    globalThis.confirm = vi.fn(() => true);
  });

  it('formats detailed certificate output with extensions and fingerprint sections', () => {
    const formatted = formatCertificateDetails({
      version: { display: 'v3', hex: '02' },
      serialNumber: { decimal: '123', hex: '7b' },
      signatureAlgorithm: 'sha256WithRSAEncryption',
      issuer: 'CN=Issuer',
      validity: {
        notBefore: '2025-01-01',
        notAfter: '2026-01-01',
      },
      subject: 'CN=Subject',
      publicKeyInfo: {
        algorithm: 'RSA',
        modulusLength: 2048,
      },
      extensions: [
        {
          oid: '1.2.3.4',
          friendlyName: 'test-ext',
          critical: true,
          value: {
            nested: 'value',
          },
        },
      ],
      signature: {
        algorithm: 'rsa',
        lines: ['aa:bb', 'cc:dd'],
      },
      fingerprints: {
        sha256: '00112233',
      },
    });

    expect(formatted).toContain('Version: v3 02');
    expect(formatted).toContain('Certificate Serial Number: 123 / 7b');
    expect(formatted).toContain('X509v3 extensions:');
    expect(formatted).toContain('Signature Algorithm: rsa');
    expect(formatted).toContain('Fingerprint:');

    expect(formatCertificateDetails({ summary: 'precomputed summary' })).toBe('precomputed summary');
    expect(formatCertificateDetails(null)).toBe('');
  });

  it('updates allow-credentials dropdown with attachment filtering and labels', () => {
    state.storedCredentials = [
      {
        userName: 'Platform User',
        credentialIdHex: 'aa11',
        attachment: 'platform',
        algorithm: -7,
      },
      {
        userName: 'Cross User',
        credentialIdHex: 'bb22',
        attachment: 'cross-platform',
        algorithm: -257,
      },
    ];

    document.getElementById('authenticator-attachment').value = 'platform';

    updateAllowCredentialsDropdown();

    const options = Array.from(document.querySelectorAll('#allow-credentials option'));
    const values = options.map((option) => option.value);

    expect(values).toEqual(expect.arrayContaining(['all', 'empty', 'aa11']));
    expect(values).not.toContain('bb22');
    expect(options.find((option) => option.value === 'aa11')?.textContent).toContain('Platform User');

    deriveAllowedAttachmentsFromHints.mockReturnValue(['cross-platform']);
    updateAllowCredentialsDropdown();

    const valuesAfterHint = Array.from(document.querySelectorAll('#allow-credentials option')).map((option) => option.value);
    expect(valuesAfterHint).toContain('bb22');
    expect(valuesAfterHint).not.toContain('aa11');
  });

  it('renders credential cards with status indicators and executes post-render hooks', () => {
    state.storedCredentials = [
      {
        type: 'advanced',
        userName: 'Alice',
        email: 'alice@example.com',
        credentialId: 'AQID',
        credentialIdHex: '010203',
        userHandle: 'BAUG',
        userHandleHex: '040506',
        algorithm: -7,
        residentKey: true,
        largeBlobSupported: true,
        attestationSummary: {
          signatureValid: true,
          rootValid: true,
          rpIdHashValid: true,
        },
        aaguidHex: '00112233445566778899aabbccddeeff',
      },
      {
        type: 'simple',
        userName: 'Bob',
        credentialId: 'Bw==',
        credentialIdHex: '07',
        userHandleHex: '08',
        algorithm: -257,
        attestationSummary: {
          signatureValid: false,
          rootValid: false,
          rpIdHashValid: false,
        },
      },
    ];

    queueAuthenticatedCredentialFlash('010203');
    updateCredentialsDisplay();

    const cards = document.querySelectorAll('.credential-item');
    expect(cards.length).toBe(4);
    expect(document.querySelectorAll('[data-credentials-list]')[0].querySelectorAll('.credential-item').length).toBe(2);
    expect(document.querySelector('[data-credential-id="010203"]')).not.toBeNull();
    expect(document.body.innerHTML).toContain('Discoverable');
    expect(document.body.innerHTML).toContain('Large blob');
    expect(document.body.innerHTML).toContain('FIDO MDS');

    expect(checkLargeBlobCapability).toHaveBeenCalled();
    expect(updateAuthenticationExtensionAvailability).toHaveBeenCalled();

    queueFailedCredentialFlash('07');
    updateCredentialsDisplay();
    expect(document.querySelector('[data-credential-id="07"]')).not.toBeNull();

    state.storedCredentials = [];
    updateCredentialsDisplay();
    expect(document.body.innerHTML).toContain('No credentials registered yet.');
  });

  it('cleans up flash animation class after card animation ends', async () => {
    state.storedCredentials = [
      {
        type: 'advanced',
        userName: 'Flash User',
        credentialIdHex: 'cafebabe',
        userHandleHex: '00aa',
        algorithm: -7,
        attestationSummary: {
          signatureValid: true,
          rootValid: true,
          rpIdHashValid: true,
        },
      },
    ];

    queueAuthenticatedCredentialFlash('cafebabe');
    updateCredentialsDisplay();
    await new Promise((resolve) => setTimeout(resolve, 0));

    const card = document.querySelector('[data-credential-id="cafebabe"]');
    expect(card).not.toBeNull();
    expect(card.classList.contains('credential-item--recent-auth-success')).toBe(true);

    card.dispatchEvent(new Event('animationend'));
    expect(card.classList.contains('credential-item--recent-auth-success')).toBe(false);
  });

  it('drives MDS navigation via card action button and reports unavailable metadata', async () => {
    state.storedCredentials = [
      {
        type: 'advanced',
        userName: 'MDS Action User',
        credentialIdHex: '112233',
        userHandleHex: '445566',
        aaguidHex: '00112233445566778899aabbccddeeff',
        algorithm: -7,
        attestationSummary: {
          signatureValid: true,
          rootValid: true,
          rpIdHashValid: true,
        },
      },
    ];

    updateCredentialsDisplay();

    const mdsButton = document.querySelector('.credential-mds-button');
    expect(mdsButton).not.toBeNull();

    // Force navigateToMdsAuthenticator() to return undefined from missing integration.
    delete window.highlightMdsAuthenticatorRow;

    mdsButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(showStatus).toHaveBeenCalledWith('advanced', 'Authenticator metadata entry unavailable.', 'warning');
    expect(showStatus).toHaveBeenCalledWith('simple', 'Authenticator metadata entry unavailable.', 'warning');
  });

  it('loads saved credentials from storage records and refreshes dependent UI', async () => {
    getAllStoredCredentialsInOrder.mockReturnValue([
      {
        type: 'simple',
        userName: 'Simple User',
        credentialIdHex: 'aa11',
        userHandleHex: 'cc33',
      },
      {
        type: 'advanced',
        userName: 'Advanced User',
        storageId: 'storage-1',
        credentialIdHex: 'bb22',
        userHandleHex: 'dd44',
        relyingParty: {
          aaguid: '00112233445566778899aabbccddeeff',
        },
      },
    ]);

    await loadSavedCredentials();

    expect(state.storedCredentials).toHaveLength(2);
    expect(state.storedCredentials[0].type).toBe('simple');
    expect(state.storedCredentials[1].type).toBe('advanced');
    expect(state.storedCredentials[1].storageId).toBe('storage-1');
    expect(updateJsonEditor).toHaveBeenCalled();
  });

  it('continues loading when credential warmup background sync rejects', async () => {
    getAllStoredCredentialsInOrder.mockReturnValue([
      {
        type: 'advanced',
        userName: 'Advanced User',
        storageId: 'storage-warmup',
        credentialIdHex: 'beef',
        userHandleHex: 'face',
      },
    ]);

    ensureAdvancedCredentialArtifactsSynced.mockRejectedValueOnce(new Error('warmup failed'));

    await loadSavedCredentials();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(state.storedCredentials).toHaveLength(1);
    expect(state.storedCredentials[0].storageId).toBe('storage-warmup');
  });

  it('navigates to MDS authenticator entries and handles missing metadata entries', async () => {
    document.getElementById('modalBody').innerHTML = `
      <div class="credential-aaguid-status">
        <span class="credential-aaguid-spinner" hidden></span>
        <span class="credential-aaguid-status-text"></span>
      </div>
    `;

    const success = await navigateToMdsAuthenticator('00112233-4455-6677-8899-aabbccddeeff');
    expect(window.switchTab).toHaveBeenCalledWith('mds', { preserveMessages: true });
    expect(success).toEqual(expect.objectContaining({ highlighted: true }));
    expect(closeModal).toHaveBeenCalledWith('credentialModal');

    window.resolveMdsEntryByAaguid.mockResolvedValueOnce(null);
    const missing = await navigateToMdsAuthenticator('00112233-4455-6677-8899-aabbccddeeff');
    expect(missing).toEqual({ highlighted: false, entry: null });
  });

  it('shows registration and credential details modals with decoded sections', async () => {
    const credentialJson = {
      id: 'credential-a',
      response: {
        clientDataJSON: btoa(JSON.stringify({ challenge: 'abc' })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
        attestationObject: 'AQID',
        authenticatorData: 'BAUG',
      },
      clientExtensionResults: {
        credProps: {
          rk: true,
        },
      },
    };

    const relyingPartyInfo = {
      attestationFmt: 'packed',
      attestationCertificates: [
        {
          parsedX5c: {
            subject: 'CN=RP Subject',
            issuer: 'CN=RP Issuer',
            fingerprints: {
              sha256: '001122',
            },
          },
        },
      ],
    };

    updateAdvancedCredentialRegistrationSnapshot.mockResolvedValue(true);

    await showRegistrationResultModal(credentialJson, relyingPartyInfo, { storageId: 'storage-1' });

    expect(updateAdvancedCredentialRegistrationSnapshot).toHaveBeenCalledWith(
      'storage-1',
      expect.objectContaining({
        schemaVersion: 1,
        html: expect.any(String),
      }),
    );
    expect(openModal).toHaveBeenCalledWith('registrationResultModal');
    expect(document.getElementById('registrationResultBody').innerHTML).toContain('Authenticator Response');
    expect(document.getElementById('registrationResultBody').innerHTML).toContain('Server-retrieved Data');

    state.storedCredentials = [
      {
        type: 'advanced',
        userName: 'Detailed User',
        displayName: 'Detailed Name',
        email: 'detail@example.com',
        credentialId: 'AQID',
        credentialIdHex: '010203',
        userHandle: 'BAUG',
        userHandleHex: '040506',
        storageId: 'storage-2',
        aaguidHex: '00112233445566778899aabbccddeeff',
        algorithm: -7,
        residentKey: true,
        largeBlobSupported: true,
        minPinLength: 6,
        attestationSummary: {
          signatureValid: true,
          rootValid: true,
          rpIdHashValid: true,
        },
        registrationResponse: credentialJson,
        relyingParty: relyingPartyInfo,
      },
    ];

    fetchCredentialArtifact.mockResolvedValueOnce({
      storedCredential: {
        registrationDetailSnapshot: {
          html: '<section>snapshot html</section>',
          attestationSectionHtml: '',
          combinedHtml: '<section>snapshot html</section>',
          state: {
            attestationObject: null,
            attestationCertificates: [],
            visibleAttestationCertificateIndices: [],
            authenticatorData: null,
            authenticatorDataHex: '',
            authenticatorDataHash: '',
            detailPreparation: {
              attestationObjectValue: '',
              attestationDecodeError: '',
              authenticatorDataValue: '',
              authenticatorDecodeError: '',
            },
          },
        },
      },
    });

    await showCredentialDetails(0);

    expect(openModal).toHaveBeenCalledWith('credentialModal');
    expect(document.getElementById('modalBody').innerHTML).toContain('User info at creation');
    expect(document.getElementById('modalBody').innerHTML).toContain('Properties');
  });

  it('deletes credentials and clears all credentials across simple/advanced stores', async () => {
    state.storedCredentials = [
      {
        type: 'simple',
        userName: 'Simple One',
        credentialIdBase64Url: 'simple-id',
        credentialId: 'simple-id',
        email: 'simple@example.com',
      },
    ];

    getAllStoredCredentialsInOrder.mockReturnValueOnce([]);
    await deleteCredential(0);
    expect(removeSimpleCredential).toHaveBeenCalledWith('simple-id', 'simple@example.com');

    state.storedCredentials = [
      {
        type: 'advanced',
        userName: 'Advanced One',
        credentialIdBase64Url: 'advanced-id',
        credentialId: 'advanced-id',
        storageId: 'storage-advanced',
      },
    ];

    getAllStoredCredentialsInOrder.mockReturnValueOnce([]);
    await deleteCredential(0);
    expect(removeAdvancedCredential).toHaveBeenCalledWith('advanced-id', 'storage-advanced');
    expect(deleteCredentialArtifact).toHaveBeenCalledWith('storage-advanced');

    getAllSimpleCredentials.mockReturnValue([{ id: 1 }]);
    getAllAdvancedCredentials.mockReturnValue([{ storageId: 'storage-a', credentialIdBase64Url: 'advanced-clear-id' }]);
    getAllStoredCredentialsInOrder.mockReturnValueOnce([]);

    await clearAllCredentials();
    expect(clearSimpleCredentials).toHaveBeenCalled();
    expect(removeAdvancedCredential).toHaveBeenCalledWith('advanced-clear-id', 'storage-a');
    expect(deleteCredentialArtifact).toHaveBeenCalledWith('storage-a');

    getAllSimpleCredentials.mockReturnValue([]);
    getAllAdvancedCredentials.mockReturnValue([]);

    await clearAllCredentials();
    expect(showStatus).toHaveBeenCalledWith('advanced', 'No saved credentials to clear.', 'info');
  });

  it('resizes certificate textareas for dynamic content safely', () => {
    document.getElementById('registrationDetailModalBody').innerHTML = `
      <textarea class="certificate-textarea">line one\nline two</textarea>
      <div class="certificate-textarea">not a textarea</div>
    `;

    autoResizeCertificateTextareas(document.getElementById('registrationDetailModalBody'));

    const textarea = document.querySelector('#registrationDetailModalBody textarea');
    expect(textarea.style.overflowY).toBe('hidden');
  });

  it('handles navigation integration gaps and highlight finalization fallback states', async () => {
    document.getElementById('modalBody').innerHTML = `
      <div class="credential-aaguid-status">
        <span class="credential-aaguid-spinner" hidden></span>
        <span class="credential-aaguid-status-text"></span>
      </div>
    `;

    delete window.highlightMdsAuthenticatorRow;
    const unavailable = navigateToMdsAuthenticator('00112233-4455-6677-8899-aabbccddeeff');
    expect(unavailable).toBeUndefined();

    window.highlightMdsAuthenticatorRow = vi.fn()
      .mockResolvedValueOnce({ highlighted: true, entry: { aaguid: '00112233445566778899aabbccddeeff' } })
      .mockResolvedValueOnce({ highlighted: false, entry: { aaguid: '00112233445566778899aabbccddeeff' } });
    window.finaliseMdsAuthenticatorHighlight = vi.fn(() => false);
    window.resolveMdsEntryByAaguid = vi.fn().mockResolvedValue({ aaguid: '00112233445566778899aabbccddeeff' });

    const result = await navigateToMdsAuthenticator('00112233-4455-6677-8899-aabbccddeeff');
    expect(result).toEqual(
      expect.objectContaining({
        highlighted: false,
        entry: expect.objectContaining({ aaguid: '00112233445566778899aabbccddeeff' }),
      }),
    );

    const statusText = document.querySelector('.credential-aaguid-status-text')?.textContent || '';
    expect(statusText).toContain('Unable to locate metadata entry.');
  });

  it('renders decode failures in registration-result modal without crashing', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      json: vi.fn().mockResolvedValue({ error: 'decode failed' }),
      text: vi.fn().mockResolvedValue('decode failed'),
    });

    await showRegistrationResultModal(
      {
        id: 'credential-error',
        response: {
          clientDataJSON: btoa(JSON.stringify({ challenge: 'x' })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
          attestationObject: 'not-decodable-attestation',
          authenticatorData: 'not-decodable-auth-data',
        },
      },
      {
        attestationFmt: 'packed',
      },
    );

    expect(openModal).toHaveBeenCalledWith('registrationResultModal');
    const resultHtml = document.getElementById('registrationResultBody').innerHTML;
    expect(resultHtml).toContain('decode failed');
  });

  it('uses snapshot detail buttons for certificate/authenticator drill-down modals', async () => {
    state.storedCredentials = [
      {
        type: 'advanced',
        userName: 'Snapshot User',
        credentialId: 'AQID',
        credentialIdHex: '010203',
        userHandle: 'BAUG',
        userHandleHex: '040506',
        storageId: 'snapshot-storage',
        aaguidHex: '00112233445566778899aabbccddeeff',
        registrationDetailSnapshot: {
          html: '<section>snapshot intro</section>',
          attestationSectionHtml: '',
          combinedHtml: `
            <section>
              <button type="button" class="btn btn-small registration-attestation-cert-button" data-cert-index="0">Attestation Certificate</button>
              <button type="button" class="btn btn-small btn-secondary registration-authenticator-data-button">Authenticator Data</button>
            </section>
          `,
          state: {
            attestationObject: {
              fmt: 'packed',
              attStmt: {},
            },
            attestationCertificates: [
              {
                parsedX5c: {
                  summary: 'Snapshot certificate summary',
                },
              },
            ],
            visibleAttestationCertificateIndices: [0],
            authenticatorData: {
              raw: '001122',
            },
            authenticatorDataHex: '001122',
            authenticatorDataHash: 'aa55',
            detailPreparation: {
              attestationObjectValue: '',
              attestationDecodeError: '',
              authenticatorDataValue: '',
              authenticatorDecodeError: '',
            },
          },
        },
      },
    ];

    await showCredentialDetails(0);
    expect(openModal).toHaveBeenCalledWith('credentialModal');

    const certButton = document.querySelector('.registration-attestation-cert-button');
    certButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(openModal).toHaveBeenCalledWith('registrationDetailModal');
    expect(document.getElementById('registrationDetailModalTitle').textContent).toContain('Attestation Certificate');

    const authButton = document.querySelector('.registration-authenticator-data-button');
    authButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(document.getElementById('registrationDetailModalTitle').textContent).toContain('Authenticator Data');
    expect(document.getElementById('registrationDetailModalBody').innerHTML).toContain('001122');
  });

  it('restores legacy snapshot certificate visibility when indices are missing', async () => {
    state.storedCredentials = [
      {
        type: 'advanced',
        userName: 'Legacy Snapshot User',
        credentialId: 'AQID',
        credentialIdHex: '010203',
        userHandle: 'BAUG',
        userHandleHex: '040506',
        storageId: 'legacy-snapshot-storage',
        aaguidHex: '00112233445566778899aabbccddeeff',
        registrationDetailSnapshot: {
          html: '<section>legacy snapshot</section>',
          attestationSectionHtml: '',
          combinedHtml: `
            <section>
              <button type="button" class="btn btn-small registration-attestation-cert-button" data-cert-index="0">Attestation Certificate</button>
            </section>
          `,
          state: {
            attestationObject: {
              fmt: 'packed',
              attStmt: {},
            },
            attestationCertificates: [
              {
                parsedX5c: {
                  summary: 'Legacy snapshot certificate summary',
                },
              },
            ],
            visibleAttestationCertificateIndices: [],
            authenticatorData: {
              value: '001122',
            },
            authenticatorDataHex: '001122',
            authenticatorDataHash: 'aabb',
            detailPreparation: {
              attestationObjectValue: '',
              attestationDecodeError: '',
              authenticatorDataValue: '',
              authenticatorDecodeError: '',
            },
          },
        },
      },
    ];

    await showCredentialDetails(0);

    const certButton = document.querySelector('.registration-attestation-cert-button');
    expect(certButton).not.toBeNull();

    certButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(openModal).toHaveBeenCalledWith('registrationDetailModal');
    expect(document.getElementById('registrationDetailModalBody').innerHTML).toContain('Legacy snapshot certificate summary');
  });

  it('keeps state intact when delete/clear confirmations are cancelled', async () => {
    state.storedCredentials = [
      {
        type: 'simple',
        userName: 'Cancel User',
        credentialIdBase64Url: 'cancel-id',
        credentialId: 'cancel-id',
        email: 'cancel@example.com',
      },
    ];

    globalThis.confirm = vi.fn(() => false);

    await deleteCredential(0);
    expect(removeSimpleCredential).not.toHaveBeenCalled();

    getAllSimpleCredentials.mockReturnValue([{ id: 's1' }]);
    getAllAdvancedCredentials.mockReturnValue([{ storageId: 'a1' }]);

    await clearAllCredentials();
    expect(clearSimpleCredentials).not.toHaveBeenCalled();
    expect(deleteCredentialArtifact).not.toHaveBeenCalled();
  });

  it('exposes modal close helpers through exported wrappers', () => {
    closeCredentialModal();
    closeRegistrationResultModal();
    closeRegistrationDetailModal();

    expect(closeModal).toHaveBeenCalledWith('credentialModal');
    expect(closeModal).toHaveBeenCalledWith('registrationResultModal');
    expect(closeModal).toHaveBeenCalledWith('registrationDetailModal');
  });

  it('still opens credential details when artifact hydration fails', async () => {
    fetchCredentialArtifact.mockRejectedValueOnce(new Error('artifact unavailable'));

    state.storedCredentials = [
      {
        type: 'advanced',
        userName: 'Hydrate Failure User',
        credentialId: 'AQID',
        credentialIdHex: '010203',
        userHandle: 'BAUG',
        userHandleHex: '040506',
        storageId: 'hydrate-failure-storage',
        aaguidHex: '00112233445566778899aabbccddeeff',
      },
    ];

    await showCredentialDetails(0);
    expect(fetchCredentialArtifact).toHaveBeenCalledWith('hydrate-failure-storage');
    expect(openModal).toHaveBeenCalledWith('credentialModal');
    expect(document.getElementById('modalBody').innerHTML).toContain('Authenticator Response');
  });
});
