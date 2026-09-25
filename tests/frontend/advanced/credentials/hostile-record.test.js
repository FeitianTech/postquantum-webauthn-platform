import { beforeEach, describe, expect, it, vi } from 'vitest';

// A credential record whose every string was chosen by an attacker: a user name
// typed into the request editor, an RP name, extension outputs, attestation
// certificate names and extension values (chosen by whoever built the
// authenticator), metadata descriptions, and stored registration HTML. Every
// credential view is rendered through its real runtime; only the modal
// open/close calls, the status toasts, the editor and storage are stubbed.

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

vi.mock('../../../../frontend/static/scripts/advanced/editor/index.js', () => ({
  updateJsonEditor: vi.fn(),
}));

vi.mock('../../../../frontend/static/scripts/advanced/auth/forms.js', () => ({
  checkLargeBlobCapability: vi.fn(),
  updateAuthenticationExtensionAvailability: vi.fn(),
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

import { fetchCredentialArtifact } from '../../../../frontend/static/scripts/shared/storage/artifacts-client.js';
import { state } from '../../../../frontend/static/scripts/shared/state.js';
import {
  showCredentialDetails,
  showRegistrationResultModal,
  updateAllowCredentialsDropdown,
  updateCredentialsDisplay,
} from '../../../../frontend/static/scripts/advanced/credentials/index.js';

// What an injected handler does. jsdom runs inline handlers in its own global,
// which the test cannot read, so the handler also marks <html data-xss>, which
// it can.
const RUN = 'window.__xss=1;document.documentElement.dataset.xss=1';

// Breaks out of element text, a double- or single-quoted attribute, a textarea
// and a pre. Each field gets its own label so a failure names the field.
const PAYLOAD = [
  `"><img src=x onerror="${RUN}">`,
  `'><svg onload=${RUN}>`,
  `</textarea><img src=x onerror=${RUN}>`,
  `</pre><img src=x onerror=${RUN}>`,
].join('');
const STORED_HTML = `<section><img src=x onerror="${RUN}">${PAYLOAD}</section>`;

function hostile(label) {
  return `${label}:${PAYLOAD}`;
}

function toBase64Url(text) {
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function hostileCertificate(label) {
  return {
    parsedX5c: {
      version: hostile(`${label}.version`),
      serialNumber: hostile(`${label}.serial`),
      signatureAlgorithm: hostile(`${label}.signatureAlgorithm`),
      issuer: hostile(`${label}.issuer`),
      subject: hostile(`${label}.subject`),
      validity: { notBefore: hostile(`${label}.notBefore`), notAfter: hostile(`${label}.notAfter`) },
      publicKeyInfo: { algorithm: hostile(`${label}.keyAlgorithm`) },
      extensions: [
        {
          oid: '1.3.6.1.4.1.45724.1.1.4',
          name: hostile(`${label}.extension.name`),
          friendlyName: hostile(`${label}.extension.friendlyName`),
          critical: true,
          value: { text: hostile(`${label}.extension.value`), list: [hostile(`${label}.extension.item`)] },
        },
      ],
    },
  };
}

const HOSTILE_CLIENT_DATA = toBase64Url(JSON.stringify({
  type: 'webauthn.create',
  challenge: hostile('clientData.challenge'),
  origin: hostile('clientData.origin'),
}));

function hostileRelyingParty() {
  return {
    id: hostile('relyingParty.id'),
    name: hostile('relyingParty.name'),
    attestationFmt: hostile('relyingParty.attestationFmt'),
    attestationCertificates: [
      hostileCertificate('certificate'),
      { parsedX5c: { summary: hostile('certificate.summary') } },
    ],
    registrationData: {
      attestationChecks: {
        metadata: {
          description: hostile('mds.description'),
          verification_warning: hostile('mds.warning'),
        },
        root_checks: { fido_mds: hostile('rootChecks.fidoMds') },
      },
      customMetadata: { description: hostile('customMetadata.description') },
    },
  };
}

function hostileRecord(extra = {}) {
  return {
    type: 'advanced',
    storageId: 'hostile-storage',
    userName: hostile('userName'),
    username: hostile('username'),
    displayName: hostile('displayName'),
    email: hostile('email'),
    // Real base64: the identifiers are decoded before anything is shown.
    credentialId: 'AQIDBAUGBwg=',
    credentialIdHex: '0102030405060708',
    userHandle: 'CQoLDA==',
    aaguid: hostile('aaguid'),
    aaguidGuid: hostile('aaguidGuid'),
    attestationFormat: hostile('attestationFormat'),
    flags: {
      at: hostile('flags.at'),
      be: hostile('flags.be'),
      bs: hostile('flags.bs'),
      ed: hostile('flags.ed'),
      up: hostile('flags.up'),
      uv: hostile('flags.uv'),
    },
    signCount: hostile('signCount'),
    clientExtensionOutputs: {
      credProps: { rk: hostile('extension.credProps') },
      [hostile('extension.key')]: hostile('extension.value'),
    },
    publicKeyAlgorithm: hostile('publicKeyAlgorithm').replace(/[0-9]/g, ''),
    publicKeyType: hostile('publicKeyType').replace(/[0-9]/g, ''),
    residentKey: hostile('residentKey'),
    largeBlob: hostile('largeBlob'),
    metadata: { verification_warning: hostile('metadata.warning') },
    properties: { aaguid: hostile('properties.aaguid') },
    relyingParty: hostileRelyingParty(),
    attestationCertificates: [hostileCertificate('recordCertificate')],
    clientDataJSON: HOSTILE_CLIENT_DATA,
    registrationResponse: {
      id: 'AQIDBAUGBwg',
      rawId: 'AQIDBAUGBwg',
      type: hostile('registrationResponse.type'),
      response: {
        clientDataJSON: HOSTILE_CLIENT_DATA,
        attestationObject: 'o2NmbXRkbm9uZQ',
      },
    },
    ...extra,
  };
}

function decodeResponse() {
  const body = {
    data: {
      attestationObject: {
        fmt: hostile('decoded.fmt'),
        attStmt: { alg: hostile('decoded.alg'), x5c: [hostileCertificate('decodedCertificate')] },
      },
      authenticatorData: {
        rpIdHash: hostile('decoded.rpIdHash'),
        flags: { UP: hostile('decoded.flags') },
      },
    },
  };
  return {
    ok: true,
    status: 200,
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

function buildDom() {
  document.body.innerHTML = `
    <div id="advanced-tab" class="tab-content active">
      <select id="allow-credentials"><option value="all">All credentials</option></select>
      <select id="authenticator-attachment"><option value="">Any</option></select>
      <button data-credentials-clear>Clear</button>
      <div data-credentials-list></div>
    </div>
    <div id="modalBody"></div>
    <div id="registrationResultBody"></div>
    <div id="registrationDetailModal"></div>
    <h3 id="registrationDetailModalTitle"></h3>
    <div id="registrationDetailModalBody"></div>
  `;
}

// Fire what an attacker's markup waits for: an image that failed to load and an
// SVG that loaded. vitest's jsdom compiles inline handlers (runScripts:
// "dangerously"), so a handler that came from data runs here as in a browser.
function inspect(root) {
  root.querySelectorAll('img').forEach((node) => node.dispatchEvent(new Event('error')));
  root.querySelectorAll('svg').forEach((node) => node.dispatchEvent(new Event('load')));
  const injected = Array.from(root.querySelectorAll('img, svg, script, iframe, object, embed'))
    .map((node) => node.tagName.toLowerCase());
  const handlers = Array.from(root.querySelectorAll('*')).flatMap((node) => Array.from(node.attributes)
    .filter((attribute) => /^on/i.test(attribute.name))
    .map((attribute) => `${node.tagName.toLowerCase()}[${attribute.name}]`));
  return {
    injected,
    handlers,
    ran: window.__xss !== undefined || document.documentElement.dataset.xss !== undefined,
  };
}

async function renderCards() {
  state.storedCredentials = [hostileRecord()];
  updateCredentialsDisplay();
  return document.querySelector('[data-credentials-list]');
}

async function renderAllowList() {
  state.storedCredentials = [hostileRecord()];
  updateAllowCredentialsDropdown();
  return document.getElementById('allow-credentials');
}

async function renderDetail(record) {
  state.storedCredentials = [record];
  await showCredentialDetails(0);
  return document.getElementById('modalBody');
}

async function renderRegistrationResult() {
  await showRegistrationResultModal(
    {
      id: 'AQIDBAUGBwg',
      rawId: 'AQIDBAUGBwg',
      type: hostile('credential.type'),
      authenticatorAttachment: hostile('credential.attachment'),
      clientExtensionResults: { [hostile('credential.extension')]: hostile('credential.extensionValue') },
      response: {
        clientDataJSON: HOSTILE_CLIENT_DATA,
        attestationObject: 'o2NmbXRkbm9uZQ',
        authenticatorData: 'AAAA',
      },
    },
    hostileRelyingParty(),
    { storageId: 'hostile-storage' },
  );
  return document.getElementById('registrationResultBody');
}

async function renderCertificateDetail() {
  await renderRegistrationResult();
  document.querySelector('#registrationResultBody .registration-attestation-cert-button').click();
  return document.getElementById('registrationDetailModalBody');
}

async function renderAuthenticatorDataDetail() {
  await renderRegistrationResult();
  document.querySelector('#registrationResultBody .registration-authenticator-data-button').click();
  return document.getElementById('registrationDetailModalBody');
}

// Whether each view ran the payload on the code of this commit. A view "runs" it
// when data became an element or an on* attribute, or a handler fired. Until
// registration details were built from data, the three stored-HTML paths did.
const VIEWS = [
  ['saved-credential cards', renderCards, false],
  ['allow-credentials options', renderAllowList, false],
  ['credential detail modal', () => renderDetail(hostileRecord()), false],
  ['credential detail modal, snapshot saved in this browser', () => renderDetail(hostileRecord({
    registrationDetailSnapshot: { html: STORED_HTML, combinedHtml: STORED_HTML, state: {} },
  })), false],
  ['credential detail modal, raw registrationDetailHtml key', () => renderDetail(hostileRecord({
    registrationDetailHtml: STORED_HTML,
  })), false],
  ['credential detail modal, snapshot from the server artifact', () => {
    fetchCredentialArtifact.mockResolvedValueOnce({
      storedCredential: { displayName: hostile('artifact.displayName') },
      registrationDetailSnapshot: { html: STORED_HTML, combinedHtml: STORED_HTML, state: {} },
    });
    return renderDetail(hostileRecord());
  }, false],
  ['registration result modal', renderRegistrationResult, false],
  ['attestation certificate sub-modal', renderCertificateDetail, false],
  ['authenticator data sub-modal', renderAuthenticatorDataDetail, false],
];

describe('a hostile credential record', () => {
  beforeEach(() => {
    buildDom();
    delete window.__xss;
    delete document.documentElement.dataset.xss;
    state.storedCredentials = [];
    globalThis.fetch = vi.fn(async () => decodeResponse());
    fetchCredentialArtifact.mockResolvedValue(null);
  });

  it('would be caught: markup from data becomes an element and its handler runs', () => {
    const root = document.getElementById('modalBody');
    root.innerHTML = `<div>${PAYLOAD}</div>`;

    const result = inspect(root);

    expect(result.injected).toContain('img');
    expect(result.handlers).toContain('img[onerror]');
    expect(result.ran).toBe(true);
  });

  it.each(VIEWS)('%s', async (_name, render, runsPayload) => {
    const root = await render();
    const result = inspect(root);

    const ranPayload = result.ran || result.injected.length > 0 || result.handlers.length > 0;
    expect(ranPayload, JSON.stringify(result)).toBe(runsPayload);
    if (runsPayload) {
      expect(result.ran).toBe(true);
    } else {
      // Shown as text: as written, or as it reads inside a JSON dump.
      const text = root.textContent;
      expect(text.includes(PAYLOAD) || text.includes(JSON.stringify(PAYLOAD).slice(1, -1))).toBe(true);
    }
  });
});
