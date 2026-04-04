import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../static/scripts/shared/loader.js', () => ({
  loaderIsActive: vi.fn(() => false),
  loaderSetMetadataCount: vi.fn(),
  loaderSetPhase: vi.fn(),
  loaderSetProgress: vi.fn(),
}));

vi.mock('../../static/scripts/shared/ui.js', () => ({
  initializeStickyHeaderForElement: vi.fn(() => {
    const miniHeader = document.createElement('div');
    const miniInner = document.createElement('div');
    miniHeader.appendChild(miniInner);
    document.body.appendChild(miniHeader);

    return {
      miniHeader,
      miniInner,
      reset: vi.fn(),
      refreshGeometry: vi.fn(),
      evaluate: vi.fn(),
    };
  }),
}));

function buildMdsDom() {
  document.body.innerHTML = `
    <div id="mds-tab">
      <div id="mds-status" class="mds-status mds-status-info">Initial status</div>
      <button id="mds-retry-button">Retry</button>
      <button id="mds-update-button">Refresh Metadata</button>
      <button id="mds-add-metadata-button">Add Metadata</button>

      <div id="mds-custom-metadata-panel" hidden>
        <div class="mds-custom-panel__dialog">
          <button id="mds-custom-panel-close">Close</button>
          <div id="mds-custom-messages"></div>
          <ul id="mds-custom-list"></ul>
          <div id="mds-custom-dropzone" tabindex="0">Drop JSON</div>
          <input id="mds-custom-file-input" type="file" />
        </div>
      </div>

      <section id="mds-list-section">
        <div id="mds-entry-count"></div>
        <div id="mds-total-count"></div>

        <input id="mds-filter-name" />
        <input id="mds-filter-protocol" />
        <input id="mds-filter-certification" />
        <input id="mds-filter-id" />
        <input id="mds-filter-user-verification" />
        <input id="mds-filter-attachment" />
        <input id="mds-filter-transports" />
        <input id="mds-filter-key-protection" />
        <input id="mds-filter-algorithms" />
        <input id="mds-filter-algorithm-info" />
        <input id="mds-filter-common-name" />

        <div id="mds-table-container">
          <table class="mds-table">
            <thead>
              <tr>
                <th><button class="mds-sort-button" data-sort-key="icon" data-sort-label="icon">Icon</button></th>
                <th><button class="mds-sort-button" data-sort-key="name" data-sort-label="name">Name</button></th>
                <th><button class="mds-sort-button" data-sort-key="protocol" data-sort-label="protocol">Protocol</button></th>
                <th><button class="mds-sort-button" data-sort-key="certification" data-sort-label="certification">Certification</button></th>
                <th><button class="mds-sort-button" data-sort-key="id" data-sort-label="id">ID</button></th>
                <th><button class="mds-sort-button" data-sort-key="userVerification" data-sort-label="uv">UV</button></th>
                <th><button class="mds-sort-button" data-sort-key="attachment" data-sort-label="attachment">Attachment</button></th>
                <th><button class="mds-sort-button" data-sort-key="transports" data-sort-label="transport">Transports</button></th>
                <th><button class="mds-sort-button" data-sort-key="keyProtection" data-sort-label="key-protection">Key Protection</button></th>
                <th><button class="mds-sort-button" data-sort-key="algorithms" data-sort-label="algorithms">Algorithms</button></th>
                <th><button class="mds-sort-button" data-sort-key="algorithmInfo" data-sort-label="algorithm-info">Algorithm Info</button></th>
                <th><button class="mds-sort-button" data-sort-key="commonName" data-sort-label="common-name">Common Name</button></th>
                <th><button class="mds-sort-button" data-sort-key="dateUpdated" data-sort-label="date-updated">Date Updated</button></th>
              </tr>
            </thead>
            <tbody id="mds-table-body"></tbody>
          </table>
        </div>

        <div id="mds-horizontal-scroll"><div class="mds-horizontal-scroll__content"></div></div>
      </section>

      <button id="mds-scroll-top-button">Top</button>

      <section id="mds-certificate-page" class="mds-detail-page" hidden>
        <header class="mds-detail-page__header">
          <button id="mds-certificate-page-close" class="mds-detail-page__back">Back</button>
          <h2 id="mds-certificate-page-title" class="mds-detail-page__title">Attestation Certificate</h2>
          <p id="mds-certificate-page-subtitle" class="mds-detail-page__subtitle"></p>
          <div class="mds-detail-page__actions"></div>
        </header>
        <div id="mds-certificate-page-body"></div>
        <div id="mds-certificate-summary"></div>
        <textarea id="mds-certificate-input"></textarea>
        <textarea id="mds-certificate-output"></textarea>
      </section>

      <section id="mds-authenticator-modal" class="mds-detail-page" hidden>
        <header class="mds-detail-page__header">
          <button id="mds-authenticator-modal-close" class="mds-detail-page__back">Back</button>
          <h2 id="mds-authenticator-modal-title" class="mds-detail-page__title">Authenticator</h2>
          <p id="mds-authenticator-modal-subtitle" class="mds-detail-page__subtitle"></p>
          <div class="mds-detail-page__actions">
            <button id="mds-authenticator-modal-raw">Raw</button>
          </div>
        </header>
        <div id="mds-authenticator-modal-body">
          <div id="mds-authenticator-modal-content"></div>
        </div>
      </section>
    </div>
  `;
}

function makeSnapshotEntries() {
  const commonMetadata = {
    description: 'Alpha Key',
    protocolFamily: 'fido2',
    userVerificationDetails: [[{ userVerificationMethod: 'presence_internal' }]],
    attachmentHint: ['internal'],
    transports: ['usb'],
    keyProtection: ['hardware'],
    authenticationAlgorithms: ['secp256r1_ecdsa_sha256_raw'],
    attestationRootCertificates: ['Q0VSVA=='],
    authenticatorGetInfo: {
      transports: ['usb'],
      versions: ['FIDO_2_0'],
      extensions: ['credProtect'],
      options: {
        rk: true,
      },
    },
  };

  return [
    {
      entryId: 'entry-alpha',
      name: 'Alpha Key',
      protocol: 'FIDO2',
      certification: 'FIDO Certified L1',
      certificationStatus: 'FIDO_CERTIFIED_L1',
      id: '00112233-4455-6677-8899-aabbccddeeff',
      aaguid: '00112233-4455-6677-8899-aabbccddeeff',
      icon: '',
      userVerification: 'Presence Internal',
      userVerificationList: ['Presence Internal'],
      attachment: 'Internal',
      attachmentList: ['Internal'],
      transports: 'USB',
      transportsList: ['USB'],
      keyProtection: 'Hardware',
      keyProtectionList: ['Hardware'],
      algorithms: 'ES256',
      algorithmsList: ['ES256'],
      certificateAlgorithmInfo: 'RSA 2048',
      certificateAlgorithmInfoList: ['RSA 2048'],
      certificateCommonNames: 'CN=Alpha',
      certificateCommonNameList: ['CN=Alpha'],
      dateUpdated: 'Apr 3, 2026',
      dateTooltip: '2026-04-03T00:00:00Z',
      metadataStatement: {
        ...commonMetadata,
      },
      rawEntry: {
        aaguid: '00112233-4455-6677-8899-aabbccddeeff',
        metadataStatement: {
          ...commonMetadata,
        },
      },
      statusReports: [
        {
          status: 'FIDO_CERTIFIED_L1',
          effectiveDate: '2026-04-03',
          certificationDescriptor: 'L1',
        },
      ],
      attestationCertificates: ['Q0VSVA=='],
      attestationKeyIdentifiers: ['key-alpha'],
      isLightweightEntry: false,
    },
    {
      entryId: 'entry-beta',
      name: 'Beta Key',
      protocol: 'FIDO2',
      certification: 'Not FIDO Certified',
      certificationStatus: 'NOT_FIDO_CERTIFIED',
      id: 'aaid-beta',
      aaguid: '',
      icon: '',
      userVerification: 'Presence Internal',
      userVerificationList: ['Presence Internal'],
      attachment: 'External',
      attachmentList: ['External'],
      transports: 'NFC',
      transportsList: ['NFC'],
      keyProtection: 'Hardware',
      keyProtectionList: ['Hardware'],
      algorithms: 'RS256',
      algorithmsList: ['RS256'],
      certificateAlgorithmInfo: 'RSA 2048',
      certificateAlgorithmInfoList: ['RSA 2048'],
      certificateCommonNames: 'CN=Beta',
      certificateCommonNameList: ['CN=Beta'],
      dateUpdated: 'Apr 2, 2026',
      dateTooltip: '2026-04-02T00:00:00Z',
      metadataStatement: {
        ...commonMetadata,
        description: 'Beta Key',
      },
      rawEntry: {
        aaid: 'aaid-beta',
        metadataStatement: {
          ...commonMetadata,
          description: 'Beta Key',
        },
      },
      statusReports: [
        {
          status: 'NOT_FIDO_CERTIFIED',
          effectiveDate: '2026-04-02',
          certificationDescriptor: 'None',
        },
      ],
      attestationCertificates: ['Q0VSVA=='],
      attestationKeyIdentifiers: ['key-beta'],
      isLightweightEntry: false,
    },
  ];
}

function jsonResponse(payload, ok = true, status = 200) {
  return {
    ok,
    status,
    json: vi.fn().mockResolvedValue(payload),
    text: vi.fn().mockResolvedValue(typeof payload === 'string' ? payload : JSON.stringify(payload)),
  };
}

async function waitForCondition(predicate, timeoutMs = 800, intervalMs = 20) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (predicate()) {
      return true;
    }
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  return false;
}

function eventWithDataTransfer(type, files = []) {
  const event = new Event(type, { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'dataTransfer', {
    configurable: true,
    value: {
      files,
      dropEffect: 'copy',
    },
  });
  return event;
}

describe('mds explorer', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    buildMdsDom();
    vi.resetModules();

    window.__INITIAL_MDS_INFO__ = {
      entryCount: 2,
      no: 7,
      generatedAt: '2026-04-03T12:00:00Z',
    };
    window.__INITIAL_MDS_SNAPSHOT__ = {
      meta: {
        entryCount: 2,
        no: 7,
        generatedAt: '2026-04-03T12:00:00Z',
      },
      entries: makeSnapshotEntries(),
      legalHeader: 'FIDO legal header',
    };

    globalThis.fetch = vi.fn((url) => {
      if (String(url).includes('/api/mds/decode-certificate')) {
        return Promise.resolve(
          jsonResponse({
            details: {
              subject: 'CN=Certificate Subject',
              issuer: 'CN=Certificate Issuer',
              summary: 'Certificate summary details',
              publicKeyInfo: {
                algorithm: {
                  name: 'RSA',
                  modulusLength: 2048,
                },
              },
              signature: {
                algorithm: 'rsa',
                hash: 'sha256',
                hex: 'deadbeef',
              },
            },
          }),
        );
      }

      if (String(url).includes('api/mds/metadata/explorer/full')) {
        return Promise.resolve(
          jsonResponse({
            meta: {
              entryCount: 2,
              no: 8,
              generatedAt: '2026-04-04T12:00:00Z',
            },
            entries: makeSnapshotEntries(),
            legalHeader: 'FIDO legal header',
          }),
        );
      }

      if (String(url).includes('fido-mds3.verified.json.meta.json')) {
        return Promise.resolve(jsonResponse({ generatedAt: '2026-04-04T12:00:00Z' }));
      }

      return Promise.resolve(jsonResponse({ items: [] }));
    });
  });

  it('initializes from bootstrap snapshot and supports filtering, sorting, detail, and refresh actions', async () => {
    const module = await import('../../static/scripts/advanced/mds.js');

    document.dispatchEvent(new Event('DOMContentLoaded'));
    await waitForCondition(() => document.querySelectorAll('#mds-table-body tr').length === 2, 1000);

    const tableRows = document.querySelectorAll('#mds-table-body tr');
    expect(tableRows.length).toBe(2);
    expect(document.getElementById('mds-entry-count').textContent).toBe('2');
    expect(document.getElementById('mds-total-count').textContent).toContain('2 total');
    expect(document.getElementById('mds-status').textContent).toContain('Loaded 2 authenticators.');

    const nameFilter = document.getElementById('mds-filter-name');
    nameFilter.value = 'Alpha';
    nameFilter.dispatchEvent(new Event('input', { bubbles: true }));

    expect(document.querySelectorAll('#mds-table-body tr').length).toBe(1);
    expect(document.getElementById('mds-entry-count').textContent).toBe('1');

    const sortButton = document.querySelector('.mds-sort-button[data-sort-key="name"]');
    sortButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(sortButton.getAttribute('data-sort-direction')).toMatch(/asc|desc/);

    const nameButton = document.querySelector('.mds-name-button');
    nameButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await Promise.resolve();

    const authenticatorModal = document.getElementById('mds-authenticator-modal');
    expect(authenticatorModal.hidden).toBe(false);
    expect(authenticatorModal.classList.contains('mds-detail-page--open')).toBe(true);
    expect(document.getElementById('mds-authenticator-modal-content').textContent).toContain('Alpha Key');

    const certButton = document.querySelector('.mds-certificate-button');
    expect(certButton).not.toBeNull();
    certButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await waitForCondition(
      () => document.getElementById('mds-certificate-output').value.includes('Certificate summary details'),
      1000,
    );

    expect(document.getElementById('mds-certificate-page').hidden).toBe(false);
    expect(document.getElementById('mds-certificate-output').value).toContain('Certificate summary details');

    document.getElementById('mds-certificate-page-close').dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 550));
    expect(document.getElementById('mds-certificate-page').hidden).toBe(true);

    const highlighted = await window.highlightMdsAuthenticatorRow('00112233-4455-6677-8899-aabbccddeeff', {
      waitForVisibility: false,
      scrollBehavior: 'auto',
    });
    expect(highlighted.highlighted).toBe(true);

    const resolved = await window.resolveMdsEntryByAaguid('00112233-4455-6677-8899-aabbccddeeff');
    expect(resolved?.name).toBe('Alpha Key');

    const loaded = await module.waitForMetadataLoad();
    expect(loaded).toBe(true);

    document.getElementById('mds-update-button').dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await waitForCondition(
      () => document.getElementById('mds-status').textContent.includes('Loaded 2 authenticators.'),
      1200,
    );

    expect(globalThis.fetch).toHaveBeenCalledWith(
      'api/mds/metadata/explorer/full',
      expect.objectContaining({ cache: 'reload' }),
    );
    expect(document.getElementById('mds-status').textContent).toContain('Loaded 2 authenticators.');

    document.getElementById('mds-add-metadata-button').dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(document.getElementById('mds-custom-metadata-panel').classList.contains('is-open')).toBe(true);

    document.getElementById('mds-custom-panel-close').dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 450));
    expect(document.getElementById('mds-custom-metadata-panel').hidden).toBe(true);
  });

  it('falls back to empty-state message when explorer endpoint returns 404', async () => {
    window.__INITIAL_MDS_INFO__ = {};
    window.__INITIAL_MDS_SNAPSHOT__ = {};

    globalThis.fetch = vi.fn((url) => {
      if (String(url).includes('api/mds/metadata/explorer/full')) {
        return Promise.resolve(
          jsonResponse({ error: 'Packaged metadata missing.' }, false, 404),
        );
      }
      return Promise.resolve(jsonResponse({ items: [] }));
    });

    const module = await import('../../static/scripts/advanced/mds.js');
    document.dispatchEvent(new Event('DOMContentLoaded'));
    await waitForCondition(
      () => document.getElementById('mds-status').textContent.includes('Packaged metadata missing.'),
      1000,
    );

    expect(document.getElementById('mds-status').textContent).toContain('Packaged metadata missing.');
    expect(document.getElementById('mds-table-body').textContent).toContain('Packaged metadata missing.');

    const loaded = await module.waitForMetadataLoad();
    expect(loaded).toBe(true);
  });

  it('handles custom metadata panel interactions, drag/drop uploads, and warning paths', async () => {
    globalThis.fetch = vi.fn((url, options = {}) => {
      if (String(url).includes('api/mds/metadata/upload')) {
        return Promise.resolve(
          jsonResponse({
            snapshot: {
              meta: {
                entryCount: 2,
                no: 9,
                generatedAt: '2026-04-05T12:00:00Z',
              },
              entries: makeSnapshotEntries(),
              legalHeader: 'Uploaded legal header',
            },
            errors: ['Duplicate entry ignored.'],
          }),
        );
      }

      if (String(url).includes('/api/mds/decode-certificate')) {
        return Promise.resolve(
          jsonResponse({
            details: {
              summary: 'Certificate summary details',
            },
          }),
        );
      }

      if (String(url).includes('fido-mds3.verified.json.meta.json')) {
        return Promise.resolve(jsonResponse({ generatedAt: '2026-04-05T12:00:00Z' }));
      }

      if (String(url).includes('api/mds/metadata/explorer/full')) {
        return Promise.resolve(
          jsonResponse({
            meta: {
              entryCount: 2,
              no: 8,
              generatedAt: '2026-04-04T12:00:00Z',
            },
            entries: makeSnapshotEntries(),
            legalHeader: 'FIDO legal header',
          }),
        );
      }

      return Promise.resolve(jsonResponse({ items: [] }));
    });

    const module = await import('../../static/scripts/advanced/mds.js');
    document.dispatchEvent(new Event('DOMContentLoaded'));
    await waitForCondition(() => document.querySelectorAll('#mds-table-body tr').length === 2, 1000);

    const addButton = document.getElementById('mds-add-metadata-button');
    const panel = document.getElementById('mds-custom-metadata-panel');
    const panelClose = document.getElementById('mds-custom-panel-close');
    const dropzone = document.getElementById('mds-custom-dropzone');
    const messages = document.getElementById('mds-custom-messages');

    addButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(panel.classList.contains('is-open')).toBe(true);

    const keydown = new KeyboardEvent('keydown', {
      key: 'Escape',
      bubbles: true,
      cancelable: true,
    });
    panel.dispatchEvent(keydown);
    expect(keydown.defaultPrevented).toBe(true);

    dropzone.dispatchEvent(eventWithDataTransfer('dragenter'));
    expect(dropzone.classList.contains('is-active')).toBe(true);

    const invalidFile = new File(['not-json'], 'notes.txt', { type: 'text/plain' });
    const validFile = new File(['{"meta":{},"entries":[]}'], 'custom-aaguid.json', {
      type: 'application/json',
    });

    dropzone.dispatchEvent(eventWithDataTransfer('drop', [invalidFile, validFile]));

    await waitForCondition(
      () => messages.textContent.includes('Metadata uploaded with warnings:'),
      1200,
    );

    expect(messages.textContent).toContain('Metadata uploaded with warnings:');
    expect(document.getElementById('mds-status').textContent).toContain('Custom metadata updated.');
    expect(globalThis.fetch).toHaveBeenCalledWith(
      'api/mds/metadata/upload',
      expect.objectContaining({ method: 'POST' }),
    );

    panelClose.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 450));
    expect(panel.hidden).toBe(true);

    const loaded = await module.waitForMetadataLoad();
    expect(loaded).toBe(true);
  });

  it('resolves lightweight entries for modal detail and opens raw-view popup', async () => {
    const lightweightEntries = makeSnapshotEntries();
    lightweightEntries[0] = {
      ...lightweightEntries[0],
      name: 'Lightweight Alpha',
      metadataStatement: null,
      isLightweightEntry: true,
      rawEntry: null,
    };

    const resolvedEntry = {
      ...makeSnapshotEntries()[0],
      name: 'Resolved Alpha',
      isLightweightEntry: false,
    };

    window.__INITIAL_MDS_SNAPSHOT__ = {
      meta: {
        entryCount: 2,
        no: 10,
        generatedAt: '2026-04-05T13:00:00Z',
      },
      entries: lightweightEntries,
      legalHeader: 'FIDO legal header',
    };

    const popupDocument = document.implementation.createHTMLDocument('popup');
    const popupWindow = {
      closed: false,
      document: popupDocument,
      focus: vi.fn(),
      resizeTo: vi.fn(),
      onbeforeunload: null,
    };

    window.open = vi.fn(() => popupWindow);

    globalThis.fetch = vi.fn((url) => {
      if (String(url).includes('api/mds/metadata/resolve')) {
        return Promise.resolve(jsonResponse({ entry: resolvedEntry }));
      }
      if (String(url).includes('/api/mds/decode-certificate')) {
        return Promise.resolve(
          jsonResponse({
            details: {
              summary: 'Resolved certificate summary',
              subject: 'CN=Resolved Subject',
              issuer: 'CN=Resolved Issuer',
            },
          }),
        );
      }
      return Promise.resolve(jsonResponse({ items: [] }));
    });

    const module = await import('../../static/scripts/advanced/mds.js');
    document.dispatchEvent(new Event('DOMContentLoaded'));
    await waitForCondition(() => document.querySelectorAll('#mds-table-body tr').length === 2, 1200);

    const firstNameButton = document.querySelector('.mds-name-button');
    firstNameButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));

    await waitForCondition(
      () => document.getElementById('mds-authenticator-modal-content').textContent.includes('Resolved Alpha'),
      1200,
    );

    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining('api/mds/metadata/resolve'),
      expect.objectContaining({ cache: 'no-store' }),
    );

    const rawButton = document.getElementById('mds-authenticator-modal-raw');
    expect(rawButton.disabled).toBe(false);

    rawButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));

    const rawTextarea = popupDocument.getElementById('mds-raw-textarea');
    expect(window.open).toHaveBeenCalled();
    expect(rawTextarea).not.toBeNull();
    expect(rawTextarea.value).toContain('metadataStatement');

    const highlighted = await window.highlightMdsAuthenticatorRow('00112233-4455-6677-8899-aabbccddeeff', {
      waitForVisibility: false,
      scrollBehavior: 'auto',
    });
    expect(highlighted.highlighted).toBe(true);

    const focused = await window.focusMdsAuthenticator('00112233-4455-6677-8899-aabbccddeeff');
    expect(focused?.name).toBe('Resolved Alpha');

    const opened = await window.openMdsAuthenticatorModal('00112233-4455-6677-8899-aabbccddeeff');
    expect(opened?.name).toBe('Resolved Alpha');

    const loadState = window.getMdsLoadState();
    expect(loadState).toEqual(expect.objectContaining({ hasLoaded: true }));

    const loaded = await module.waitForMetadataLoad();
    expect(loaded).toBe(true);
  });

  it('shows decode failure messages on certificate page when decode endpoint errors', async () => {
    globalThis.fetch = vi.fn((url) => {
      if (String(url).includes('/api/mds/decode-certificate')) {
        return Promise.resolve({
          ok: false,
          status: 500,
          json: vi.fn().mockResolvedValue({ error: 'decode failed' }),
          text: vi.fn().mockResolvedValue('decode failed'),
        });
      }

      if (String(url).includes('fido-mds3.verified.json.meta.json')) {
        return Promise.resolve(jsonResponse({ generatedAt: '2026-04-04T12:00:00Z' }));
      }

      return Promise.resolve(
        jsonResponse({
          meta: {
            entryCount: 2,
            no: 8,
            generatedAt: '2026-04-04T12:00:00Z',
          },
          entries: makeSnapshotEntries(),
          legalHeader: 'FIDO legal header',
        }),
      );
    });

    await import('../../static/scripts/advanced/mds.js');
    document.dispatchEvent(new Event('DOMContentLoaded'));
    await waitForCondition(() => document.querySelectorAll('#mds-table-body tr').length === 2, 1200);

    const nameButton = document.querySelector('.mds-name-button');
    nameButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await waitForCondition(() => document.querySelector('.mds-certificate-button') !== null, 1200);

    const certButton = document.querySelector('.mds-certificate-button');
    certButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));

    await waitForCondition(
      () => document.getElementById('mds-certificate-output').value.includes('Certificate decode failed with status 500'),
      1200,
    );

    expect(document.getElementById('mds-certificate-summary').textContent).toContain(
      'Certificate decode failed with status 500',
    );

    document.getElementById('mds-certificate-page-close').dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 550));
    expect(document.getElementById('mds-certificate-page').hidden).toBe(true);
  });

  it('handles custom panel wheel/touch guards, drag leave cleanup, and file-input uploads', async () => {
    globalThis.fetch = vi.fn((url) => {
      if (String(url).includes('api/mds/metadata/upload')) {
        return Promise.resolve(
          jsonResponse({
            snapshot: {
              meta: {
                entryCount: 2,
                no: 11,
                generatedAt: '2026-04-06T12:00:00Z',
              },
              entries: makeSnapshotEntries(),
              legalHeader: 'Uploaded legal header',
            },
            errors: [],
          }),
        );
      }

      if (String(url).includes('/api/mds/decode-certificate')) {
        return Promise.resolve(
          jsonResponse({
            details: {
              summary: 'Certificate summary details',
            },
          }),
        );
      }

      if (String(url).includes('fido-mds3.verified.json.meta.json')) {
        return Promise.resolve(jsonResponse({ generatedAt: '2026-04-06T12:00:00Z' }));
      }

      return Promise.resolve(
        jsonResponse({
          meta: {
            entryCount: 2,
            no: 11,
            generatedAt: '2026-04-06T12:00:00Z',
          },
          entries: makeSnapshotEntries(),
          legalHeader: 'FIDO legal header',
        }),
      );
    });

    await import('../../static/scripts/advanced/mds.js');
    document.dispatchEvent(new Event('DOMContentLoaded'));
    await waitForCondition(() => document.querySelectorAll('#mds-table-body tr').length === 2, 1200);

    const addButton = document.getElementById('mds-add-metadata-button');
    const panel = document.getElementById('mds-custom-metadata-panel');
    const panelClose = document.getElementById('mds-custom-panel-close');
    const dropzone = document.getElementById('mds-custom-dropzone');
    const fileInput = document.getElementById('mds-custom-file-input');
    const messages = document.getElementById('mds-custom-messages');

    addButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(panel.classList.contains('is-open')).toBe(true);

    const dialog = panel.querySelector('.mds-custom-panel__dialog');
    Object.defineProperty(dialog, 'scrollHeight', { configurable: true, value: 400 });
    Object.defineProperty(dialog, 'clientHeight', { configurable: true, value: 200 });
    dialog.scrollTop = 0;

    const wheelEvent = new WheelEvent('wheel', { bubbles: true, cancelable: true, deltaY: -30 });
    dialog.dispatchEvent(wheelEvent);
    expect(wheelEvent.defaultPrevented).toBe(true);

    const touchStart = new Event('touchstart', { bubbles: true, cancelable: true });
    Object.defineProperty(touchStart, 'touches', {
      configurable: true,
      value: [{ clientY: 100 }],
    });
    dialog.dispatchEvent(touchStart);

    const touchMove = new Event('touchmove', { bubbles: true, cancelable: true });
    Object.defineProperty(touchMove, 'touches', {
      configurable: true,
      value: [{ clientY: 130 }],
    });
    dialog.dispatchEvent(touchMove);
    expect(touchMove.defaultPrevented).toBe(true);

    dropzone.dispatchEvent(eventWithDataTransfer('dragenter'));
    expect(dropzone.classList.contains('is-active')).toBe(true);

    const dragLeaveEvent = new Event('dragleave', { bubbles: true, cancelable: true });
    dropzone.dispatchEvent(dragLeaveEvent);
    expect(dropzone.classList.contains('is-active')).toBe(false);

    const validFile = new File(['{"meta":{},"entries":[]}'], 'custom-upload.json', {
      type: 'application/json',
    });
    Object.defineProperty(fileInput, 'files', {
      configurable: true,
      value: [validFile],
    });

    fileInput.dispatchEvent(new Event('change', { bubbles: true }));

    await waitForCondition(
      () => messages.textContent.includes('Metadata uploaded successfully.'),
      1200,
    );

    expect(globalThis.fetch).toHaveBeenCalledWith(
      'api/mds/metadata/upload',
      expect.objectContaining({ method: 'POST' }),
    );

    panelClose.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    dialog.dispatchEvent(new Event('transitionend', { bubbles: true }));
    await Promise.resolve();
    expect(panel.hidden).toBe(true);
  });

  it('supports sorting on every table column and finalizing deferred row highlight', async () => {
    await import('../../static/scripts/advanced/mds.js');
    document.dispatchEvent(new Event('DOMContentLoaded'));
    await waitForCondition(() => document.querySelectorAll('#mds-table-body tr').length === 2, 1200);

    const sortButtons = Array.from(document.querySelectorAll('.mds-sort-button'));
    expect(sortButtons.length).toBeGreaterThan(5);

    sortButtons.forEach((button) => {
      button.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      expect(button.getAttribute('data-sort-direction')).not.toBe('none');
    });

    const highlighted = await window.highlightMdsAuthenticatorRow('00112233-4455-6677-8899-aabbccddeeff', {
      deferScroll: true,
      waitForVisibility: true,
      focusRow: false,
    });
    expect(highlighted.highlighted).toBe(true);

    const finalized = window.finaliseMdsAuthenticatorHighlight({ behavior: 'auto', focus: false });
    expect(finalized).toBe(true);
    expect(document.querySelector('tr.mds-row--highlight')).not.toBeNull();
  });

  it('falls back to raw-view line rendering when JSON serialization throws and reuses popup window', async () => {
    const entries = makeSnapshotEntries();
    entries[0] = {
      ...entries[0],
      rawEntry: {
        aaguid: '00112233-4455-6677-8899-aabbccddeeff',
        metadataStatement: {
          description: 'Raw fallback key',
        },
        nested: {
          mode: 'fallback',
          values: ['one', 'two'],
        },
        toJSON() {
          throw new Error('serialization blocked');
        },
      },
    };

    window.__INITIAL_MDS_SNAPSHOT__ = {
      meta: {
        entryCount: 2,
        no: 12,
        generatedAt: '2026-04-06T13:00:00Z',
      },
      entries,
      legalHeader: 'FIDO legal header',
    };

    const popupDocument = document.implementation.createHTMLDocument('popup');
    const popupWindow = {
      closed: false,
      document: popupDocument,
      focus: vi.fn(),
      resizeTo: vi.fn(),
      onbeforeunload: null,
    };

    window.open = vi.fn(() => popupWindow);

    globalThis.fetch = vi.fn((url) => {
      if (String(url).includes('/api/mds/decode-certificate')) {
        return Promise.resolve(
          jsonResponse({
            details: {
              summary: 'Popup certificate summary',
            },
          }),
        );
      }
      return Promise.resolve(jsonResponse({ items: [] }));
    });

    await import('../../static/scripts/advanced/mds.js');
    document.dispatchEvent(new Event('DOMContentLoaded'));
    await waitForCondition(() => document.querySelectorAll('#mds-table-body tr').length === 2, 1200);

    const firstNameButton = document.querySelector('.mds-name-button');
    firstNameButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await waitForCondition(
      () => document.getElementById('mds-authenticator-modal-content').textContent.includes('Alpha Key'),
      1200,
    );

    const rawButton = document.getElementById('mds-authenticator-modal-raw');
    expect(rawButton.disabled).toBe(false);

    rawButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    rawButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));

    const rawTextarea = popupDocument.getElementById('mds-raw-textarea');
    expect(window.open).toHaveBeenCalled();
    expect(rawTextarea).not.toBeNull();
    expect(rawTextarea.value).toContain('nested:');
    expect(popupWindow.resizeTo).toHaveBeenCalled();
    expect(popupWindow.focus).toHaveBeenCalled();
  });
});
