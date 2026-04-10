import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../frontend/static/scripts/shared/utils/loader.js', () => ({
  loaderIsActive: vi.fn(() => false),
  loaderSetMetadataCount: vi.fn(),
  loaderSetPhase: vi.fn(),
  loaderSetProgress: vi.fn(),
}));

vi.mock('../../../../frontend/static/scripts/shared/ui/core.js', () => ({
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
        description: 'Alpha Key',
      },
      rawEntry: {
        aaguid: '00112233-4455-6677-8899-aabbccddeeff',
      },
      statusReports: [],
      attestationCertificates: ['Q0VSVA=='],
      attestationKeyIdentifiers: ['key-alpha'],
      isLightweightEntry: false,
    },
  ];
}

function makeRawMetadataEntries(count = 2) {
  return Array.from({ length: count }, (_, index) => {
    const suffix = String(index + 1).padStart(12, '0');
    const status = index % 2 === 0 ? 'FIDO_CERTIFIED_L1' : 'NOT_FIDO_CERTIFIED';

    return {
      aaguid: `00112233-4455-6677-8899-${suffix}`,
      metadataStatement: {
        description: `Raw Key ${index + 1}`,
        protocolFamily: 'fido2',
        userVerificationDetails: [[{ userVerificationMethod: 'presence_internal' }]],
        attachmentHint: [index % 2 === 0 ? 'internal' : 'external'],
        transports: ['usb'],
        keyProtection: ['hardware'],
        authenticationAlgorithms: ['secp256r1_ecdsa_sha256_raw'],
        attestationRootCertificates: ['Q0VSVA=='],
        authenticatorGetInfo: {
          versions: ['FIDO_2_0'],
          transports: ['usb'],
        },
      },
      statusReports: [
        {
          status,
          effectiveDate: `2026-04-${String((index % 9) + 1).padStart(2, '0')}`,
          certificationDescriptor: status,
        },
      ],
      timeOfLastStatusChange: '2026-04-06T00:00:00Z',
    };
  });
}

function jsonResponse(payload, ok = true, status = 200) {
  return {
    ok,
    status,
    json: vi.fn().mockResolvedValue(payload),
    text: vi.fn().mockResolvedValue(typeof payload === 'string' ? payload : JSON.stringify(payload)),
  };
}

function createDeferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

async function waitForCondition(predicate, timeoutMs = 900, intervalMs = 20) {
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

describe('mds edge cases', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
    buildMdsDom();

    window.__INITIAL_MDS_INFO__ = {};
    window.__INITIAL_MDS_SNAPSHOT__ = {};
  });

  it('recovers from transient explorer failure when retry is clicked', async () => {
    let fullExplorerCalls = 0;

    globalThis.fetch = vi.fn((url) => {
      if (String(url).includes('api/mds/metadata/explorer/full')) {
        fullExplorerCalls += 1;
        if (fullExplorerCalls === 1) {
          return Promise.resolve(jsonResponse({ error: 'Transient metadata outage.' }, false, 503));
        }
        return Promise.resolve(jsonResponse({
          meta: { entryCount: 1, no: 81, generatedAt: '2026-04-06T00:00:00Z' },
          entries: makeSnapshotEntries(),
          legalHeader: 'FIDO legal header',
        }));
      }
      return Promise.resolve(jsonResponse({ items: [] }));
    });

    await import('../../../../frontend/static/scripts/advanced/mds/index.js');
    document.dispatchEvent(new Event('DOMContentLoaded'));

    await waitForCondition(() => {
      return document.getElementById('mds-status').textContent.includes('Transient metadata outage.');
    }, 1200);

    expect(document.getElementById('mds-retry-button').hidden).toBe(false);

    document.getElementById('mds-retry-button').dispatchEvent(new MouseEvent('click', { bubbles: true }));

    await waitForCondition(() => document.querySelectorAll('#mds-table-body tr').length === 1, 1200);
    expect(document.getElementById('mds-status').textContent).toContain('Loaded 1 authenticators.');
    expect(document.getElementById('mds-retry-button').hidden).toBe(true);
    expect(fullExplorerCalls).toBeGreaterThanOrEqual(2);
  });

  it('shows refresh guard message while initial loading is in progress', async () => {
    const deferred = createDeferred();

    globalThis.fetch = vi.fn((url) => {
      if (String(url).includes('api/mds/metadata/explorer/full')) {
        return deferred.promise;
      }
      return Promise.resolve(jsonResponse({ items: [] }));
    });

    await import('../../../../frontend/static/scripts/advanced/mds/index.js');
    document.dispatchEvent(new Event('DOMContentLoaded'));

    document.getElementById('mds-update-button').dispatchEvent(new MouseEvent('click', { bubbles: true }));

    await waitForCondition(() => {
      return document
        .getElementById('mds-status')
        .textContent.includes('Metadata is currently loading. Please wait for the current operation to finish.');
    }, 1200);

    deferred.resolve(jsonResponse({
      meta: { entryCount: 1, no: 82, generatedAt: '2026-04-06T00:00:00Z' },
      entries: makeSnapshotEntries(),
      legalHeader: 'FIDO legal header',
    }));

    await waitForCondition(() => document.querySelectorAll('#mds-table-body tr').length === 1, 1200);
    expect(document.getElementById('mds-update-button').classList.contains('is-busy')).toBe(false);
    expect(document.getElementById('mds-update-button').disabled).toBe(false);
  });

  it('applies tab-change side effects and handles missing highlight target', async () => {
    window.__INITIAL_MDS_SNAPSHOT__ = {
      meta: { entryCount: 1, no: 83, generatedAt: '2026-04-06T00:00:00Z' },
      entries: makeSnapshotEntries(),
      legalHeader: 'FIDO legal header',
    };

    globalThis.fetch = vi.fn(() => Promise.resolve(jsonResponse({ items: [] })));

    await import('../../../../frontend/static/scripts/advanced/mds/index.js');
    document.dispatchEvent(new Event('DOMContentLoaded'));
    await waitForCondition(() => document.querySelectorAll('#mds-table-body tr').length === 1, 1200);

    const missing = await window.highlightMdsAuthenticatorRow('00000000-0000-0000-0000-000000000000', {
      waitForVisibility: false,
      scrollBehavior: 'auto',
    });
    expect(missing).toEqual(expect.objectContaining({ highlighted: false, entry: null }));

    const highlighted = await window.highlightMdsAuthenticatorRow('00112233-4455-6677-8899-aabbccddeeff', {
      waitForVisibility: false,
      scrollBehavior: 'auto',
    });
    expect(highlighted.highlighted).toBe(true);

    const scrollTopButton = document.getElementById('mds-scroll-top-button');
    scrollTopButton.hidden = false;
    scrollTopButton.setAttribute('aria-hidden', 'false');

    const horizontal = document.getElementById('mds-horizontal-scroll');
    horizontal.hidden = false;
    horizontal.removeAttribute('hidden');
    horizontal.setAttribute('aria-hidden', 'false');
    horizontal.classList.add('is-ready', 'is-overflowing', 'is-floating');

    document.dispatchEvent(new CustomEvent('tab:changed', { detail: { tab: 'simple' } }));

    expect(document.querySelector('tr.mds-row--highlight')).toBeNull();
    expect(scrollTopButton.hidden).toBe(true);
    expect(horizontal.hidden).toBe(true);
    expect(horizontal.getAttribute('aria-hidden')).toBe('true');
  });

  it('shows warning for non-json drop and error message when upload fails', async () => {
    window.__INITIAL_MDS_SNAPSHOT__ = {
      meta: { entryCount: 1, no: 84, generatedAt: '2026-04-06T00:00:00Z' },
      entries: makeSnapshotEntries(),
      legalHeader: 'FIDO legal header',
    };

    globalThis.fetch = vi.fn((url) => {
      if (String(url).includes('api/mds/metadata/upload')) {
        return Promise.resolve(jsonResponse({ error: 'Upload parser failed.' }, false, 500));
      }
      return Promise.resolve(jsonResponse({ items: [] }));
    });

    await import('../../../../frontend/static/scripts/advanced/mds/index.js');
    document.dispatchEvent(new Event('DOMContentLoaded'));
    await waitForCondition(() => document.querySelectorAll('#mds-table-body tr').length === 1, 1200);

    document.getElementById('mds-add-metadata-button').dispatchEvent(new MouseEvent('click', { bubbles: true }));

    const dropzone = document.getElementById('mds-custom-dropzone');
    const messages = document.getElementById('mds-custom-messages');

    const invalid = new File(['not-json'], 'notes.txt', { type: 'text/plain' });
    dropzone.dispatchEvent(eventWithDataTransfer('drop', [invalid]));

    await waitForCondition(() => messages.textContent.includes('Ignored non-JSON files: notes.txt'), 1200);

    const valid = new File(['{"meta":{},"entries":[]}'], 'broken.json', { type: 'application/json' });
    dropzone.dispatchEvent(eventWithDataTransfer('drop', [valid]));

    await waitForCondition(() => messages.textContent.includes('Failed to upload metadata files.'), 1200);

    expect(messages.className).toContain('mds-custom-panel__messages--error');
  });

  it('parses legacy raw explorer payloads when transformed entry ids are absent', async () => {
    const rawEntries = makeRawMetadataEntries(2);

    globalThis.fetch = vi.fn((url) => {
      if (String(url).includes('api/mds/metadata/explorer/full')) {
        return Promise.resolve(jsonResponse({
          meta: { entryCount: 2, no: 85, generatedAt: '2026-04-06T00:00:00Z' },
          entries: rawEntries,
          legalHeader: 'Legacy metadata header',
        }));
      }
      if (String(url).includes('/api/mds/decode-certificate')) {
        return Promise.resolve(jsonResponse({
          details: {
            algorithmInfo: 'RSA 2048',
            subjectCommonNames: ['CN=Legacy Raw Device'],
          },
        }));
      }
      if (String(url).includes('fido-mds3.verified.json.meta.json')) {
        return Promise.resolve(jsonResponse({ generatedAt: '2026-04-06T00:00:00Z' }));
      }
      return Promise.resolve(jsonResponse({ items: [] }));
    });

    const module = await import('../../../../frontend/static/scripts/advanced/mds/index.js');
    document.dispatchEvent(new Event('DOMContentLoaded'));

    await waitForCondition(() => document.querySelectorAll('#mds-table-body tr').length === 2, 1600);

    expect(document.getElementById('mds-status').textContent).toContain('Loaded 2 authenticators.');
    expect(document.getElementById('mds-table-body').textContent).toContain('Raw Key 1');
    expect(globalThis.fetch).toHaveBeenCalledWith(
      '/api/mds/decode-certificate',
      expect.objectContaining({ method: 'POST' }),
    );

    const loaded = await module.waitForMetadataLoad();
    expect(loaded).toBe(true);
  });

  it('uses lazy/background parsing for large legacy raw payloads', async () => {
    const rawEntries = makeRawMetadataEntries(130);

    globalThis.fetch = vi.fn((url) => {
      if (String(url).includes('api/mds/metadata/explorer/full')) {
        return Promise.resolve(jsonResponse({
          meta: { entryCount: 130, no: 86, generatedAt: '2026-04-06T00:00:00Z' },
          entries: rawEntries,
          legalHeader: 'Large legacy metadata header',
        }));
      }
      if (String(url).includes('/api/mds/decode-certificate')) {
        return Promise.resolve(jsonResponse({
          details: {
            algorithmInfo: 'RSA 2048',
            subjectCommonNames: ['CN=Large Legacy Device'],
          },
        }));
      }
      if (String(url).includes('fido-mds3.verified.json.meta.json')) {
        return Promise.resolve(jsonResponse({ generatedAt: '2026-04-06T00:00:00Z' }));
      }
      return Promise.resolve(jsonResponse({ items: [] }));
    });

    await import('../../../../frontend/static/scripts/advanced/mds/index.js');
    document.dispatchEvent(new Event('DOMContentLoaded'));

    await waitForCondition(() => {
      const text = document.getElementById('mds-entry-count').textContent || '';
      return Number(text.replace(/,/g, '')) === 130;
    }, 2500);

    const statusEl = document.getElementById('mds-status');
    expect(statusEl.textContent).toContain('Loaded 130 authenticators.');

    await waitForCondition(() => statusEl.classList.contains('mds-status-success'), 2500);
    expect(statusEl.textContent).toContain('Loaded 130 authenticators.');
  });
});
