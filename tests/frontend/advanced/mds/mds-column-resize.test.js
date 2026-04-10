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

function jsonResponse(payload, ok = true, status = 200) {
  return {
    ok,
    status,
    json: vi.fn().mockResolvedValue(payload),
    text: vi.fn().mockResolvedValue(typeof payload === 'string' ? payload : JSON.stringify(payload)),
  };
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

function createPointerEvent(type, { button = 0, pointerId = 1, clientX = 0 } = {}) {
  const event = new Event(type, { bubbles: true, cancelable: true });
  Object.defineProperties(event, {
    button: {
      configurable: true,
      value: button,
    },
    pointerId: {
      configurable: true,
      value: pointerId,
    },
    clientX: {
      configurable: true,
      value: clientX,
    },
  });
  return event;
}

describe('mds explorer column resizing', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
    buildMdsDom();

    window.__INITIAL_MDS_INFO__ = {
      entryCount: 1,
      no: 41,
      generatedAt: '2026-04-06T12:00:00Z',
    };
    window.__INITIAL_MDS_SNAPSHOT__ = {
      meta: {
        entryCount: 1,
        no: 41,
        generatedAt: '2026-04-06T12:00:00Z',
      },
      entries: makeSnapshotEntries(),
      legalHeader: 'FIDO legal header',
    };

    globalThis.fetch = vi.fn((url) => {
      if (String(url).includes('/api/mds/decode-certificate')) {
        return Promise.resolve(jsonResponse({ details: { summary: 'certificate details' } }));
      }

      if (String(url).includes('api/mds/metadata/explorer/full')) {
        return Promise.resolve(
          jsonResponse({
            meta: {
              entryCount: 1,
              no: 42,
              generatedAt: '2026-04-06T13:00:00Z',
            },
            entries: makeSnapshotEntries(),
            legalHeader: 'FIDO legal header',
          }),
        );
      }

      return Promise.resolve(jsonResponse({ items: [] }));
    });
  });

  it('resizes a column on pointer drag and tears down resize state on pointerup', async () => {
    await import('../../../../frontend/static/scripts/advanced/mds.js');
    document.dispatchEvent(new Event('DOMContentLoaded'));

    await waitForCondition(() => document.querySelectorAll('#mds-table-body tr').length === 1, 1200);

    const resizer = document.querySelector('.mds-column-resizer');
    const tableContainer = document.getElementById('mds-table-container');
    const firstHeader = document.querySelector('.mds-table thead tr th');

    expect(resizer).not.toBeNull();
    expect(firstHeader).not.toBeNull();

    await waitForCondition(() => !resizer.classList.contains('is-disabled'), 1200);

    resizer.dispatchEvent(createPointerEvent('pointerdown', { button: 1, pointerId: 3, clientX: 100 }));
    expect(resizer.classList.contains('is-active')).toBe(false);
    expect(tableContainer.classList.contains('mds-table-container--resizing')).toBe(false);

    const initialWidth = Number.parseInt(firstHeader.style.width || '64', 10);

    resizer.dispatchEvent(createPointerEvent('pointerdown', { button: 0, pointerId: 9, clientX: 100 }));

    await waitForCondition(
      () =>
        resizer.classList.contains('is-active') &&
        tableContainer.classList.contains('mds-table-container--resizing'),
      1200,
    );

    document.dispatchEvent(createPointerEvent('pointermove', { pointerId: 9, clientX: 160 }));

    const resizedWidth = Number.parseInt(firstHeader.style.width || '0', 10);
    expect(resizedWidth).toBeGreaterThan(initialWidth);

    document.dispatchEvent(createPointerEvent('pointerup', { pointerId: 9, clientX: 160 }));

    await waitForCondition(
      () =>
        !resizer.classList.contains('is-active') &&
        !tableContainer.classList.contains('mds-table-container--resizing'),
      1200,
    );

    expect(resizer.classList.contains('is-active')).toBe(false);
    expect(tableContainer.classList.contains('mds-table-container--resizing')).toBe(false);
  });
});
