import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { bootstrapMds } from '../../../../frontend/static/scripts/advanced/mds/runtime/bootstrap.js';
import { createExplorerSource } from '../../../../frontend/static/scripts/advanced/mds/metadata/explorer-source.js';
import { loadMdsDataInState } from '../../../../frontend/static/scripts/advanced/mds/metadata/explorer-load.js';

function jsonResponse(payload, ok = true, status = 200) {
  return {
    ok,
    status,
    json: () => Promise.resolve(payload),
  };
}

function createBootstrapDeps(overrides = {}) {
  return {
    handleWindowScroll: vi.fn(),
    initializeState: vi.fn(),
    updateSortButtonState: vi.fn(),
    setUpdateButtonMode: vi.fn(),
    formatInitialExplorerStatus: vi.fn(() => ''),
    setStatus: vi.fn(),
    getState: vi.fn(() => ({})),
    setDefaultStatus: vi.fn(),
    getInitialSnapshotPayload: vi.fn(() => null),
    applyExplorerSnapshot: vi.fn(),
    loadMdsData: vi.fn(() => Promise.resolve()),
    openAuthenticatorModalByAaguid: vi.fn(),
    focusAuthenticatorByAaguid: vi.fn(),
    highlightAuthenticatorRowByAaguid: vi.fn(),
    finaliseHighlightedAuthenticatorRow: vi.fn(),
    waitForMetadataLoad: vi.fn(),
    getMdsLoadStateSnapshot: vi.fn(),
    resolveEntryByAaguid: vi.fn(),
    ...overrides,
  };
}

function createLoadDeps(overrides = {}) {
  let isLoading = false;
  let hasLoaded = false;
  let loadPromise = null;
  return {
    getState: () => ({}),
    getAbortSignal: () => null,
    throwIfAborted: () => {},
    getIsLoading: () => isLoading,
    setIsLoading: value => {
      isLoading = value;
    },
    getLoadPromise: () => loadPromise,
    setLoadPromise: value => {
      loadPromise = value;
    },
    getHasLoaded: () => hasLoaded,
    setHasLoaded: value => {
      hasLoaded = value;
    },
    setExplorerPreloadPromise: vi.fn(),
    clearResolvedEntryCache: vi.fn(),
    setStatus: vi.fn(),
    setRetryButtonVisible: vi.fn(),
    setColumnResizersEnabled: vi.fn(),
    mdsExplorerFullPath: 'api/mds/metadata/explorer/full',
    missingMetadataMessage: 'missing',
    resetExplorerState: vi.fn(),
    applyMetadataEntries: vi.fn(),
    applyExplorerSnapshot: vi.fn(() => {
      hasLoaded = true;
    }),
    ...overrides,
  };
}

const SNAPSHOT = {
  meta: { entryCount: 1, hasCustomEntries: false },
  entries: [{ entryId: 'aaguid:1', name: 'Demo' }],
};

describe('explorer snapshot source', () => {
  it('uses the cacheable static snapshot only for sessions without uploads', () => {
    const source = createExplorerSource({
      snapshotUrl: '/fido-mds3.explorer.full.json',
      customEntriesState: 'none',
    });

    expect(source.resolve()).toEqual({
      url: '/fido-mds3.explorer.full.json',
      cache: 'default',
      kind: 'static',
    });
    expect(source.resolve({ forceReload: true })).toEqual({
      url: 'api/mds/metadata/explorer/full',
      cache: 'reload',
      kind: 'api',
    });

    source.noteSnapshotMeta({ hasCustomEntries: true });
    expect(source.resolve().kind).toBe('api');

    source.noteSnapshotMeta({ hasCustomEntries: false });
    expect(source.resolve().kind).toBe('static');
  });

  it('falls back to the session API when state is unknown or no static URL exists', () => {
    expect(createExplorerSource({ snapshotUrl: '/snap.json', customEntriesState: 'unknown' }).resolve()).toEqual({
      url: 'api/mds/metadata/explorer/full',
      cache: 'no-store',
      kind: 'api',
    });
    expect(createExplorerSource({ customEntriesState: 'none' }).resolve().kind).toBe('api');
    expect(createExplorerSource(undefined).resolve().kind).toBe('api');
  });
});

describe('explorer loading with a snapshot source', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('loads the static snapshot when the session has no uploads', async () => {
    globalThis.fetch = vi.fn(() => Promise.resolve(jsonResponse(SNAPSHOT)));
    const deps = createLoadDeps({
      explorerSource: createExplorerSource({ snapshotUrl: '/snap.json', customEntriesState: 'none' }),
    });

    await loadMdsDataInState('', {}, deps);

    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    expect(globalThis.fetch).toHaveBeenCalledWith('/snap.json', { cache: 'default' });
    expect(deps.applyExplorerSnapshot).toHaveBeenCalledWith(SNAPSHOT, '');
  });

  it('falls back to the API when the static snapshot cannot be loaded', async () => {
    globalThis.fetch = vi.fn(url => {
      if (url === '/snap.json') {
        return Promise.resolve(jsonResponse(null, false, 404));
      }
      return Promise.resolve(jsonResponse(SNAPSHOT));
    });
    const deps = createLoadDeps({
      explorerSource: createExplorerSource({ snapshotUrl: '/snap.json', customEntriesState: 'none' }),
    });

    await loadMdsDataInState('', {}, deps);

    expect(globalThis.fetch).toHaveBeenNthCalledWith(2, 'api/mds/metadata/explorer/full', { cache: 'no-store' });
    expect(deps.applyExplorerSnapshot).toHaveBeenCalledWith(SNAPSHOT, '');
    expect(deps.resetExplorerState).not.toHaveBeenCalled();
  });

  it('falls back to the API when the static request throws', async () => {
    globalThis.fetch = vi.fn(url => {
      if (url === '/snap.json') {
        return Promise.reject(new TypeError('network down'));
      }
      return Promise.resolve(jsonResponse(SNAPSHOT));
    });
    const deps = createLoadDeps({
      explorerSource: createExplorerSource({ snapshotUrl: '/snap.json', customEntriesState: 'none' }),
    });

    await loadMdsDataInState('', {}, deps);

    expect(deps.applyExplorerSnapshot).toHaveBeenCalledWith(SNAPSHOT, '');
  });
});

describe('deferred MDS bootstrap', () => {
  let idleCallbacks;

  beforeEach(() => {
    vi.useFakeTimers();
    idleCallbacks = [];
    window.requestIdleCallback = vi.fn(callback => {
      idleCallbacks.push(callback);
      return idleCallbacks.length;
    });
    document.body.innerHTML = `
      <button data-tab="mds"></button>
      <div id="mds-tab"></div>
    `;
  });

  afterEach(() => {
    vi.useRealTimers();
    delete window.requestIdleCallback;
    Object.defineProperty(navigator, 'connection', { value: undefined, configurable: true });
  });

  it('does not fetch explorer data while the page is starting', () => {
    const deps = createBootstrapDeps();
    bootstrapMds(deps);

    document.dispatchEvent(new Event('DOMContentLoaded'));

    expect(deps.loadMdsData).not.toHaveBeenCalled();
  });

  it('loads immediately when the user opens or heads for the MDS tab', () => {
    const deps = createBootstrapDeps();
    bootstrapMds(deps);
    document.dispatchEvent(new Event('DOMContentLoaded'));

    document.querySelector('[data-tab="mds"]').dispatchEvent(new Event('pointerenter'));
    expect(deps.loadMdsData).toHaveBeenCalledTimes(1);

    document.dispatchEvent(new CustomEvent('tab:changed', { detail: { tab: 'mds' } }));
    expect(deps.loadMdsData).toHaveBeenCalledTimes(2);
  });

  it('loads immediately when the MDS tab is already open', () => {
    document.getElementById('mds-tab').classList.add('active');
    const deps = createBootstrapDeps();
    bootstrapMds(deps);

    document.dispatchEvent(new Event('DOMContentLoaded'));

    expect(deps.loadMdsData).toHaveBeenCalledTimes(1);
  });

  it('preloads in the background once the app is ready', () => {
    const deps = createBootstrapDeps();
    bootstrapMds(deps);
    document.dispatchEvent(new Event('DOMContentLoaded'));

    document.dispatchEvent(new CustomEvent('app:ready'));
    // Loading waits for the browser to be idle rather than starting right away.
    expect(deps.loadMdsData).not.toHaveBeenCalled();
    expect(idleCallbacks.length).toBeGreaterThan(0);

    // Bootstraps from earlier tests share `document`, so run every queued callback.
    idleCallbacks.forEach(callback => callback());
    expect(deps.loadMdsData).toHaveBeenCalledTimes(1);
  });

  it('skips the background preload when the user asked to save data', () => {
    Object.defineProperty(navigator, 'connection', { value: { saveData: true }, configurable: true });
    const deps = createBootstrapDeps();
    bootstrapMds(deps);
    document.dispatchEvent(new Event('DOMContentLoaded'));

    document.dispatchEvent(new CustomEvent('app:ready'));
    vi.advanceTimersByTime(20000);
    idleCallbacks.forEach(callback => callback());

    expect(deps.loadMdsData).not.toHaveBeenCalled();
  });

  it('applies an injected snapshot without fetching', () => {
    const deps = createBootstrapDeps({ getInitialSnapshotPayload: vi.fn(() => SNAPSHOT) });
    bootstrapMds(deps);

    document.dispatchEvent(new Event('DOMContentLoaded'));

    expect(deps.applyExplorerSnapshot).toHaveBeenCalledWith(SNAPSHOT);
    expect(deps.loadMdsData).not.toHaveBeenCalled();
  });
});
