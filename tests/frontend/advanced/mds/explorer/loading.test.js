import { afterEach, describe, expect, it, vi } from 'vitest';

import { MDS_EXPLORER_FULL_PATH, MDS_INFO_PATH, MISSING_METADATA_MESSAGE } from '../../../../../frontend/static/scripts/advanced/mds/constants.js';
import {
  classifyExplorerAnswer,
  explorerLoadFailure,
  fetchExplorerInfo,
  indexEntriesByAaguid,
  isMissingSnapshot,
  needsLegacyEntryParser,
  prepareSnapshotEntries,
  requestExplorerSnapshot,
} from '../../../../../frontend/static/scripts/advanced/mds/explorer/loading.js';
import { createExplorerSource } from '../../../../../frontend/static/scripts/advanced/mds/metadata/explorer-source.js';

function answer(body, { ok = true, status = 200 } = {}) {
  return {
    ok,
    status,
    json: async () => {
      if (body instanceof Error) {
        throw body;
      }
      return body;
    },
  };
}

function abortError() {
  const error = new Error('aborted');
  error.name = 'AbortError';
  return error;
}

const SNAPSHOT = { meta: { hasCustomEntries: false }, entries: [{ entryId: 'aaguid:1' }] };

afterEach(() => {
  vi.restoreAllMocks();
});

describe('explorer loading: which source answers', () => {
  it('asks the API when there is no explorer source, reloading when forced', async () => {
    globalThis.fetch = vi.fn(async () => answer(SNAPSHOT));

    const plain = await requestExplorerSnapshot(null);
    expect(globalThis.fetch).toHaveBeenLastCalledWith(MDS_EXPLORER_FULL_PATH, { cache: 'no-store' });
    expect(plain.payload).toEqual(SNAPSHOT);

    await requestExplorerSnapshot(undefined, { forceReload: true, apiPath: '/elsewhere' });
    expect(globalThis.fetch).toHaveBeenLastCalledWith('/elsewhere', { cache: 'reload' });
  });

  it('passes the abort signal when there is one', async () => {
    globalThis.fetch = vi.fn(async () => answer(SNAPSHOT));
    const signal = new AbortController().signal;
    await requestExplorerSnapshot(null, { signal });
    expect(globalThis.fetch).toHaveBeenCalledWith(MDS_EXPLORER_FULL_PATH, { cache: 'no-store', signal });
  });

  it('asks the API once when the source chooses it', async () => {
    globalThis.fetch = vi.fn(async () => answer(SNAPSHOT));
    const source = createExplorerSource({ snapshotUrl: '/snap.json', customEntriesState: 'present' });
    await requestExplorerSnapshot(source);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    expect(globalThis.fetch).toHaveBeenCalledWith(MDS_EXPLORER_FULL_PATH, { cache: 'no-store' });
  });

  it('keeps the packaged file when it answers with an object', async () => {
    globalThis.fetch = vi.fn(async () => answer(SNAPSHOT));
    const source = createExplorerSource({ snapshotUrl: '/snap.json', customEntriesState: 'none' });
    const result = await requestExplorerSnapshot(source);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    expect(globalThis.fetch).toHaveBeenCalledWith('/snap.json', { cache: 'default' });
    expect(result.payload).toEqual(SNAPSHOT);
  });

  it.each([
    ['a failed answer', () => answer(null, { ok: false, status: 404 })],
    ['a body that is not JSON', () => answer(new SyntaxError('not json'))],
    ['a body that is not an object', () => answer('text')],
  ])('falls back to the API after %s from the packaged file', async (_label, staticAnswer) => {
    globalThis.fetch = vi.fn(async url => (url === '/snap.json' ? staticAnswer() : answer(SNAPSHOT)));
    const source = createExplorerSource({ snapshotUrl: '/snap.json', customEntriesState: 'none' });
    const result = await requestExplorerSnapshot(source);
    expect(globalThis.fetch).toHaveBeenNthCalledWith(2, MDS_EXPLORER_FULL_PATH, { cache: 'no-store' });
    expect(result.payload).toEqual(SNAPSHOT);
  });

  it('falls back to the API when the packaged file cannot be fetched at all', async () => {
    globalThis.fetch = vi.fn(async url => {
      if (url === '/snap.json') {
        throw new TypeError('offline');
      }
      return answer(SNAPSHOT);
    });
    const source = createExplorerSource({ snapshotUrl: '/snap.json', customEntriesState: 'none' });
    await expect(requestExplorerSnapshot(source)).resolves.toMatchObject({ payload: SNAPSHOT });
  });

  it('never swallows an abort', async () => {
    globalThis.fetch = vi.fn(async () => {
      throw abortError();
    });
    const source = createExplorerSource({ snapshotUrl: '/snap.json', customEntriesState: 'none' });
    await expect(requestExplorerSnapshot(source)).rejects.toMatchObject({ name: 'AbortError' });
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it('treats a thrown non-error as a failure of the packaged file', async () => {
    globalThis.fetch = vi.fn(async url => {
      if (url === '/snap.json') {
        throw null;
      }
      return answer(SNAPSHOT);
    });
    const source = createExplorerSource({ snapshotUrl: '/snap.json', customEntriesState: 'none' });
    await expect(requestExplorerSnapshot(source)).resolves.toMatchObject({ payload: SNAPSHOT });
  });
});

describe('explorer loading: what an answer means', () => {
  it('reads a 404 as a missing snapshot, in the server words or the packaged sentence', () => {
    expect(classifyExplorerAnswer({ response: { ok: false, status: 404 }, payload: { error: 'Gone.' } })).toEqual({
      kind: 'missing',
      message: 'Gone.',
    });
    expect(classifyExplorerAnswer({ response: { ok: false, status: 404 }, payload: null })).toEqual({
      kind: 'missing',
      message: MISSING_METADATA_MESSAGE,
    });
    expect(classifyExplorerAnswer({ response: { ok: false, status: 404 }, payload: { error: '' } }, 'Custom.')).toEqual({
      kind: 'missing',
      message: 'Custom.',
    });
  });

  it('reads another failure with the server error or the status', () => {
    expect(classifyExplorerAnswer({ response: { ok: false, status: 500 }, payload: { error: 'Broken.' } })).toEqual({
      kind: 'failed',
      message: 'Broken.',
    });
    expect(classifyExplorerAnswer({ response: { ok: false, status: 502 }, payload: { error: 7 } })).toEqual({
      kind: 'failed',
      message: 'Explorer request failed with status 502.',
    });
  });

  it('refuses a success that is not an object', () => {
    for (const payload of [null, 'text']) {
      expect(classifyExplorerAnswer({ response: { ok: true, status: 200 }, payload })).toEqual({
        kind: 'failed',
        message: 'Explorer response was not valid JSON.',
      });
    }
  });

  it('keeps a snapshot', () => {
    expect(classifyExplorerAnswer({ response: { ok: true, status: 200 }, payload: SNAPSHOT })).toEqual({
      kind: 'snapshot',
      payload: SNAPSHOT,
    });
  });

  it('says whether the entries need the legacy parser', () => {
    expect(needsLegacyEntryParser(null)).toBe(false);
    expect(needsLegacyEntryParser({ entries: [] })).toBe(false);
    expect(needsLegacyEntryParser({ entries: [{ entryId: 'a' }, { entryId: 'b' }] })).toBe(false);
    expect(needsLegacyEntryParser({ entries: [{ entryId: 'a' }, { name: 'no id' }] })).toBe(true);
    expect(needsLegacyEntryParser({ entries: [null] })).toBe(true);
  });

  it('words a load failure', () => {
    expect(explorerLoadFailure(new Error('Explorer response was not valid JSON.'))).toBe(
      'Explorer response was not valid JSON.',
    );
    expect(explorerLoadFailure(new Error(''))).toBe('Unable to load the packaged authenticator explorer.');
    expect(explorerLoadFailure('nope')).toBe('Unable to load the packaged authenticator explorer.');
  });
});

describe('explorer loading: the entries shown', () => {
  it('copies the entries, drops what is not an entry and marks inline detail', () => {
    const inline = { entryId: 'aaguid:1', metadataStatement: { description: 'x' } };
    const light = { entryId: 'aaguid:2', isLightweightEntry: true };
    const entries = prepareSnapshotEntries({ entries: [inline, null, 'text', light] });

    expect(entries).toHaveLength(2);
    expect(entries[0]).not.toBe(inline);
    expect(entries[0]).toMatchObject({ entryId: 'aaguid:1', isLightweightEntry: false });
    expect(entries[1]).toEqual(light);
  });

  it('keeps an entry already resolved in full', () => {
    const cache = new Map([['aaguid:1', { entryId: 'aaguid:1', name: 'Resolved', rawEntry: {} }]]);
    const entries = prepareSnapshotEntries({ entries: [{ entryId: 'aaguid:1', name: 'Listed' }, { name: 'x' }] }, cache);
    expect(entries[0]).toEqual({ entryId: 'aaguid:1', name: 'Resolved', rawEntry: {} });
    expect(entries[1]).toEqual({ name: 'x' });
  });

  it('reads no entries from a snapshot without them', () => {
    expect(prepareSnapshotEntries(null)).toEqual([]);
    expect(prepareSnapshotEntries({ entries: 'no' })).toEqual([]);
  });

  it('indexes the entries by AAGUID and caches every entry with an id', () => {
    const cache = new Map();
    const byAaguid = indexEntriesByAaguid(
      [
        { entryId: 'aaguid:a', aaguid: 'FCB1BCB4-F370-078C-6993-BC24D0AE3FBE' },
        { entryId: 'aaguid:b', id: 'ee041bce-25e5-4cdb-8f86-897fd6418464' },
        { entryId: 'aaid:4e4e#4005', id: '4e4e#4005' },
        null,
      ],
      cache,
    );
    expect([...byAaguid.keys()]).toEqual([
      'fcb1bcb4-f370-078c-6993-bc24d0ae3fbe',
      'ee041bce-25e5-4cdb-8f86-897fd6418464',
    ]);
    expect([...cache.keys()]).toEqual(['aaguid:a', 'aaguid:b', 'aaid:4e4e#4005']);
    expect(indexEntriesByAaguid([{ aaguid: 'fcb1bcb4-f370-078c-6993-bc24d0ae3fbe' }]).size).toBe(1);
  });

  it('calls a snapshot with no entry missing', () => {
    expect(isMissingSnapshot(null)).toBe(true);
    expect(isMissingSnapshot({ meta: {} })).toBe(true);
    expect(isMissingSnapshot({ entries: [] })).toBe(true);
    expect(isMissingSnapshot({ entries: [{}] })).toBe(false);
  });
});

describe('explorer loading: what the page starts from', () => {
  it('asks the info endpoint, never from the cache', async () => {
    const info = { snapshotUrl: '/assets/dev/fido-mds3.explorer.full.json', customEntriesState: 'none' };
    globalThis.fetch = vi.fn(async () => answer(info));
    const signal = new AbortController().signal;
    await expect(fetchExplorerInfo({ signal })).resolves.toEqual(info);
    expect(globalThis.fetch).toHaveBeenCalledWith(MDS_INFO_PATH, { cache: 'no-store', signal });
    await expect(fetchExplorerInfo()).resolves.toEqual(info);
  });

  it('gives nothing for a failure or an answer that is not an object', async () => {
    globalThis.fetch = vi.fn(async () => answer({ error: 'x' }, { ok: false, status: 500 }));
    await expect(fetchExplorerInfo()).resolves.toBeNull();
    globalThis.fetch = vi.fn(async () => answer([1, 2]));
    await expect(fetchExplorerInfo()).resolves.toBeNull();
    globalThis.fetch = vi.fn(async () => answer(null));
    await expect(fetchExplorerInfo()).resolves.toBeNull();
    globalThis.fetch = vi.fn(async () => answer(new SyntaxError('not json')));
    await expect(fetchExplorerInfo()).resolves.toBeNull();
    globalThis.fetch = vi.fn(async () => {
      throw null;
    });
    await expect(fetchExplorerInfo()).resolves.toBeNull();
  });

  it('never swallows an abort', async () => {
    globalThis.fetch = vi.fn(async () => {
      throw abortError();
    });
    await expect(fetchExplorerInfo()).rejects.toMatchObject({ name: 'AbortError' });
  });
});
