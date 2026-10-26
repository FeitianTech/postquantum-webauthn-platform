import { afterEach, describe, expect, it, vi } from 'vitest';

import { MDS_CUSTOM_ENTRIES_PATH, MDS_LIST_PATH } from './constants.js';
import { classifyExplorerParts, createExplorerSource, explorerLoadFailure, requestExplorerParts } from './explorer-source.js';
import { forgetExplorerList } from './explorer/loading.js';

// Where the explorer's two parts are asked for, and what their answers are
// (mds/explorer-source.js).

function answer(body, { ok = true, status = 200 } = {}) {
  return { response: { ok, status }, payload: body };
}

function abortError() {
  const error = new Error('aborted');
  error.name = 'AbortError';
  return error;
}

const LIST = { meta: { no: 7 }, entries: [{ entryId: 'aaguid:x', isLightweightEntry: true }] };
const CUSTOM = { meta: { customEntryCount: 1, hasCustomEntries: true }, entries: [{ entryId: 'aaguid:u' }] };

afterEach(() => {
  forgetExplorerList();
  vi.restoreAllMocks();
});

describe('the explorer\'s source', () => {
  it('always reads the packaged list at its one URL', () => {
    for (const info of [null, { customEntriesState: 'none' }, { customEntriesState: 'present' }]) {
      expect(createExplorerSource(info).list()).toEqual({ url: MDS_LIST_PATH, cache: 'default', kind: 'static' });
    }
  });

  it('asks for the session\'s entries unless it has none, and always on a reload', () => {
    expect(createExplorerSource({ customEntriesState: 'none' }).custom()).toBeNull();
    expect(createExplorerSource({ customEntriesState: 'none' }).custom({ forceReload: true })).toEqual({
      url: MDS_CUSTOM_ENTRIES_PATH,
      cache: 'reload',
      kind: 'api',
    });
    for (const info of [null, { customEntriesState: 42 }, { customEntriesState: 'unknown' }, { customEntriesState: 'present' }]) {
      expect(createExplorerSource(info).custom()).toEqual({ url: MDS_CUSTOM_ENTRIES_PATH, cache: 'no-store', kind: 'api' });
    }
  });

  it('follows what a shown list says of the session\'s uploads, and nothing else', () => {
    const source = createExplorerSource({ customEntriesState: 'unknown' });
    source.noteSnapshotMeta({ hasCustomEntries: false });
    expect(source.custom()).toBeNull();
    source.noteSnapshotMeta(null);
    source.noteSnapshotMeta({ hasCustomEntries: 'yes' });
    expect(source.custom()).toBeNull();
    source.noteSnapshotMeta({ hasCustomEntries: true });
    expect(source.custom()).not.toBeNull();
  });
});

describe('the explorer\'s two parts', () => {
  it('asks for both at once, the list without the cookie', async () => {
    globalThis.fetch = vi.fn(async (url) => ({ ok: true, status: 200, json: async () => (url === MDS_LIST_PATH ? LIST : CUSTOM) }));

    const parts = await requestExplorerParts(createExplorerSource({ customEntriesState: 'present' }));

    expect(parts.list.payload).toEqual(LIST);
    expect(parts.custom.payload).toEqual(CUSTOM);
    expect(globalThis.fetch.mock.calls).toEqual([
      [MDS_LIST_PATH, { cache: 'default', credentials: 'omit' }],
      [MDS_CUSTOM_ENTRIES_PATH, { cache: 'no-store' }],
    ]);
  });

  it('asks only for the list while the session has no uploads, and passes the abort signal', async () => {
    globalThis.fetch = vi.fn(async () => ({ ok: true, status: 200, json: async () => LIST }));
    const signal = new AbortController().signal;

    const parts = await requestExplorerParts(createExplorerSource({ customEntriesState: 'none' }), { signal });

    expect(parts.custom).toBeNull();
    expect(globalThis.fetch.mock.calls).toEqual([[MDS_LIST_PATH, { cache: 'default', credentials: 'omit', signal }]]);
  });

  it('never swallows an abort', async () => {
    globalThis.fetch = vi.fn(async () => {
      throw abortError();
    });

    await expect(requestExplorerParts(createExplorerSource(null))).rejects.toMatchObject({ name: 'AbortError' });
  });
});

describe('what a load\'s answers are', () => {
  it('gives the list and the session\'s entries, either of them absent', () => {
    expect(classifyExplorerParts({ list: answer(LIST), custom: answer(CUSTOM) })).toEqual({ kind: 'parts', packaged: LIST, custom: CUSTOM });
    expect(classifyExplorerParts({ list: answer(LIST), custom: null })).toEqual({ kind: 'parts', packaged: LIST, custom: null });
  });

  it('reads a list answering 404 as a server without a snapshot, the uploads alone shown', () => {
    expect(classifyExplorerParts({ list: answer('<html>', { ok: false, status: 404 }), custom: answer(CUSTOM) })).toEqual({
      kind: 'parts',
      packaged: null,
      custom: CUSTOM,
    });
  });

  it('fails with the server\'s words, the status, or what was not JSON', () => {
    expect(classifyExplorerParts({ list: answer({ error: 'Resting.' }, { ok: false, status: 503 }), custom: null })).toEqual({
      kind: 'failed',
      message: 'Resting.',
    });
    expect(classifyExplorerParts({ list: answer(null, { ok: false, status: 502 }), custom: null }).message).toBe(
      'Explorer request failed with status 502.',
    );
    expect(classifyExplorerParts({ list: answer(null), custom: null }).message).toBe('Explorer response was not valid JSON.');
    expect(classifyExplorerParts({ list: answer(LIST), custom: answer({ error: 'Uploads unreadable.' }, { ok: false, status: 503 }) }).message).toBe(
      'Uploads unreadable.',
    );
    expect(classifyExplorerParts({ list: answer(LIST), custom: answer('text') }).message).toBe('Explorer response was not valid JSON.');
  });

  it('words a load that threw', () => {
    expect(explorerLoadFailure(new Error('Failed to fetch'))).toBe('Failed to fetch');
    expect(explorerLoadFailure(new Error(''))).toBe('Unable to load the packaged authenticator explorer.');
    expect(explorerLoadFailure('nope')).toBe('Unable to load the packaged authenticator explorer.');
  });
});
