import { afterEach, describe, expect, it, vi } from 'vitest';

import { MDS_CUSTOM_ENTRIES_PATH, MDS_INFO_PATH, MDS_LIST_PATH } from '../constants.js';
import {
  fetchExplorerInfo,
  forgetExplorerList,
  isMissingSnapshot,
  prefetchExplorerList,
  prepareSnapshotEntries,
  requestExplorerAnswer,
} from './loading.js';

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

afterEach(() => {
  vi.restoreAllMocks();
});

describe('explorer loading: the entries shown', () => {
  it('copies the entries and drops what is not an entry', () => {
    const listed = { entryId: 'aaguid:1', isLightweightEntry: true };
    const entries = prepareSnapshotEntries({ entries: [listed, null, 'text'] });

    expect(entries).toEqual([listed]);
    expect(entries[0]).not.toBe(listed);
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

  it('calls a snapshot with no entry missing', () => {
    expect(isMissingSnapshot(null)).toBe(true);
    expect(isMissingSnapshot({ meta: {} })).toBe(true);
    expect(isMissingSnapshot({ entries: [] })).toBe(true);
    expect(isMissingSnapshot({ entries: [{}] })).toBe(false);
  });
});

describe('explorer loading: what the page starts from', () => {
  it('asks the info endpoint, never from the cache', async () => {
    const info = { no: 7, customEntriesState: 'none' };
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

describe('the packaged list fetched ahead', () => {
  const LIST = { meta: { no: 7 }, entries: [{ entryId: 'aaguid:x', isLightweightEntry: true }] };
  const LIST_LOCATION = { url: MDS_LIST_PATH, cache: 'default', kind: 'static' };

  afterEach(() => {
    forgetExplorerList();
  });

  it('is fetched once, without the cookie, at the priority asked', async () => {
    globalThis.fetch = vi.fn(async () => answer(LIST));

    prefetchExplorerList(undefined, { priority: 'low' });
    prefetchExplorerList();
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    expect(globalThis.fetch).toHaveBeenCalledWith(MDS_LIST_PATH, { cache: 'default', priority: 'low', credentials: 'omit' });
  });

  it('is what the explorer\'s first load from that URL gets; a later load fetches again', async () => {
    globalThis.fetch = vi.fn(async () => answer(LIST));
    prefetchExplorerList();

    await expect(requestExplorerAnswer(LIST_LOCATION)).resolves.toMatchObject({ payload: LIST });
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    await requestExplorerAnswer(LIST_LOCATION);
    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
  });

  it('is shared by a load that starts while it is still out', async () => {
    let arrive = () => {};
    globalThis.fetch = vi.fn(() => new Promise((resolve) => { arrive = () => resolve(answer(LIST)); }));

    const first = requestExplorerAnswer(LIST_LOCATION);
    const second = requestExplorerAnswer(LIST_LOCATION);
    arrive();

    await expect(first).resolves.toMatchObject({ payload: LIST });
    await expect(second).resolves.toMatchObject({ payload: LIST });
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['a failed answer', async () => answer(null, { ok: false, status: 503 })],
    ['a fetch that failed', async () => { throw new TypeError('Failed to fetch'); }],
  ])('is dropped after %s, so the explorer fetches it again', async (_label, first) => {
    globalThis.fetch = vi.fn().mockImplementationOnce(first).mockImplementation(async () => answer(LIST));
    prefetchExplorerList();
    await vi.waitFor(() => expect(globalThis.fetch).toHaveBeenCalledTimes(1));
    await new Promise((resolve) => setTimeout(resolve, 0));

    await expect(requestExplorerAnswer(LIST_LOCATION)).resolves.toMatchObject({ payload: LIST });
    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
    expect(globalThis.fetch).toHaveBeenLastCalledWith(MDS_LIST_PATH, { cache: 'default', credentials: 'omit' });
  });

  it('keeps a later request when one it replaced fails afterwards', async () => {
    let fail = () => {};
    globalThis.fetch = vi.fn()
      .mockImplementationOnce(() => new Promise((resolve) => { fail = () => resolve(answer(null, { ok: false, status: 503 })); }))
      .mockImplementation(async () => answer(LIST));
    prefetchExplorerList();
    forgetExplorerList();

    const later = requestExplorerAnswer(LIST_LOCATION);
    fail();
    await later;
    await new Promise((resolve) => setTimeout(resolve, 0));

    prefetchExplorerList();
    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
  });

  it('is not fetched ahead again once the explorer has fetched it', async () => {
    globalThis.fetch = vi.fn(async () => answer(LIST));
    await requestExplorerAnswer(LIST_LOCATION);

    prefetchExplorerList(undefined, { priority: 'low' });
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it('is forgotten when the page starts afresh', async () => {
    globalThis.fetch = vi.fn(async () => answer(LIST));
    prefetchExplorerList();
    forgetExplorerList();

    await requestExplorerAnswer(LIST_LOCATION);
    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
  });
});

describe('the session\'s own entries', () => {
  it('are fetched afresh each time, with the cookie, and the abort signal when there is one', async () => {
    globalThis.fetch = vi.fn(async () => answer({ entries: [] }));
    const location = { url: MDS_CUSTOM_ENTRIES_PATH, cache: 'no-store', kind: 'api' };
    const signal = new AbortController().signal;

    await requestExplorerAnswer(location);
    await requestExplorerAnswer(location, signal);

    expect(globalThis.fetch.mock.calls).toEqual([
      [MDS_CUSTOM_ENTRIES_PATH, { cache: 'no-store' }],
      [MDS_CUSTOM_ENTRIES_PATH, { cache: 'no-store', signal }],
    ]);
  });

  it('read a body that is not JSON as no payload', async () => {
    globalThis.fetch = vi.fn(async () => answer(new SyntaxError('not json')));

    await expect(requestExplorerAnswer({ url: MDS_CUSTOM_ENTRIES_PATH, cache: 'no-store', kind: 'api' })).resolves.toMatchObject({ payload: null });
  });
});
