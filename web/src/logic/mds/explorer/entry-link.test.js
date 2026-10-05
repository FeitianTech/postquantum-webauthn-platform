import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  entryIdForAaguid,
  requestEntryDetail,
  requestResolvedEntry,
  resolveQueryForEntry,
} from './entry-link.js';

function answer(body, { ok = true, status = 200 } = {}) {
  return { ok, status, json: async () => body, text: async () => JSON.stringify(body) };
}

afterEach(() => {
  delete globalThis.fetch;
});

describe('opening an entry from elsewhere', () => {

  it('names an AAGUID\'s entry as the server does', () => {
    expect(entryIdForAaguid('F1D0F1D0-0000-4000-8000-000000000001')).toBe('aaguid:f1d0f1d0-0000-4000-8000-000000000001');
    expect(entryIdForAaguid('f1d0f1d000004000800000000000000A')).toBe('aaguid:f1d0f1d0-0000-4000-8000-00000000000a');
    expect(entryIdForAaguid('not an aaguid')).toBe('');
    expect(entryIdForAaguid(null)).toBe('');
  });
});

describe('resolving an entry the list does not hold', () => {
  it('asks by entry id, else AAGUID, else AAID', () => {
    expect(resolveQueryForEntry({ entryId: 'aaid:F1D0#0012', aaguid: 'x', id: 'y' })).toEqual({ entryId: 'aaid:F1D0#0012' });
    expect(resolveQueryForEntry({ entryId: 5, aaguid: 'F1D0F1D0000040008000000000000001' })).toEqual({
      aaguid: 'f1d0f1d0-0000-4000-8000-000000000001',
    });
    expect(resolveQueryForEntry({ aaguid: '', id: 'F1D0#0012' })).toEqual({ aaid: 'F1D0#0012' });
    expect(resolveQueryForEntry({ id: 7 })).toEqual({});
    expect(resolveQueryForEntry(null)).toEqual({});
  });

  it('asks the server without the cache and gives the entry it answers', async () => {
    const entry = { entryId: 'aaguid:x', name: 'Key' };
    globalThis.fetch = vi.fn(async () => answer({ entry }));
    await expect(requestResolvedEntry({ entryId: 'aaid:F1D0#0012', aaguid: '', aaid: 5 })).resolves.toEqual({ entry });
    expect(globalThis.fetch).toHaveBeenCalledWith('/api/mds/metadata/resolve?entryId=aaid%3AF1D0%230012', { cache: 'no-store' });

    const signal = new AbortController().signal;
    await requestResolvedEntry({ aaguid: 'x' }, { signal });
    expect(globalThis.fetch).toHaveBeenLastCalledWith('/api/mds/metadata/resolve?aaguid=x', { cache: 'no-store', signal });
  });

  it('asks nothing when there is nothing to ask', async () => {
    globalThis.fetch = vi.fn();
    await expect(requestResolvedEntry({})).resolves.toEqual({ entry: null });
    await expect(requestResolvedEntry(null)).resolves.toEqual({ entry: null });
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('gives no entry for an answer without one', async () => {
    globalThis.fetch = vi.fn(async () => answer({ entry: 'text' }));
    await expect(requestResolvedEntry({ entryId: 'x' })).resolves.toEqual({ entry: null });
    globalThis.fetch = vi.fn(async () => answer(null));
    await expect(requestResolvedEntry({ entryId: 'x' })).resolves.toEqual({ entry: null });
  });

  it('keeps the server\'s sentence for a refusal', async () => {
    globalThis.fetch = vi.fn(async () => answer({ error: 'Metadata entry not found.' }, { ok: false, status: 404 }));
    await expect(requestResolvedEntry({ entryId: 'aaguid:gone' })).resolves.toEqual({
      entry: null,
      failure: { status: 404, message: 'Metadata entry not found.' },
    });
    globalThis.fetch = vi.fn(async () => answer({ error: 'Provide exactly one of entryId, aaguid, or aaid.' }, { ok: false, status: 400 }));
    await expect(requestResolvedEntry({ entryId: 'x' })).resolves.toMatchObject({
      failure: { status: 400, message: 'Provide exactly one of entryId, aaguid, or aaid.' },
    });
  });

  it('throws on a body that is not JSON', async () => {
    globalThis.fetch = vi.fn(async () => ({ ok: true, status: 200, json: async () => { throw new SyntaxError('not json'); } }));
    await expect(requestResolvedEntry({ entryId: 'x' })).rejects.toThrow('not json');
  });
});

describe('an entry\'s detail', () => {
  const LISTED = { entryId: 'aaid:F1D0#0012', id: 'F1D0#0012', detailUrl: '/assets/mds/entries/aaid%3AF1D0%230012?v=7.abc.1' };
  const DETAIL = { ...LISTED, metadataStatement: { description: 'Key' }, isLightweightEntry: false };

  it('comes from the file the listed entry names, without the cookie', async () => {
    globalThis.fetch = vi.fn(async () => answer(DETAIL));
    await expect(requestEntryDetail(LISTED, LISTED.entryId)).resolves.toEqual({ entry: DETAIL });
    expect(globalThis.fetch).toHaveBeenCalledWith(LISTED.detailUrl, { credentials: 'omit' });

    const signal = new AbortController().signal;
    await requestEntryDetail(LISTED, LISTED.entryId, { signal });
    expect(globalThis.fetch).toHaveBeenLastCalledWith(LISTED.detailUrl, { credentials: 'omit', signal });
  });

  it('is asked of the server when the file is missing, unreadable or not an entry', async () => {
    const resolved = { entry: { ...DETAIL, rawEntry: {} } };
    for (const fromFile of [
      async () => answer({ error: 'gone' }, { ok: false, status: 404 }),
      async () => { throw new TypeError('Failed to fetch'); },
      async () => answer(['not an entry']),
      async () => answer(null),
    ]) {
      globalThis.fetch = vi.fn().mockImplementationOnce(fromFile).mockImplementation(async () => answer(resolved));
      await expect(requestEntryDetail(LISTED, LISTED.entryId)).resolves.toEqual(resolved);
      expect(globalThis.fetch).toHaveBeenLastCalledWith('/api/mds/metadata/resolve?entryId=aaid%3AF1D0%230012', { cache: 'no-store' });
    }
  });

  it('is asked of the server by the entry id for an entry the list does not hold, or one without a file', async () => {
    globalThis.fetch = vi.fn(async () => answer({ entry: DETAIL }));
    await requestEntryDetail(null, 'aaguid:gone');
    expect(globalThis.fetch).toHaveBeenLastCalledWith('/api/mds/metadata/resolve?entryId=aaguid%3Agone', { cache: 'no-store' });
    await requestEntryDetail({ entryId: 'aaguid:listed' }, 'aaguid:listed');
    expect(globalThis.fetch).toHaveBeenLastCalledWith('/api/mds/metadata/resolve?entryId=aaguid%3Alisted', { cache: 'no-store' });
  });

  it('stops when it is called off', async () => {
    const aborted = Object.assign(new Error('aborted'), { name: 'AbortError' });
    globalThis.fetch = vi.fn(async () => { throw aborted; });
    await expect(requestEntryDetail(LISTED, LISTED.entryId)).rejects.toBe(aborted);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });
});

