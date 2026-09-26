import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  ENTRY_LINK_MESSAGES,
  entryIdForAaguid,
  requestResolvedEntry,
  resolveQueryForEntry,
} from '../../../../../frontend/static/scripts/advanced/mds/explorer/entry-link.js';

function answer(body, { ok = true, status = 200 } = {}) {
  return { ok, status, json: async () => body, text: async () => JSON.stringify(body) };
}

afterEach(() => {
  delete globalThis.fetch;
});

describe('opening an entry from elsewhere (MDS-J1, J2)', () => {
  it('keeps the credential jump\'s sentences', () => {
    expect(ENTRY_LINK_MESSAGES).toEqual({
      locating: 'Locating metadata entry...',
      opening: 'Opening authenticator metadata...',
      notLocated: 'Unable to locate metadata entry.',
      failed: 'Unable to open authenticator metadata.',
      unavailable: 'Authenticator metadata entry unavailable.',
      notFound: 'Authenticator metadata not found.',
    });
    expect(Object.isFrozen(ENTRY_LINK_MESSAGES)).toBe(true);
  });

  it('names an AAGUID\'s entry as the server does', () => {
    expect(entryIdForAaguid('F1D0F1D0-0000-4000-8000-000000000001')).toBe('aaguid:f1d0f1d0-0000-4000-8000-000000000001');
    expect(entryIdForAaguid('f1d0f1d000004000800000000000000A')).toBe('aaguid:f1d0f1d0-0000-4000-8000-00000000000a');
    expect(entryIdForAaguid('not an aaguid')).toBe('');
    expect(entryIdForAaguid(null)).toBe('');
  });
});

describe('resolving an entry the list does not hold (MDS-D2)', () => {
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
