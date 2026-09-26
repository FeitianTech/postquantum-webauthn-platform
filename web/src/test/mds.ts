// The MDS fixture (tests/fixtures/mds, built by tests/app/metadata/mds_fixture.py
// with the server's own code) as the component tests use it, and a fetch that
// answers like Flask serving it.
import summary from '@test-fixtures/mds/snapshot/fido-mds3.explorer.json.meta.json';
import full from '@test-fixtures/mds/snapshot/fido-mds3.explorer.full.json';
import { vi } from 'vitest';

import type { MdsEntry, MdsSnapshot } from '@/components/mds/model';

export const FIXTURE_SNAPSHOT = full as unknown as MdsSnapshot;
export const FIXTURE_ENTRIES = FIXTURE_SNAPSHOT.entries as MdsEntry[];
export const SNAPSHOT_URL = '/assets/dev/fido-mds3.explorer.full.json';
export const FIXTURE_INFO = { ...summary, snapshotUrl: SNAPSHOT_URL, customEntriesState: 'none' };

export function entryNamed(name: string) {
  return FIXTURE_ENTRIES.find((entry) => entry.name === name)!;
}

export function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

type Route = (init: RequestInit | undefined, url: string) => Response | Promise<Response>;

// A fetch answering by path; anything else is a 404 the test did not expect.
export function stubFetch(routes: Record<string, Route>) {
  const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname : input.url;
    const path = url.split('?')[0];
    const route = routes[path];
    return route ? route(init, url) : json({ error: `Unexpected ${path}` }, 404);
  });
  vi.stubGlobal('fetch', fetch);
  return fetch;
}

// GET /api/mds/metadata/resolve as Flask answers it: the entry an entryId,
// AAGUID or AAID names, else its 404.
export function resolveFrom(entries: MdsEntry[] = FIXTURE_ENTRIES): Route {
  return (_init, url) => {
    const query = new URLSearchParams(url.split('?')[1] ?? '');
    const found = entries.find(
      (entry) =>
        entry.entryId === query.get('entryId') ||
        (query.has('aaguid') && entry.aaguid === query.get('aaguid')) ||
        (query.has('aaid') && entry.id === query.get('aaid')),
    );
    return found ? json({ entry: found }) : json({ error: 'Metadata entry not found.' }, 404);
  };
}

// Flask with the fixture, for a session that has uploaded nothing.
export function fixtureRoutes(overrides: Record<string, Route> = {}) {
  return {
    '/api/mds/metadata/info': () => json(FIXTURE_INFO),
    '/api/mds/metadata/resolve': resolveFrom(),
    [SNAPSHOT_URL]: () => json(FIXTURE_SNAPSHOT),
    '/api/mds/metadata/explorer/full': () => json(FIXTURE_SNAPSHOT),
    ...overrides,
  };
}
