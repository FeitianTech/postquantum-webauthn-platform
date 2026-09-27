import { vi } from 'vitest';

export function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

export type Route = (init: RequestInit | undefined, url: string) => Response | Promise<Response>;

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
