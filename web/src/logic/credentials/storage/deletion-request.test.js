import { afterEach, describe, expect, it, vi } from 'vitest';

import { requestDeletion } from './deletion-request.js';

// A DELETE's answer as the saved credentials' deletion reads it
// (credentials/storage/deletion-request.js).

const URL = '/api/advanced/credential-artifacts/cred-1';

function answering(body, init) {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(body, init)));
}

function json(body, status = 200) {
  answering(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

// A body that fails while it is read, as when the connection drops.
function droppedBody() {
  return new ReadableStream({
    start(controller) {
      controller.error(new TypeError('network error'));
    },
  });
}

describe('a deletion\'s answer', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends a DELETE for the visitor, keyed on their cookie', async () => {
    json({ status: 'deleted' });

    await requestDeletion(URL);

    expect(fetch).toHaveBeenCalledWith(URL, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
    });
  });

  it('says deleted, absent, or failed with the server\'s reason', async () => {
    json({ status: 'deleted' });
    await expect(requestDeletion(URL)).resolves.toEqual({ ok: true, status: 'deleted', httpStatus: 200 });

    json({ status: ' Absent ' }, 404);
    await expect(requestDeletion(URL)).resolves.toEqual({ ok: false, status: 'absent', httpStatus: 404 });

    json({ status: 'failed', error: ' delete failed ' }, 500);
    await expect(requestDeletion(URL)).resolves.toEqual({
      ok: false,
      status: 'failed',
      httpStatus: 500,
      error: 'delete failed',
    });

    // Deleted is believed only from a success.
    json({ status: 'deleted' }, 500);
    await expect(requestDeletion(URL)).resolves.toMatchObject({ ok: false, status: 'failed', httpStatus: 500 });
  });

  it('reports a plain-text refusal as its error', async () => {
    answering('  Service Unavailable\n', { status: 503, headers: { 'Content-Type': 'text/plain' } });

    await expect(requestDeletion(URL)).resolves.toEqual({
      ok: false,
      status: 'failed',
      httpStatus: 503,
      error: 'Service Unavailable',
    });
  });

  it('names the status when a refusal has an empty body', async () => {
    answering(null, { status: 502 });

    await expect(requestDeletion(URL)).resolves.toEqual({
      ok: false,
      status: 'failed',
      httpStatus: 502,
      error: 'Request failed with status 502',
    });
  });

  it('treats an answer that is not valid JSON as no answer', async () => {
    answering('{"status": "del', { status: 200, headers: { 'Content-Type': 'application/json' } });

    await expect(requestDeletion(URL)).resolves.toEqual({
      ok: false,
      status: 'failed',
      httpStatus: 200,
      error: 'Request failed with status 200',
    });
  });

  it('treats an answer whose body could not be read as no answer', async () => {
    answering(droppedBody(), { status: 500 });

    await expect(requestDeletion(URL)).resolves.toEqual({
      ok: false,
      status: 'failed',
      httpStatus: 500,
      error: 'Request failed with status 500',
    });
  });

  it('says the request failed, with its error when it is one', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new Error('offline');
    }));
    await expect(requestDeletion(URL)).resolves.toEqual({
      ok: false,
      status: 'failed',
      httpStatus: null,
      error: 'offline',
    });

    vi.stubGlobal('fetch', vi.fn(async () => {
      throw 'offline';
    }));
    await expect(requestDeletion(URL)).resolves.toEqual({
      ok: false,
      status: 'failed',
      httpStatus: null,
      error: 'Delete request failed.',
    });
  });
});
