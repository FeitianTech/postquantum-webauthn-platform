import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  deleteCredentialArtifact,
  fetchCredentialArtifact,
  fetchCredentialArtifactsBulk,
} from '../../../../frontend/static/scripts/shared/storage/artifacts-client.js';

const STORAGE_ID = 'THBi3GyG-MexchMynbz3x5Nv::1a0c4506c00::abb1b052d88044e486bb1446aa6a1e87';

function jsonAnswer(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

// A body that fails while it is read, as when the connection drops.
function droppedBody() {
  return new ReadableStream({
    start(controller) {
      controller.error(new TypeError('network error'));
    },
  });
}

describe('the credential artifacts client', () => {
  beforeEach(() => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('asks nothing for a storage id that is not text', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    await expect(fetchCredentialArtifact(42)).resolves.toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('names the status when a refusal has no text', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 503 })));

    await expect(fetchCredentialArtifact(STORAGE_ID)).rejects.toMatchObject({
      message: 'Request failed with status 503',
      status: 503,
    });
  });

  it('reads an answer without a content type as no artifact', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 200 })));

    await expect(fetchCredentialArtifact(STORAGE_ID)).resolves.toBeNull();
  });

  it('answers no artifacts when the bulk answer holds none', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonAnswer({ storageIds: [STORAGE_ID] })));

    await expect(fetchCredentialArtifactsBulk([STORAGE_ID])).resolves.toEqual({});
  });

  it('reports a plain-text refusal of a delete as its error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('  Service Unavailable\n', {
      status: 503,
      headers: { 'Content-Type': 'text/plain' },
    })));

    await expect(deleteCredentialArtifact(STORAGE_ID)).resolves.toEqual({
      ok: false,
      status: 'failed',
      httpStatus: 503,
      error: 'Service Unavailable',
    });
  });

  it('names the status when a delete is refused with an empty body', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 502 })));

    await expect(deleteCredentialArtifact(STORAGE_ID)).resolves.toEqual({
      ok: false,
      status: 'failed',
      httpStatus: 502,
      error: 'Request failed with status 502',
    });
  });

  it('treats a delete answer that is not valid JSON as no answer', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{"status": "del', {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })));

    await expect(deleteCredentialArtifact(STORAGE_ID)).resolves.toEqual({
      ok: false,
      status: 'failed',
      httpStatus: 200,
      error: 'Request failed with status 200',
    });
  });

  it('treats a delete answer whose body could not be read as no answer', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(droppedBody(), { status: 500 })));

    await expect(deleteCredentialArtifact(STORAGE_ID)).resolves.toEqual({
      ok: false,
      status: 'failed',
      httpStatus: 500,
      error: 'Request failed with status 500',
    });
  });

  it('says the delete failed when the request fails with something other than an Error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw 'offline';
    }));

    await expect(deleteCredentialArtifact(STORAGE_ID)).resolves.toEqual({
      ok: false,
      status: 'failed',
      httpStatus: null,
      error: 'Delete request failed.',
    });
  });
});
