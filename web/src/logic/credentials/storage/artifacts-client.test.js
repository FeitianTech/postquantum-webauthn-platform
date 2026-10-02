import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  deleteCredentialArtifact,
  fetchCredentialArtifact,
  fetchCredentialArtifactsBulk,
  updateCredentialSnapshot,
  uploadCredentialArtifact,
} from './artifacts-client.js';

// A saved credential's heavy parts kept on the server
// (credentials/storage/artifacts-client.js).

function jsonResponse(data, { ok = true, status = 200, contentType = 'application/json' } = {}) {
  return {
    ok,
    status,
    headers: {
      get: (name) => (name.toLowerCase() === 'content-type' ? contentType : null),
    },
    json: vi.fn(async () => data),
    text: vi.fn(async () => (typeof data === 'string' ? data : JSON.stringify(data))),
  };
}

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

describe('the requests to the artifacts API', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('fetches one artifact: none for a blank id, the artifact, none for a 404, and none for an error', async () => {
    expect(await fetchCredentialArtifact('   ')).toBeNull();
    expect(fetch).not.toHaveBeenCalled();

    fetch.mockResolvedValueOnce(jsonResponse({ artifact: { a: 1 } }));
    await expect(fetchCredentialArtifact('  abc  ')).resolves.toEqual({ a: 1 });

    const [url] = fetch.mock.calls[0];
    expect(url).toContain('/api/advanced/credential-artifacts/abc');

    fetch.mockResolvedValueOnce(jsonResponse({ notArtifact: true }));
    await expect(fetchCredentialArtifact('abc')).resolves.toBeNull();

    fetch.mockResolvedValueOnce(jsonResponse('not found', { ok: false, status: 404 }));
    await expect(fetchCredentialArtifact('abc')).resolves.toBeNull();

    fetch.mockResolvedValueOnce(jsonResponse('boom', { ok: false, status: 500 }));
    await expect(fetchCredentialArtifact('abc')).rejects.toThrow(/boom|Request failed/);
  });

  it('fetches several artifacts by their trimmed ids, and none when that fails', async () => {
    await expect(fetchCredentialArtifactsBulk(null)).resolves.toEqual({});

    fetch.mockResolvedValueOnce(jsonResponse({ artifacts: { one: { x: 1 } } }));
    await expect(
      fetchCredentialArtifactsBulk([' a ', '', 'b', '   ']),
    ).resolves.toEqual({ one: { x: 1 } });

    const [, options] = fetch.mock.calls[0];
    expect(options.method).toBe('POST');
    expect(JSON.parse(options.body)).toEqual({ storageIds: ['a', 'b'] });

    fetch.mockRejectedValueOnce(new Error('network'));
    await expect(fetchCredentialArtifactsBulk(['id'])).resolves.toEqual({});
  });

  it('uploads an artifact for a storage id, and says whether it was kept', async () => {
    await expect(uploadCredentialArtifact('', { a: 1 })).resolves.toBe(false);
    await expect(uploadCredentialArtifact('id', null)).resolves.toBe(false);

    fetch.mockResolvedValueOnce(jsonResponse({ ok: true }));
    await expect(uploadCredentialArtifact(' id ', { a: 1 }, { merge: false })).resolves.toBe(true);

    const [, options] = fetch.mock.calls[0];
    expect(options.method).toBe('PUT');
    expect(JSON.parse(options.body)).toEqual({ artifact: { a: 1 }, merge: false });

    fetch.mockRejectedValueOnce(new Error('upload failed'));
    await expect(uploadCredentialArtifact('id', { a: 1 })).resolves.toBe(false);
  });

  it('updates an artifact\'s snapshot for a storage id, and says whether it was kept', async () => {
    await expect(updateCredentialSnapshot('', {})).resolves.toBe(false);
    await expect(updateCredentialSnapshot('id', 'bad')).resolves.toBe(false);

    fetch.mockResolvedValueOnce(jsonResponse({ ok: true }));
    await expect(updateCredentialSnapshot(' id ', { snap: 1 })).resolves.toBe(true);

    const [, options] = fetch.mock.calls[0];
    expect(options.method).toBe('PUT');
    expect(JSON.parse(options.body)).toEqual({ snapshot: { snap: 1 } });

    fetch.mockRejectedValueOnce(new Error('snapshot failed'));
    await expect(updateCredentialSnapshot('id', {})).resolves.toBe(false);
  });

  it('deletes an artifact, and says how the delete went', async () => {
    await expect(deleteCredentialArtifact('')).resolves.toEqual(
      expect.objectContaining({
        ok: false,
        status: 'failed',
      }),
    );

    fetch.mockResolvedValueOnce(jsonResponse({ status: 'deleted' }));
    await expect(deleteCredentialArtifact(' id ')).resolves.toEqual({
      ok: true,
      status: 'deleted',
      httpStatus: 200,
    });

    const [, options] = fetch.mock.calls[0];
    expect(options.method).toBe('DELETE');

    fetch.mockResolvedValueOnce(jsonResponse({ status: 'absent' }));
    await expect(deleteCredentialArtifact('id')).resolves.toEqual({
      ok: false,
      status: 'absent',
      httpStatus: 200,
    });

    fetch.mockResolvedValueOnce(jsonResponse({ status: 'failed', error: 'delete failed' }, { ok: false, status: 500 }));
    await expect(deleteCredentialArtifact('id')).resolves.toEqual({
      ok: false,
      status: 'failed',
      httpStatus: 500,
      error: 'delete failed',
    });

    fetch.mockRejectedValueOnce(new Error('delete failed'));
    await expect(deleteCredentialArtifact('id')).resolves.toEqual(
      expect.objectContaining({
        ok: false,
        status: 'failed',
        httpStatus: null,
      }),
    );
  });

  it('reads an answer that is not JSON as no artifact', async () => {
    fetch.mockResolvedValueOnce(jsonResponse({ ignored: true }, { contentType: 'text/plain' }));
    await expect(fetchCredentialArtifact('abc')).resolves.toBeNull();
  });
});

describe('the artifacts API\'s unusual answers', () => {
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
