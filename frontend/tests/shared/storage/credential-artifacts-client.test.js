import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  deleteCredentialArtifact,
  fetchCredentialArtifact,
  fetchCredentialArtifactsBulk,
  updateCredentialSnapshot,
  uploadCredentialArtifact,
} from '../../../static/scripts/shared/credential-artifacts-client.js';

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

describe('credential-artifacts-client', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('fetchCredentialArtifact handles normalization, success, 404, and generic errors', async () => {
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

  it('fetchCredentialArtifactsBulk posts normalized ids and handles failures', async () => {
    await expect(fetchCredentialArtifactsBulk(null)).resolves.toEqual({});

    fetch.mockResolvedValueOnce(jsonResponse({ artifacts: { one: { x: 1 } } }));
    await expect(
      fetchCredentialArtifactsBulk([' a ', '', 'b', '   ']),
    ).resolves.toEqual({ one: { x: 1 } });

    const [, options] = fetch.mock.calls[0];
    expect(options.method).toBe('POST');
    expect(JSON.parse(options.body)).toEqual({ storageIds: ['a', 'b'] });

    fetch.mockRejectedValueOnce(new Error('network'));
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await expect(fetchCredentialArtifactsBulk(['id'])).resolves.toEqual({});
    expect(warnSpy).toHaveBeenCalled();
    warnSpy.mockRestore();
  });

  it('uploadCredentialArtifact validates inputs and handles success/failure', async () => {
    await expect(uploadCredentialArtifact('', { a: 1 })).resolves.toBe(false);
    await expect(uploadCredentialArtifact('id', null)).resolves.toBe(false);

    fetch.mockResolvedValueOnce(jsonResponse({ ok: true }));
    await expect(uploadCredentialArtifact(' id ', { a: 1 }, { merge: false })).resolves.toBe(true);

    const [, options] = fetch.mock.calls[0];
    expect(options.method).toBe('PUT');
    expect(JSON.parse(options.body)).toEqual({ artifact: { a: 1 }, merge: false });

    fetch.mockRejectedValueOnce(new Error('upload failed'));
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await expect(uploadCredentialArtifact('id', { a: 1 })).resolves.toBe(false);
    expect(warnSpy).toHaveBeenCalled();
    warnSpy.mockRestore();
  });

  it('updateCredentialSnapshot validates and performs snapshot update', async () => {
    await expect(updateCredentialSnapshot('', {})).resolves.toBe(false);
    await expect(updateCredentialSnapshot('id', 'bad')).resolves.toBe(false);

    fetch.mockResolvedValueOnce(jsonResponse({ ok: true }));
    await expect(updateCredentialSnapshot(' id ', { snap: 1 })).resolves.toBe(true);

    const [, options] = fetch.mock.calls[0];
    expect(options.method).toBe('PUT');
    expect(JSON.parse(options.body)).toEqual({ snapshot: { snap: 1 } });

    fetch.mockRejectedValueOnce(new Error('snapshot failed'));
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await expect(updateCredentialSnapshot('id', {})).resolves.toBe(false);
    expect(warnSpy).toHaveBeenCalled();
    warnSpy.mockRestore();
  });

  it('deleteCredentialArtifact validates and handles delete outcomes', async () => {
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
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await expect(deleteCredentialArtifact('id')).resolves.toEqual(
      expect.objectContaining({
        ok: false,
        status: 'failed',
        httpStatus: null,
      }),
    );
    expect(warnSpy).toHaveBeenCalled();
    warnSpy.mockRestore();
  });

  it('jsonFetch returns null for non-json content type', async () => {
    fetch.mockResolvedValueOnce(jsonResponse({ ignored: true }, { contentType: 'text/plain' }));
    await expect(fetchCredentialArtifact('abc')).resolves.toBeNull();
  });
});
