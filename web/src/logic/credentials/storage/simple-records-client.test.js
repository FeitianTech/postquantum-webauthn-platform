import { afterEach, describe, expect, it, vi } from 'vitest';

import { deleteSimpleCredentialRecord } from './simple-records-client.js';

// The Simple tab's records on the server (credentials/storage/simple-records-client.js).

describe('deleting a Simple credential\'s record', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends a DELETE for its base64url ID under its username as saved, and reads the answer', async () => {
    const fetch = vi.fn(async () => new Response(JSON.stringify({ status: 'deleted' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetch);

    // An ID a browser saved in standard base64 goes in base64url; the name as it was saved.
    await expect(deleteSimpleCredentialRecord('a+b/', ' Alice & Bob ')).resolves.toEqual({
      ok: true,
      status: 'deleted',
      httpStatus: 200,
    });

    const [url, options] = fetch.mock.calls[0];
    expect(url).toBe('/api/simple/credentials/a-b_?email=%20Alice%20%26%20Bob%20');
    expect(options.method).toBe('DELETE');
  });
});
