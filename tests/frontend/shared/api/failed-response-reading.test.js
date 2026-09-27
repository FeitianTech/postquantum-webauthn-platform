import { describe, expect, it } from 'vitest';

import { readFailedResponse } from '../../../../frontend/static/scripts/shared/api/failed-response.js';

// How the reader copes with an answer that is not a well-behaved Response.
describe('reading an odd failed answer', () => {
  it('reads a body that gives no text as none', async () => {
    const failure = await readFailedResponse({ status: 502, text: async () => undefined });
    expect(failure.text).toBe('The server could not be reached.');
  });

  it('reads headers that cannot be read as no content type', async () => {
    const headers = {
      get() {
        throw new TypeError('headers are gone');
      },
    };
    const failure = await readFailedResponse({ status: 400, headers, text: async () => 'Invalid signature.' });
    expect(failure.message).toBe('Invalid signature.');
  });
});
