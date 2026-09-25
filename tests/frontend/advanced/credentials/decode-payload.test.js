import { describe, expect, it, vi } from 'vitest';

import { decodePayloadThroughApi } from '../../../../frontend/static/scripts/advanced/credential-display/registration-result.js';

function failedResponse(status, body, contentType = 'application/json') {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return {
    ok: false,
    status,
    headers: new Headers({ 'Content-Type': contentType }),
    json: vi.fn(async () => JSON.parse(text)),
    text: vi.fn().mockResolvedValue(text),
  };
}

describe('the decode request behind the registration details', () => {
  it('answering 400 with a JSON error', async () => {
    fetch.mockResolvedValueOnce(failedResponse(400, { error: 'The payload is not valid CBOR.' }));

    await expect(decodePayloadThroughApi('AQID')).rejects.toThrowErrorMatchingInlineSnapshot(`[FailedResponseError: The payload is not valid CBOR.]`);
  });

  it('answering 413', async () => {
    fetch.mockResolvedValueOnce(failedResponse(413, {
      error: 'The request is larger than the limit of 8388608 bytes this server accepts.',
    }));

    await expect(decodePayloadThroughApi('AQID')).rejects.toThrowErrorMatchingInlineSnapshot(`[FailedResponseError: The request is larger than the limit of 8388608 bytes this server accepts. Send a smaller request.]`);
  });
});
