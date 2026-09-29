import { afterEach, describe, expect, it, vi } from 'vitest';

import { decodePayloadThroughApi } from './decode-payload.js';
import { answerResponse } from '@/test/logic/simple/ceremony-answers.js';
import { registration } from '@/test/logic/advanced/credentials/registration-detail-answers.js';

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

describe('decodePayloadThroughApi', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  /** Puts a decoder in the page that answers `answer` (a status and a body). */
  function decoderAnswering(answer) {
    const fetch = vi.fn(async () => answerResponse(answer));
    vi.stubGlobal('fetch', fetch);
    return fetch;
  }

  it("posts the payload, trimmed, to the decoder and gives the decoder's answer", async () => {
    const entry = registration('es256');
    const fetch = decoderAnswering({ status: 200, body: entry.authenticatorDataDecode });
    await expect(decodePayloadThroughApi(`  ${entry.authenticatorData}\n`)).resolves.toEqual(entry.authenticatorDataDecode);
    expect(fetch).toHaveBeenCalledWith('/api/decode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload: entry.authenticatorData }),
    });
  });

  it('refuses a blank payload without asking the decoder', async () => {
    const fetch = decoderAnswering({ status: 200, body: {} });
    await expect(decodePayloadThroughApi(' \n')).rejects.toThrow('Decoder payload must be a non-empty string.');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('refuses a payload that is not text', async () => {
    const fetch = decoderAnswering({ status: 200, body: {} });
    await expect(decodePayloadThroughApi(42)).rejects.toThrow('Decoder payload must be a non-empty string.');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('throws the error an answer carries', async () => {
    decoderAnswering({ status: 200, body: { error: 'Unable to decode payload.' } });
    await expect(decodePayloadThroughApi('AQID')).rejects.toThrow('Unable to decode payload.');
  });

  it('throws when the answer holds no data', async () => {
    decoderAnswering({ status: 200, body: { success: true, type: 'Authenticator data' } });
    await expect(decodePayloadThroughApi('AQID')).rejects.toThrow('Decoder response did not include data.');
  });

  it('throws when the answer is not a map', async () => {
    decoderAnswering({ status: 200, body: null });
    await expect(decodePayloadThroughApi('AQID')).rejects.toThrow('Decoder response did not include data.');
  });
});
