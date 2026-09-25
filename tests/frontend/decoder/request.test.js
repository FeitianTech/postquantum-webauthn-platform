import { describe, expect, it, vi } from 'vitest';

import { FailedResponseError } from '../../../frontend/static/scripts/shared/api/failed-response.js';
import {
  CODEC_MODES,
  buildCodecRequest,
  codecFailureText,
  codecProgressText,
  codecRawJson,
  codecSuccessText,
  requestCodec,
  validateCodecInput,
} from '../../../frontend/static/scripts/decoder/codec/request.js';

function jsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => 'application/json' },
    text: async () => JSON.stringify(body),
    json: async () => body,
  };
}

describe('codec request: the checks before sending', () => {
  it('names the two modes', () => {
    expect(CODEC_MODES).toEqual(['decode', 'encode']);
  });

  it('refuses an empty or blank input, in the words of each mode', () => {
    expect(validateCodecInput('decode', '  \n ', null)).toBe('Codec input is empty. Please paste something to process.');
    expect(validateCodecInput('encode', '', 'EDN')).toBe('Encoder input is empty. Provide JSON to encode.');
  });

  it('lets any decode input through: the server reads it', () => {
    expect(validateCodecInput('decode', 'not json at all', null)).toBeNull();
  });

  it('asks for a format before encoding', () => {
    expect(validateCodecInput('encode', '{}', '')).toBe('Select an encoding format before encoding.');
    expect(validateCodecInput('encode', '{}', '   ')).toBe('Select an encoding format before encoding.');
    expect(validateCodecInput('encode', '{}', null)).toBe('Select an encoding format before encoding.');
  });

  it('sends EDN as written, without reading it as JSON', () => {
    expect(validateCodecInput('encode', '{1: h\'00\'}', 'EDN')).toBeNull();
    expect(validateCodecInput('encode', 'not json', 'edn (exact bytes)')).toBeNull();
  });

  it('reads every other format as JSON first', () => {
    expect(validateCodecInput('encode', '{"a": ', 'CBOR (canonical)')).toBe('Encoder expects valid JSON input.');
    expect(validateCodecInput('encode', '{"a": 1}', 'CBOR (canonical)')).toBeNull();
    expect(validateCodecInput('encode', '{"anything": true}', 'CBOR (CTAP/WebAuthn Data)')).toBeNull();
  });

  it('names the chosen format when the JSON holds nothing it can take', () => {
    expect(validateCodecInput('encode', '{"a": true}', 'PEM')).toBe('Input cannot be converted into PEM.');
    expect(validateCodecInput('encode', '{"hex": "3003020101"}', 'DER')).toBeNull();
  });
});

describe('codec request: the body', () => {
  it('sends the input as typed, and lenient only when asked', () => {
    expect(buildCodecRequest('decode', ' a1 ')).toEqual({ payload: ' a1 ', mode: 'decode' });
    expect(buildCodecRequest('decode', 'a1', { lenient: false })).toEqual({ payload: 'a1', mode: 'decode' });
    expect(buildCodecRequest('decode', 'a1', { lenient: true })).toEqual({ payload: 'a1', mode: 'decode', lenient: true });
  });

  it('sends the format when encoding, and never lenient', () => {
    expect(buildCodecRequest('encode', '{}', { format: 'COSE', lenient: true }))
      .toEqual({ payload: '{}', mode: 'encode', format: 'COSE' });
  });
});

describe('codec request: sending it', () => {
  it('posts JSON to /api/codec and returns the answer', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(200, { success: true, type: 'JSON' }));
    await expect(requestCodec({ payload: '{}', mode: 'decode' }, fetchImpl)).resolves.toEqual({ success: true, type: 'JSON' });
    expect(fetchImpl).toHaveBeenCalledWith('/api/codec', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"payload":"{}","mode":"decode"}',
    });
  });

  it('uses the page\'s fetch when given none', async () => {
    globalThis.fetch = vi.fn(async () => jsonResponse(200, { success: true }));
    await expect(requestCodec({ payload: 'a0', mode: 'decode' })).resolves.toEqual({ success: true });
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it('throws a refusal with the server\'s message, offset and path kept in its failure', async () => {
    const body = { error: 'Not JSON at offset 6 (${"a"}): NaN is not JSON.', offset: 6, path: '${"a"}' };
    const fetchImpl = vi.fn(async () => jsonResponse(422, body));
    const error = await requestCodec({ payload: '{"a": NaN}', mode: 'decode' }, fetchImpl).catch((caught) => caught);
    expect(error).toBeInstanceOf(FailedResponseError);
    expect(error.message).toBe(body.error);
    expect(error.failure.body).toEqual(body);
  });

  it('says so when a success is not JSON', async () => {
    const fetchImpl = vi.fn(async () => ({ ok: true, status: 200, json: async () => { throw new SyntaxError('bad'); } }));
    await expect(requestCodec({ payload: 'a0', mode: 'decode' }, fetchImpl)).rejects.toThrow('Failed to parse decoder response.');
  });
});

describe('codec request: the sentences around it', () => {
  it('says what is happening, and what happened', () => {
    expect(codecProgressText('decode')).toBe('Decoding…');
    expect(codecProgressText('encode')).toBe('Encoding…');
    expect(codecSuccessText('decode')).toBe('Response decoded successfully!');
    expect(codecSuccessText('encode')).toBe('Payload encoded successfully!');
  });

  it('prefixes a failure with the step that failed', () => {
    expect(codecFailureText('decode', new Error('No.'))).toBe('Decoding failed: No.');
    expect(codecFailureText('encode', 'plain')).toBe('Encoding failed: plain');
  });

  it('shows the whole answer as JSON indented by two spaces', () => {
    expect(codecRawJson({ success: true, data: { a: [1] } })).toBe('{\n  "success": true,\n  "data": {\n    "a": [\n      1\n    ]\n  }\n}');
  });
});
