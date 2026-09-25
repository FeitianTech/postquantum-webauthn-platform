// What the Codec sends and what it says around a request, without the page:
// the checks made before sending, the request itself, and the sentences for
// progress, success and failure. The current panel (process.js) and the new UI
// in web/ both use this one copy.
import { FailedResponseError, readFailedResponse } from '../../shared/api/failed-response.js';
import { canEncodeToFormat } from './encoding/can-encode.js';
import { getCanonicalEncoderFormat } from './encoding/format.js';

export const CODEC_MODES = ['decode', 'encode'];

// Why `input` cannot be sent in `mode` (with `format` when encoding), or null
// when it can.
export function validateCodecInput(mode, input, format) {
    if (!input.trim()) {
        return mode === 'encode'
            ? 'Encoder input is empty. Provide JSON to encode.'
            : 'Codec input is empty. Please paste something to process.';
    }
    if (mode !== 'encode') {
        return null;
    }
    if (!format || !format.trim()) {
        return 'Select an encoding format before encoding.';
    }

    // EDN is not JSON: it goes to the server as written, which reads it and
    // names the offset where it is not valid.
    if (getCanonicalEncoderFormat(format) === 'edn') {
        return null;
    }
    let parsedValue;
    try {
        parsedValue = JSON.parse(input);
    } catch (parseError) {
        return 'Encoder expects valid JSON input.';
    }
    if (!canEncodeToFormat(parsedValue, format)) {
        return `Input cannot be converted into ${format}.`;
    }
    return null;
}

// The body of POST /api/codec. The input goes as typed; `lenient` is sent only
// when asked for, and only when decoding.
export function buildCodecRequest(mode, input, { format = null, lenient = false } = {}) {
    const body = { payload: input, mode };
    if (mode === 'encode') {
        body.format = format;
    } else if (lenient) {
        body.lenient = true;
    }
    return body;
}

// Send `body` and return the server's answer. A refusal is thrown as a
// FailedResponseError (its failure carries the server's message, and the offset
// and path where the input stops being well-formed when the server names them).
export async function requestCodec(body, fetchImpl = fetch) {
    const response = await fetchImpl('/api/codec', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
    });

    if (!response.ok) {
        throw new FailedResponseError(await readFailedResponse(response));
    }

    try {
        return await response.json();
    } catch (parseError) {
        throw new Error('Failed to parse decoder response.');
    }
}

export function codecProgressText(mode) {
    return mode === 'encode' ? 'Encoding…' : 'Decoding…';
}

export function codecSuccessText(mode) {
    return mode === 'encode'
        ? 'Payload encoded successfully!'
        : 'Response decoded successfully!';
}

export function codecFailureText(mode, error) {
    const message = error instanceof Error ? error.message : String(error);
    const failurePrefix = mode === 'encode' ? 'Encoding failed' : 'Decoding failed';
    return `${failurePrefix}: ${message}`;
}

// The whole answer, as the raw view shows it.
export function codecRawJson(payload) {
    return JSON.stringify(payload, null, 2);
}
