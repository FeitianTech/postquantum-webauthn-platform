// A payload decoded by the server's decoder (POST /api/codec), as the
// registration view asks for its attestation object and authenticator data.
// DOM-free: both interfaces import it.
import {FailedResponseError, readFailedResponse} from '../../shared/api/failed-response.js';

export async function decodePayloadThroughApi(payload) {
    const trimmed = typeof payload === 'string' ? payload.trim() : '';
    if (!trimmed) {
        throw new Error('Decoder payload must be a non-empty string.');
    }

    const response = await fetch('/api/codec', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ payload: trimmed, mode: 'decode' })
    });

    if (!response.ok) {
        throw new FailedResponseError(await readFailedResponse(response));
    }

    const json = await response.json();
    if (json && typeof json === 'object') {
        if (json.error) {
            throw new Error(json.error);
        }
        if (json.data !== undefined) {
            return json;
        }
    }

    throw new Error('Decoder response did not include data.');
}
