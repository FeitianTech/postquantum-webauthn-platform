// A DELETE of something the server keeps for the visitor (a credential's artifact,
// a Simple credential's record), and what its answer says: deleted, absent, or
// failed with the reason. DOM-free.

import { readFailedResponse } from '../../shared/failed-response.js';

/**
 * What a deletion's answer said.
 * @typedef {{ ok: boolean, status: 'deleted' | 'absent' | 'failed', httpStatus: number | null, error?: string }} DeletionAnswer
 */

/**
 * @param {string} url
 * @returns {Promise<DeletionAnswer>}
 */
export async function requestDeletion(url) {
    try {
        const response = await fetch(url, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
        });

        const contentType = response.headers.get('content-type') || '';
        let payload = null;

        if (contentType.includes('application/json')) {
            try {
                payload = await response.json();
            } catch (error) {
                payload = null;
            }
        } else {
            // Not JSON (a proxy's page): said by its status, never shown as it came.
            payload = { error: (await readFailedResponse(response)).message };
        }

        const status = typeof payload?.status === 'string'
            ? payload.status.trim().toLowerCase()
            : 'failed';

        if (response.ok && status === 'deleted') {
            return {
                ok: true,
                status: 'deleted',
                httpStatus: response.status,
            };
        }

        if (status === 'absent') {
            return {
                ok: false,
                status: 'absent',
                httpStatus: response.status,
            };
        }

        const errorMessage = typeof payload?.error === 'string' && payload.error.trim()
            ? payload.error.trim()
            : `Request failed with status ${response.status}`;

        return {
            ok: false,
            status: 'failed',
            httpStatus: response.status,
            error: errorMessage,
        };
    } catch (error) {
        return {
            ok: false,
            status: 'failed',
            httpStatus: null,
            error: error instanceof Error ? error.message : 'Delete request failed.',
        };
    }
}
