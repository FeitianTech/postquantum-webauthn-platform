// How an explorer entry is found when the list does not hold it, and how another
// surface (a saved credential) opens one by its AAGUID. No DOM.
import { readFailedResponse } from '../../shared/failed-response.js';
import { MDS_RESOLVE_PATH } from '../constants.js';
import { aaguidGuid } from '../../shared/aaguid.js';
import { isAbortError } from './loading.js';

/** @import { MdsEntry } from './loading.js' */

// What the jump from a saved credential says while and after it looks.
export const ENTRY_LINK_MESSAGES = Object.freeze({
    locating: 'Locating metadata entry...',
    opening: 'Opening authenticator metadata...',
    notLocated: 'Unable to locate metadata entry.',
    failed: 'Unable to open authenticator metadata.',
    unavailable: 'Authenticator metadata entry unavailable.',
    notFound: 'Authenticator metadata not found.',
});

// The entry id of an AAGUID's entry (`aaguid:` and the AAGUID dashed, lower
// case), which is also its URL in web (#mds/aaguid:…); '' when it is no AAGUID.
/**
 * @param {unknown} aaguid
 * @returns {string}
 */
export function entryIdForAaguid(aaguid) {
    const normalised = aaguidGuid(aaguid);
    return normalised ? `aaguid:${normalised}` : '';
}

// What GET /api/mds/metadata/resolve is asked for an entry: its entry id, else
// its AAGUID, else its id as an AAID.
/**
 * @param {Record<string, any> | null | undefined} entry
 * @returns {Record<string, string>}
 */
export function resolveQueryForEntry(entry) {
    if (typeof entry?.entryId === 'string' && entry.entryId) {
        return { entryId: entry.entryId };
    }
    if (typeof entry?.aaguid === 'string' && entry.aaguid) {
        return { aaguid: aaguidGuid(entry.aaguid) };
    }
    if (typeof entry?.id === 'string' && entry.id) {
        return { aaid: entry.id };
    }
    return {};
}

// GET /api/mds/metadata/resolve. `{ entry }` for an answer (null when there is
// nothing to ask or the answer holds no entry), `{ entry: null, failure }` for a
// refusal, with its status and the server's sentence ("Metadata entry not
// found." for a 404). A body that is not JSON throws.
/**
 * @param {Record<string, unknown> | null | undefined} query
 * @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<{ entry: MdsEntry | null, failure?: { status: number, message: string } }>}
 */
export async function requestResolvedEntry(query, { signal } = {}) {
    const params = new URLSearchParams();
    Object.entries(query || {}).forEach(([key, value]) => {
        if (typeof value === 'string' && value) {
            params.set(key, value);
        }
    });
    if (!params.toString()) {
        return { entry: null };
    }

    /** @type {RequestInit} */
    const init = signal ? { cache: 'no-store', signal } : { cache: 'no-store' };
    const response = await fetch(`${MDS_RESOLVE_PATH}?${params.toString()}`, init);
    if (!response.ok) {
        const failure = await readFailedResponse(response);
        return { entry: null, failure: { status: failure.status, message: failure.text } };
    }

    const payload = await response.json();
    const entry = payload?.entry;
    return { entry: entry && typeof entry === 'object' ? entry : null };
}

// An entry's detail: the file its list row names (`detailUrl`), cached as the
// browser keeps it and fetched without the session's cookie; else (no such row,
// or the file is missing or unreadable) GET /api/mds/metadata/resolve, by what
// the row holds or by the entry id. An abort is never swallowed.
/**
 * @param {Record<string, any> | null | undefined} listed
 * @param {string} entryId
 * @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<{ entry: MdsEntry | null, failure?: { status: number, message: string } }>}
 */
export async function requestEntryDetail(listed, entryId, { signal } = {}) {
    const url = typeof listed?.detailUrl === 'string' ? listed.detailUrl : '';
    if (url) {
        try {
            /** @type {RequestInit} */
            const init = signal ? { credentials: 'omit', signal } : { credentials: 'omit' };
            const response = await fetch(url, init);
            const entry = response.ok ? await response.json() : null;
            if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
                return { entry };
            }
        } catch (error) {
            if (isAbortError(error)) {
                throw error;
            }
        }
    }
    return requestResolvedEntry(listed ? resolveQueryForEntry(listed) : { entryId }, { signal });
}

