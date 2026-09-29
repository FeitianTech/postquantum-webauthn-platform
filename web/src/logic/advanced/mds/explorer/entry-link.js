// How an explorer entry is found when the list does not hold it, and how another
// surface (a saved credential) opens one by its AAGUID. No DOM.
import { readFailedResponse } from '../../../shared/api/failed-response.js';
import { MDS_RESOLVE_PATH } from '../constants.js';
import { normaliseAaguid } from '../utils/resolvers.js';

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
export function entryIdForAaguid(aaguid) {
    const normalised = normaliseAaguid(aaguid);
    return normalised ? `aaguid:${normalised}` : '';
}

// What GET /api/mds/metadata/resolve is asked for an entry: its entry id, else
// its AAGUID, else its id as an AAID.
export function resolveQueryForEntry(entry) {
    if (typeof entry?.entryId === 'string' && entry.entryId) {
        return { entryId: entry.entryId };
    }
    if (typeof entry?.aaguid === 'string' && entry.aaguid) {
        return { aaguid: normaliseAaguid(entry.aaguid) };
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
