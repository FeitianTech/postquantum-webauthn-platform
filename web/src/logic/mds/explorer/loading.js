// Where the explorer's entries come from and what an answer means. No DOM.
import { MDS_EXPLORER_FULL_PATH, MDS_INFO_PATH, MISSING_METADATA_MESSAGE } from '../constants.js';

/** @import { ExplorerSource, SnapshotLocation } from '../explorer-source.js' */

/**
 * One authenticator as the server lists it (mds/build.py's build_explorer_entry):
 * every column's text is already there.
 * @typedef {{
 *     entryId: string,
 *     index?: number,
 *     name: string,
 *     icon?: string | null,
 *     protocol: string,
 *     certification: string,
 *     certificationStatus: string,
 *     id: string,
 *     aaguid?: string,
 *     userVerification: string,
 *     userVerificationList: string[],
 *     attachment: string,
 *     attachmentList: string[],
 *     transports: string,
 *     transportsList: string[],
 *     keyProtection: string,
 *     keyProtectionList: string[],
 *     algorithms: string,
 *     algorithmsList: string[],
 *     algorithmInfo: string,
 *     certificateAlgorithmInfoList: string[],
 *     commonName: string,
 *     certificateCommonNameList: string[],
 *     dateUpdated: string,
 *     dateTooltip?: string,
 *     source?: string,
 *     [key: string]: unknown,
 * }} MdsEntry
 */

/** @typedef {{ meta?: { [key: string]: unknown }, entries: MdsEntry[] }} MdsSnapshot */

/**
 * What GET /api/mds/metadata/info answers: the packaged summary, snapshotUrl and customEntriesState.
 * @typedef {{ [key: string]: unknown }} MdsInfo
 */

/**
 * A snapshot request's response, and its JSON (null when it was not JSON).
 * @typedef {{ response: Response, payload: any }} ExplorerAnswer
 * @typedef {(
 *     | { kind: 'missing', message: string }
 *     | { kind: 'failed', message: string }
 *     | { kind: 'snapshot', payload: MdsSnapshot }
 * )} ExplorerOutcome
 */

/** @param {any} error */
export function isAbortError(error) {
    return Boolean(error && error.name === 'AbortError');
}

/** @param {Record<string, any> | null | undefined} entry */
export function hasInlineDetail(entry) {
    return Boolean(
        entry
        && typeof entry === 'object'
        && entry.isLightweightEntry !== true
        && entry.metadataStatement
        && typeof entry.metadataStatement === 'object',
    );
}

export function cloneMetadataEntry(entry) {
    if (!entry || typeof entry !== 'object') {
        return null;
    }
    return structuredClone(entry);
}

/**
 * @param {SnapshotLocation} source
 * @param {AbortSignal | null} signal
 * @returns {Promise<ExplorerAnswer>}
 */
async function fetchExplorerAnswer(source, signal) {
    /** @type {RequestInit} */
    const fetchOptions = {
        cache: source.cache,
    };
    // The packaged list is the same for everyone: it is fetched without the
    // session's cookie, so its answer can never put back an older session.
    if (source.kind === 'static') {
        fetchOptions.credentials = 'omit';
    }
    if (signal) {
        fetchOptions.signal = signal;
    }

    const response = await fetch(source.url, fetchOptions);
    let payload = null;
    try {
        payload = await response.json();
    } catch {
        payload = null;
    }
    return { response, payload };
}

// Asks the source the explorer source chooses (../explorer-source.js). The
// packaged file is an optimisation: any problem loading it falls back to the
// per-session API. An abort is never swallowed.
/**
 * @param {ExplorerSource | null} explorerSource
 * @param {{ forceReload?: boolean, signal?: AbortSignal | null, apiPath?: string }} [options]
 * @returns {Promise<ExplorerAnswer>}
 */
export async function requestExplorerSnapshot(
    explorerSource,
    { forceReload = false, signal = null, apiPath = MDS_EXPLORER_FULL_PATH } = {},
) {
    if (!explorerSource || typeof explorerSource.resolve !== 'function') {
        return fetchExplorerAnswer({ url: apiPath, cache: forceReload ? 'reload' : 'no-store', kind: 'api' }, signal);
    }
    const primarySource = explorerSource.resolve({ forceReload });

    if (primarySource.kind !== 'static') {
        return fetchExplorerAnswer(primarySource, signal);
    }

    let result = null;
    try {
        result = await fetchExplorerAnswer(primarySource, signal);
        if (!result.response.ok || !result.payload || typeof result.payload !== 'object') {
            result = null;
        }
    } catch (error) {
        if (isAbortError(error)) {
            throw error;
        }
        result = null;
    }
    return result || fetchExplorerAnswer(explorerSource.fallback({ forceReload }), signal);
}

function answerError(payload) {
    return payload && typeof payload.error === 'string' && payload.error ? payload.error : '';
}

// What an answer is: `missing` (a 404: no snapshot), `failed` (with the sentence
// the status line shows) or `snapshot`.
/**
 * @param {ExplorerAnswer} answer
 * @param {string} [missingMessage]
 * @returns {ExplorerOutcome}
 */
export function classifyExplorerAnswer({ response, payload }, missingMessage = MISSING_METADATA_MESSAGE) {
    if (!response.ok) {
        if (response.status === 404) {
            return { kind: 'missing', message: answerError(payload) || missingMessage };
        }
        return {
            kind: 'failed',
            message: answerError(payload) || `Explorer request failed with status ${response.status}.`,
        };
    }
    if (!payload || typeof payload !== 'object') {
        return { kind: 'failed', message: 'Explorer response was not valid JSON.' };
    }
    return { kind: 'snapshot', payload };
}

/**
 * @param {unknown} error
 * @returns {string}
 */
export function explorerLoadFailure(error) {
    return error instanceof Error && error.message
        ? error.message
        : 'Unable to load the packaged authenticator explorer.';
}

// A snapshot's entries as the table shows them: copies, entries with their
// detail inline marked so, and any entry already resolved in full kept whole.
/**
 * @param {MdsSnapshot | null | undefined} snapshot
 * @param {Map<string, Record<string, unknown>>} [resolvedEntryCache]
 * @returns {MdsEntry[]}
 */
export function prepareSnapshotEntries(snapshot, resolvedEntryCache = new Map()) {
    const incomingEntries = Array.isArray(snapshot?.entries) ? snapshot.entries : [];
    return incomingEntries
        .map(entry => cloneMetadataEntry(entry))
        .filter(entry => entry && typeof entry === 'object')
        .map(entry => {
            if (hasInlineDetail(entry)) {
                entry.isLightweightEntry = false;
            }
            const cached = entry.entryId ? resolvedEntryCache.get(entry.entryId) : null;
            return cached && typeof cached === 'object' ? { ...entry, ...cached } : entry;
        });
}

// What the page starts from (GET /api/mds/metadata/info: the packaged summary,
// `snapshotUrl` and `customEntriesState`). Null when it cannot be had: the
// explorer then asks the API.
/**
 * @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<MdsInfo | null>}
 */
export async function fetchExplorerInfo({ signal } = {}) {
    try {
        const response = await fetch(MDS_INFO_PATH, { cache: 'no-store', signal });
        if (!response.ok) {
            return null;
        }
        const payload = await response.json();
        return payload && typeof payload === 'object' && !Array.isArray(payload) ? payload : null;
    } catch (error) {
        if (isAbortError(error)) {
            throw error;
        }
        return null;
    }
}

// No entry at all: the server has no snapshot (it answers 200 with nothing in
// it) and no metadata was uploaded.
/**
 * @param {MdsSnapshot | null | undefined} snapshot
 * @returns {boolean}
 */
export function isMissingSnapshot(snapshot) {
    return !Array.isArray(snapshot?.entries) || snapshot.entries.length === 0;
}
