// Where the explorer's entries come from and what an answer means. No DOM.
import { cloneJson } from '../../shared/json.js';
import { MDS_INFO_PATH, MDS_LIST_PATH } from '../constants.js';

/** @import { SnapshotLocation } from '../explorer-source.js' */

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
 *     latestStatus: string,
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
 * What GET /api/mds/metadata/info answers: the packaged summary and customEntriesState.
 * @typedef {{ [key: string]: unknown }} MdsInfo
 */

/**
 * A snapshot request's response, and its JSON (null when it was not JSON).
 * @typedef {{ response: Response, payload: any }} ExplorerAnswer
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

/**
 * @param {SnapshotLocation} source
 * @param {AbortSignal | null} signal
 * @param {RequestPriority} [priority]
 * @returns {Promise<ExplorerAnswer>}
 */
async function fetchExplorerAnswer(source, signal, priority) {
    /** @type {RequestInit} */
    const fetchOptions = {
        cache: source.cache,
    };
    if (priority) {
        fetchOptions.priority = priority;
    }
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

// The packaged list as fetched for this page, by URL: ahead of the explorer
// (not yet taken), or by it (taken; shared while it is still out). An answer
// that is not a list is forgotten.
/** @type {Map<string, { answer: Promise<ExplorerAnswer>, taken: boolean, settled: boolean }>} */
const lists = new Map();

/**
 * @param {string} url
 * @param {Promise<ExplorerAnswer>} answer
 * @param {boolean} taken
 */
function remember(url, answer, taken) {
    const held = { answer, taken, settled: false };
    lists.set(url, held);
    const forget = () => {
        if (lists.get(url) === held) {
            lists.delete(url);
        }
    };
    answer.then(
        ({ response }) => {
            held.settled = true;
            if (!response.ok) {
                forget();
            }
        },
        forget,
    );
}

// Fetches the packaged list ahead, once, so the explorer shows it as soon as it
// is opened: the page asks once its first view is interactive (at low priority)
// and at once when the URL opens #mds. The explorer's first load from that URL
// takes the answer; a list this page has already fetched is not fetched ahead.
/**
 * @param {string} [url]
 * @param {{ priority?: RequestPriority }} [options]
 */
export function prefetchExplorerList(url = MDS_LIST_PATH, { priority } = {}) {
    if (!lists.has(url)) {
        remember(url, fetchExplorerAnswer({ url, cache: 'default', kind: 'static' }, null, priority), false);
    }
}

/** Forgets the lists fetched (each test's page starts afresh). */
export function forgetExplorerList() {
    lists.clear();
}

// A location's answer: the packaged list as this page fetched it (the answer
// fetched ahead, taken once, or one still out, shared), else fetched now; the
// session's part always fetched now. An abort is never swallowed.
/**
 * @param {SnapshotLocation} location
 * @param {AbortSignal | null} [signal]
 * @returns {Promise<ExplorerAnswer>}
 */
export function requestExplorerAnswer(location, signal = null) {
    if (location.kind !== 'static') {
        return fetchExplorerAnswer(location, signal);
    }
    const held = lists.get(location.url);
    if (held && (!held.taken || !held.settled)) {
        held.taken = true;
        return held.answer;
    }
    const answer = fetchExplorerAnswer(location, signal);
    remember(location.url, answer, true);
    return answer;
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
        .map(entry => cloneJson(entry))
        .filter(entry => entry && typeof entry === 'object')
        .map(entry => {
            if (hasInlineDetail(entry)) {
                entry.isLightweightEntry = false;
            }
            const cached = entry.entryId ? resolvedEntryCache.get(entry.entryId) : null;
            return cached && typeof cached === 'object' ? { ...entry, ...cached } : entry;
        });
}

// What the page starts from (GET /api/mds/metadata/info: the packaged summary
// and `customEntriesState`). Null when it cannot be had: the explorer then asks
// for the session's own rows as well as the list.
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
