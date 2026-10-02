// What the explorer's status line and count say. No DOM.

/** @import { MdsSnapshot } from './loading.js' */

/** @typedef {{ text: string, variant: 'info' | 'success' | 'error', title: string }} ExplorerStatus */

/**
 * @param {unknown} info
 * @returns {Record<string, unknown> | null}
 */
export function normaliseSnapshotInfo(info) {
    if (!info || typeof info !== 'object') {
        return null;
    }

    /** @type {Record<string, unknown>} */
    const normalised = {};
    for (const [key, value] of Object.entries(info)) {
        if (typeof value === 'string') {
            normalised[key] = value.trim();
        } else {
            normalised[key] = value;
        }
    }
    return normalised;
}

export function extractSnapshotTimestamp(info) {
    if (!info || typeof info !== 'object') {
        return null;
    }

    for (const key of [
        'generatedAt',
        'generated_at',
        'fetchedAt',
        'fetched_at',
        'lastModifiedIso',
        'last_modified_iso',
        'lastModified',
        'last_modified',
    ]) {
        const value = info[key];
        if (typeof value === 'string' && value.trim()) {
            return value.trim();
        }
    }
    return null;
}

export function formatSnapshotTimestamp(info) {
    const raw = extractSnapshotTimestamp(info);
    if (!raw) {
        return null;
    }

    const date = new Date(raw);
    if (Number.isNaN(date.getTime())) {
        return raw;
    }

    return new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'short',
    }).format(date);
}

/**
 * @param {Record<string, any> | null | undefined} info
 * @returns {string}
 */
export function formatInitialExplorerStatus(info) {
    if (!info || typeof info !== 'object') {
        return 'Packaged FIDO metadata is available. Explorer data is loading in the background.';
    }

    const parts = [];
    const entryCount = Number.isFinite(info.entryCount) ? Number(info.entryCount) : null;
    const snapshotNo = Number.isFinite(info.no) ? Number(info.no) : null;
    const lastUpdated = formatSnapshotTimestamp(info);

    if (snapshotNo !== null) {
        parts.push(`Snapshot ${snapshotNo}`);
    }
    if (entryCount !== null) {
        parts.push(`${entryCount.toLocaleString()} authenticators`);
    }
    if (lastUpdated) {
        parts.push(`last updated ${lastUpdated}`);
    }

    if (!parts.length) {
        return 'Packaged FIDO metadata is available. Explorer data is loading in the background.';
    }

    return `${parts.join(' • ')}. Explorer data is loading in the background.`;
}

export const EXPLORER_REFRESHED_NOTE = 'Explorer refreshed.';
export const EXPLORER_NO_MATCHES = 'No authenticators match the selected filters.';

/** @param {boolean} forceReload */
export function explorerLoadingStatus(forceReload) {
    return forceReload ? 'Refreshing authenticator explorer…' : 'Loading authenticator explorer…';
}

export function buildLoadedStatus(snapshot, note, formatTimestamp = formatSnapshotTimestamp) {
    const meta = snapshot?.meta && typeof snapshot.meta === 'object' ? snapshot.meta : {};
    const entryCount = Array.isArray(snapshot?.entries) ? snapshot.entries.length : 0;
    const parts = [`Loaded ${entryCount.toLocaleString()} authenticators.`];

    const lastUpdated = formatTimestamp(meta);
    if (lastUpdated) {
        parts.push(`Last updated ${lastUpdated}.`);
    }

    if (Number.isFinite(meta?.customEntryCount) && meta.customEntryCount > 0) {
        const count = Number(meta.customEntryCount);
        const suffix = count === 1 ? 'entry' : 'entries';
        parts.push(`Including ${count.toLocaleString()} session metadata ${suffix}.`);
    }

    if (note) {
        parts.push(note);
    }

    return parts.join(' ');
}

// The line once a snapshot is shown: its sentence, its variant (success, or info
// when there is nothing to show) and the snapshot's legal header as its title.
/**
 * @param {MdsSnapshot} snapshot
 * @param {string} note
 * @param {number} entryCount
 * @returns {ExplorerStatus}
 */
export function explorerLoadedStatus(snapshot, note, entryCount, buildStatus = buildLoadedStatus) {
    const meta = snapshot?.meta && typeof snapshot.meta === 'object' ? snapshot.meta : {};
    return {
        text: buildStatus(snapshot, note),
        variant: entryCount ? 'success' : 'info',
        title: typeof meta.legalHeader === 'string' ? meta.legalHeader : '',
    };
}

export function formatEntryCount(filtered, total) {
    return {
        count: filtered.toLocaleString(),
        total: total ? `of ${total.toLocaleString()} total` : '',
    };
}
