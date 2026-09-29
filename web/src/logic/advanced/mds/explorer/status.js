// What the explorer's status line and count say, for both UIs: the legacy tab
// (metadata/explorer-load.js, runtime/runtime-refresh-metadata.js,
// status-controls.js) and web's MDS section. No DOM.
import { formatSnapshotTimestamp } from '../metadata/metadata-helpers.js';


export const EXPLORER_REFRESHED_NOTE = 'Explorer refreshed.';
export const EXPLORER_NO_MATCHES = 'No authenticators match the selected filters.';

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
