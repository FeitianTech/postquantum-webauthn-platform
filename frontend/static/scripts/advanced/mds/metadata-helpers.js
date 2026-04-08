export function normaliseSnapshotInfo(info) {
    if (!info || typeof info !== 'object') {
        return null;
    }

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
    try {
        return JSON.parse(JSON.stringify(entry));
    } catch (error) {
        console.warn('Failed to clone metadata entry.', error);
        return entry;
    }
}

export function normaliseFileList(list) {
    if (!list) {
        return [];
    }
    return Array.from(list).filter(file => file instanceof File);
}

export function splitAcceptedFiles(files) {
    const accepted = [];
    const rejected = [];
    files.forEach(file => {
        if (!file) {
            return;
        }
        const name = typeof file.name === 'string' ? file.name : '';
        if (name.toLowerCase().endsWith('.json')) {
            accepted.push(file);
        } else {
            rejected.push(name || 'Unnamed file');
        }
    });
    return { accepted, rejected };
}
