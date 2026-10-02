// Manage Trusted Metadata's requests and everything it says. No DOM.
import { CUSTOM_METADATA_DELETE_PATH, CUSTOM_METADATA_LIST_PATH, CUSTOM_METADATA_UPLOAD_PATH } from '../constants.js';

/** @import { MdsSnapshot } from './loading.js' */

/**
 * What the panel says, and how.
 * @typedef {'info' | 'success' | 'warning' | 'error'} MessageVariant
 * @typedef {{ text: string, variant: MessageVariant }} PanelMessage
 */

/**
 * An uploaded file as the list shows it.
 * @typedef {{ name: string, storedFilename: string, deleteLabel: string, details: string }} CustomItem
 */

/**
 * A request's response, and its JSON (null when it was not JSON).
 * @typedef {{ response: Response, payload: any }} CustomMetadataAnswer
 */

/**
 * @param {File[]} files
 * @returns {{ accepted: File[], rejected: string[] }}
 */
export function splitAcceptedFiles(files) {
    /** @type {File[]} */
    const accepted = [];
    /** @type {string[]} */
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

export const CUSTOM_METADATA_UPDATED_NOTE = 'Custom metadata updated.';
export const METADATA_UPDATE_CANCELLED = 'Metadata update cancelled.';
export const NO_CUSTOM_METADATA = 'No custom metadata has been added yet.';
export const CHOOSE_METADATA_FILES = 'Please choose one or more JSON files.';
export const UPLOADING_METADATA = 'Uploading metadata…';
export const UPLOAD_METADATA_FAILED = 'Failed to upload metadata files.';
export const DELETE_METADATA_FAILED = 'Failed to delete metadata file.';

// What the page says while an upload runs, in order, and how it ends.
export const UPLOAD_PROGRESS = {
    start: 'Updating Metadata...',
    uploading: UPLOADING_METADATA,
    applying: 'Applying metadata…',
    reloading: 'Reloading metadata…',
    success: 'Completing metadata update...',
    cancel: METADATA_UPDATE_CANCELLED,
    failure: 'Metadata update failed.',
};

// The same for a delete.
export const DELETE_PROGRESS = {
    start: 'Removing metadata...',
    removing: 'Removing metadata…',
    applying: 'Applying metadata…',
    refreshing: 'Refreshing metadata…',
    unchanged: 'No metadata changes detected.',
    success: 'Completing metadata removal...',
    cancel: 'Metadata removal cancelled.',
    failure: 'Metadata removal failed.',
};

// Which chosen files are sent (the `.json` ones), and what to say first: the
// names refused, or that there was nothing to send.
/**
 * @param {File[]} files
 * @returns {{ accepted: File[], message: PanelMessage | null }}
 */
export function describeFileSelection(files) {
    const { accepted, rejected } = splitAcceptedFiles(files);
    /** @type {PanelMessage | null} */
    let message = null;
    if (rejected.length) {
        message = { text: `Ignored non-JSON files: ${rejected.join(', ')}`, variant: 'warning' };
    } else if (!accepted.length) {
        message = { text: 'Please select one or more JSON files.', variant: 'warning' };
    }
    return { accepted, message };
}

export function buildCustomMetadataForm(files) {
    const formData = new FormData();
    files.forEach(file => {
        const name = typeof file.name === 'string' && file.name ? file.name : 'metadata.json';
        formData.append('files', file, name);
    });
    return formData;
}

async function readCustomMetadataAnswer(response) {
    try {
        return await response.json();
    } catch {
        return null;
    }
}

/**
 * @param {File[]} files
 * @param {{ signal?: AbortSignal, path?: string }} [options]
 * @returns {Promise<CustomMetadataAnswer>}
 */
export async function requestCustomMetadataUpload(files, { signal, path = CUSTOM_METADATA_UPLOAD_PATH } = {}) {
    const response = await fetch(path, {
        method: 'POST',
        body: buildCustomMetadataForm(files),
        signal,
    });
    return { response, payload: await readCustomMetadataAnswer(response) };
}

function trimmedText(value) {
    return typeof value === 'string' && value.trim() ? value.trim() : '';
}

// An upload's answer: what the panel says (the server's warnings too), and the
// snapshot to show when the server sends one.
/**
 * @param {Response} response
 * @param {any} payload
 * @returns {{ ok: boolean, message: string, variant: MessageVariant, snapshot?: MdsSnapshot | null }}
 */
export function describeUploadAnswer(response, payload) {
    const errors = Array.isArray(payload?.errors) ? payload.errors : [];
    if (!response.ok) {
        return {
            ok: false,
            message: trimmedText(payload?.error) || errors.join(' ') || UPLOAD_METADATA_FAILED,
            variant: 'error',
        };
    }
    return {
        ok: true,
        message: errors.length > 0
            ? `Metadata uploaded with warnings: ${errors.join(' ')}`
            : 'Metadata uploaded successfully.',
        variant: errors.length ? 'warning' : 'success',
        snapshot: payload?.snapshot && typeof payload.snapshot === 'object' ? payload.snapshot : null,
    };
}

/**
 * @param {unknown} itemName
 * @returns {string}
 */
export function customMetadataItemLabel(itemName) {
    return trimmedText(itemName) || 'metadata file';
}

/** @param {string} itemName */
export function removingCustomMetadataMessage(itemName) {
    return `Removing ${itemName}…`;
}

/** @param {string} itemName */
export function removedCustomMetadataMessage(itemName) {
    return `${itemName} removed.`;
}

/**
 * @param {string} storedFilename
 * @param {{ signal?: AbortSignal, path?: string }} [options]
 * @returns {Promise<CustomMetadataAnswer>}
 */
export async function requestCustomMetadataDelete(
    storedFilename,
    { signal, path = CUSTOM_METADATA_DELETE_PATH } = {},
) {
    const response = await fetch(`${path}/${encodeURIComponent(storedFilename)}`, {
        method: 'DELETE',
        signal,
    });
    return { response, payload: await readCustomMetadataAnswer(response) };
}

// A delete's answer: a 404 (already gone) is a warning, other failures errors.
/**
 * @param {Response} response
 * @param {any} payload
 * @returns {{ ok: boolean, message?: string, variant?: MessageVariant, snapshot?: MdsSnapshot | null }}
 */
export function describeDeleteAnswer(response, payload) {
    if (!response.ok) {
        return {
            ok: false,
            message: trimmedText(payload?.error) || trimmedText(payload?.message) || DELETE_METADATA_FAILED,
            variant: response.status === 404 ? 'warning' : 'error',
        };
    }
    return {
        ok: true,
        snapshot: payload?.snapshot && typeof payload.snapshot === 'object' ? payload.snapshot : null,
    };
}

// One uploaded file as the list shows it: its name, the stored name a delete
// needs, what the Delete button is called, and "Uploaded … · Includes legal header".
/**
 * @param {any} item
 * @returns {CustomItem}
 */
export function describeCustomMetadataItem(item) {
    const storedFilename =
        (item?.source?.storedFilename && String(item.source.storedFilename).trim()) || '';
    const name =
        (item?.source?.originalFilename && String(item.source.originalFilename).trim())
        || storedFilename
        || 'metadata.json';

    const details = [];
    const uploadedAtRaw = item?.source?.uploadedAt;
    if (typeof uploadedAtRaw === 'string' && uploadedAtRaw) {
        const parsed = new Date(uploadedAtRaw);
        if (!Number.isNaN(parsed.getTime())) {
            details.push(`Uploaded ${parsed.toLocaleString()}`);
        }
    }
    if (item?.legalHeader) {
        details.push('Includes legal header');
    }

    return { name, storedFilename, deleteLabel: `Delete ${name}`, details: details.join(' · ') };
}

// The files uploaded in this session (GET /api/mds/metadata/custom), newest first.
/**
 * @param {{ signal?: AbortSignal, path?: string }} [options]
 * @returns {Promise<unknown[]>}
 */
export async function requestCustomMetadataList({ signal, path = CUSTOM_METADATA_LIST_PATH } = {}) {
    const response = await fetch(path, { cache: 'no-store', signal });
    const payload = await readCustomMetadataAnswer(response);
    return response.ok && Array.isArray(payload?.items) ? payload.items : [];
}
