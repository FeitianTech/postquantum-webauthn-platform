const ARTIFACT_ENDPOINT_BASE = '/api/advanced/credential-artifacts';

function normaliseStorageId(storageId) {
    if (typeof storageId !== 'string') {
        return '';
    }
    const trimmed = storageId.trim();
    return trimmed ? trimmed : '';
}

async function jsonFetch(url, options = {}) {
    const response = await fetch(url, {
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        ...options,
    });

    if (!response.ok) {
        const text = await response.text();
        const error = new Error(text || `Request failed with status ${response.status}`);
        error.status = response.status;
        throw error;
    }

    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
        return null;
    }

    return response.json();
}

export async function fetchCredentialArtifact(storageId) {
    const normalised = normaliseStorageId(storageId);
    if (!normalised) {
        return null;
    }

    try {
        const result = await jsonFetch(`${ARTIFACT_ENDPOINT_BASE}/${encodeURIComponent(normalised)}`);
        if (result && typeof result === 'object' && result.artifact && typeof result.artifact === 'object') {
            return result.artifact;
        }
    } catch (error) {
        if (error && typeof error === 'object' && Number(error.status) === 404) {
            return null;
        }
        throw error;
    }

    return null;
}

export async function fetchCredentialArtifactsBulk(storageIds) {
    const normalizedIds = Array.isArray(storageIds)
        ? storageIds
            .map(normaliseStorageId)
            .filter(Boolean)
        : [];
    if (!normalizedIds.length) {
        return {};
    }

    try {
        const result = await jsonFetch(`${ARTIFACT_ENDPOINT_BASE}/bulk`, {
            method: 'POST',
            body: JSON.stringify({ storageIds: normalizedIds }),
        });
        if (result && typeof result === 'object' && result.artifacts && typeof result.artifacts === 'object') {
            return result.artifacts;
        }
    } catch (error) {
        console.warn('Failed to fetch credential artifacts in bulk', error);
    }

    return {};
}

export async function uploadCredentialArtifact(storageId, artifact, { merge = true } = {}) {
    const normalised = normaliseStorageId(storageId);
    if (!normalised || !artifact || typeof artifact !== 'object') {
        return false;
    }

    try {
        await jsonFetch(`${ARTIFACT_ENDPOINT_BASE}/${encodeURIComponent(normalised)}`, {
            method: 'PUT',
            body: JSON.stringify({ artifact, merge }),
        });
        return true;
    } catch (error) {
        console.warn('Failed to upload credential artifact', error);
        return false;
    }
}

export async function updateCredentialSnapshot(storageId, snapshot) {
    const normalised = normaliseStorageId(storageId);
    if (!normalised || (snapshot && typeof snapshot !== 'object')) {
        return false;
    }

    try {
        await jsonFetch(`${ARTIFACT_ENDPOINT_BASE}/${encodeURIComponent(normalised)}/snapshot`, {
            method: 'PUT',
            body: JSON.stringify({ snapshot }),
        });
        return true;
    } catch (error) {
        console.warn('Failed to update credential snapshot', error);
        return false;
    }
}

export async function deleteCredentialArtifact(storageId) {
    const normalised = normaliseStorageId(storageId);
    if (!normalised) {
        return false;
    }

    try {
        await jsonFetch(`${ARTIFACT_ENDPOINT_BASE}/${encodeURIComponent(normalised)}`, {
            method: 'DELETE',
        });
        return true;
    } catch (error) {
        console.warn('Failed to delete credential artifact', error);
        return false;
    }
}
