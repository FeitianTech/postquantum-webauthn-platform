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
        return {
            ok: false,
            status: 'failed',
            httpStatus: null,
            error: 'Invalid storage identifier.',
        };
    }

    try {
        const response = await fetch(`${ARTIFACT_ENDPOINT_BASE}/${encodeURIComponent(normalised)}`, {
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
            try {
                const text = await response.text();
                if (typeof text === 'string' && text.trim()) {
                    payload = { error: text.trim() };
                }
            } catch (error) {
                payload = null;
            }
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
        console.warn('Failed to delete credential artifact', error);
        return {
            ok: false,
            status: 'failed',
            httpStatus: null,
            error: error instanceof Error ? error.message : 'Delete request failed.',
        };
    }
}
