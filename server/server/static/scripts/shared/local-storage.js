const STORAGE_KEY = 'postquantum-webauthn.simpleCredentials';

function safeParse(json) {
    if (typeof json !== 'string') {
        return [];
    }
    try {
        const parsed = JSON.parse(json);
        if (Array.isArray(parsed)) {
            return parsed.filter(item => item && typeof item === 'object');
        }
    } catch (error) {
        // Ignore parse errors and fall back to empty list.
    }
    return [];
}

function readStoredCredentials() {
    if (typeof window === 'undefined' || !window.localStorage) {
        return [];
    }
    try {
        return safeParse(window.localStorage.getItem(STORAGE_KEY));
    } catch (error) {
        return [];
    }
}

function persistStoredCredentials(records) {
    if (typeof window === 'undefined' || !window.localStorage) {
        return false;
    }
    try {
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify(records));
        return true;
    } catch (error) {
        return false;
    }
}

function normaliseCredentialId(record) {
    if (!record) {
        return '';
    }
    if (typeof record.credentialIdBase64Url === 'string' && record.credentialIdBase64Url) {
        return record.credentialIdBase64Url;
    }
    if (typeof record.credentialId === 'string' && record.credentialId) {
        return record.credentialId;
    }
    if (typeof record.id === 'string' && record.id) {
        return record.id;
    }
    return '';
}

function cloneCredential(record) {
    if (!record || typeof record !== 'object') {
        return null;
    }
    return { ...record };
}

export function getAllSimpleCredentials() {
    return readStoredCredentials().map(cloneCredential).filter(Boolean);
}

export function getSimpleCredentialsForEmail(email) {
    if (!email) {
        return [];
    }
    const normalised = String(email).toLowerCase();
    return getAllSimpleCredentials().filter(cred => {
        const storedEmail = cred.email || cred.userName || cred.username;
        return storedEmail && String(storedEmail).toLowerCase() === normalised;
    });
}

export function saveSimpleCredential(rawCredential) {
    if (!rawCredential || typeof rawCredential !== 'object') {
        return null;
    }

    const credential = {
        type: 'simple',
        ...rawCredential,
    };

    if (!credential.email) {
        credential.email = credential.userName || credential.username || '';
    }

    const credentialId = normaliseCredentialId(credential);
    if (!credentialId) {
        return null;
    }

    credential.credentialIdBase64Url = credentialId;
    if (typeof credential.signCount !== 'number' || !Number.isFinite(credential.signCount)) {
        credential.signCount = 0;
    }

    const stored = readStoredCredentials();
    const filtered = stored.filter(item => normaliseCredentialId(item) !== credentialId);
    filtered.push(credential);
    persistStoredCredentials(filtered);
    return credential;
}

export function removeSimpleCredential(credentialId, email) {
    const id = credentialId ? String(credentialId) : '';
    if (!id) {
        return false;
    }
    const stored = readStoredCredentials();
    const normalisedEmail = email ? String(email).toLowerCase() : null;
    const filtered = stored.filter(record => {
        const recordId = normaliseCredentialId(record);
        if (recordId !== id) {
            return true;
        }
        if (normalisedEmail) {
            const recordEmail = record.email || record.userName || record.username;
            return String(recordEmail || '').toLowerCase() !== normalisedEmail;
        }
        return false;
    });
    const changed = filtered.length !== stored.length;
    if (changed) {
        persistStoredCredentials(filtered);
    }
    return changed;
}

export function clearSimpleCredentials() {
    persistStoredCredentials([]);
}

export function updateSimpleCredentialSignCount(email, credentialId, signCount) {
    const id = credentialId ? String(credentialId) : '';
    if (!id) {
        return false;
    }
    const stored = readStoredCredentials();
    const normalisedEmail = email ? String(email).toLowerCase() : null;
    let updated = false;
    const updatedRecords = stored.map(record => {
        const recordId = normaliseCredentialId(record);
        if (recordId !== id) {
            return record;
        }
        if (normalisedEmail) {
            const recordEmail = record.email || record.userName || record.username;
            if (String(recordEmail || '').toLowerCase() !== normalisedEmail) {
                return record;
            }
        }
        const clone = { ...record };
        if (typeof signCount === 'number' && Number.isFinite(signCount)) {
            clone.signCount = signCount;
        } else if (typeof clone.signCount === 'number' && Number.isFinite(clone.signCount)) {
            clone.signCount += 1;
        } else {
            clone.signCount = 1;
        }
        updated = true;
        return clone;
    });
    if (updated) {
        persistStoredCredentials(updatedRecords);
    }
    return updated;
}

export function prepareCredentialsForServer(credentials) {
    if (!Array.isArray(credentials) || !credentials.length) {
        return [];
    }
    return credentials
        .filter(item => item && typeof item === 'object')
        .map(item => {
            const credentialId = normaliseCredentialId(item);
            const aaguid = item.aaguid || item.aaguidHex || null;
            const publicKey = item.publicKeyBase64Url || item.publicKey || null;
            const algorithm = typeof item.publicKeyAlgorithm === 'number'
                ? item.publicKeyAlgorithm
                : (typeof item.algorithm === 'number' ? item.algorithm : undefined);
            return {
                credentialId,
                aaguid,
                publicKey,
                signCount: Number.isFinite(item.signCount) ? item.signCount : 0,
                algorithm,
            };
        })
        .filter(item => item.credentialId && item.publicKey);
}

export default {
    getAllSimpleCredentials,
    getSimpleCredentialsForEmail,
    saveSimpleCredential,
    removeSimpleCredential,
    clearSimpleCredentials,
    updateSimpleCredentialSignCount,
    prepareCredentialsForServer,
};
