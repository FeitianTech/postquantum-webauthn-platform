const SIMPLE_STORAGE_KEY = 'postquantum-webauthn.simpleCredentials';
const ADVANCED_STORAGE_KEY = 'postquantum-webauthn.advancedCredentials';

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

function readStoredCredentials(storageKey) {
    if (typeof window === 'undefined' || !window.localStorage) {
        return [];
    }
    try {
        return safeParse(window.localStorage.getItem(storageKey));
    } catch (error) {
        return [];
    }
}

function persistStoredCredentials(storageKey, records) {
    if (typeof window === 'undefined' || !window.localStorage) {
        return false;
    }
    try {
        window.localStorage.setItem(storageKey, JSON.stringify(records));
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
    return readStoredCredentials(SIMPLE_STORAGE_KEY).map(cloneCredential).filter(Boolean);
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

    const stored = readStoredCredentials(SIMPLE_STORAGE_KEY);
    const filtered = stored.filter(item => normaliseCredentialId(item) !== credentialId);
    filtered.push(credential);
    persistStoredCredentials(SIMPLE_STORAGE_KEY, filtered);
    return credential;
}

export function removeSimpleCredential(credentialId, email) {
    const id = credentialId ? String(credentialId) : '';
    if (!id) {
        return false;
    }
    const stored = readStoredCredentials(SIMPLE_STORAGE_KEY);
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
        persistStoredCredentials(SIMPLE_STORAGE_KEY, filtered);
    }
    return changed;
}

export function clearSimpleCredentials() {
    persistStoredCredentials(SIMPLE_STORAGE_KEY, []);
}

export function updateSimpleCredentialSignCount(email, credentialId, signCount) {
    const id = credentialId ? String(credentialId) : '';
    if (!id) {
        return false;
    }
    const stored = readStoredCredentials(SIMPLE_STORAGE_KEY);
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
        persistStoredCredentials(SIMPLE_STORAGE_KEY, updatedRecords);
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

function normaliseAdvancedCredentialId(record) {
    if (!record) {
        return '';
    }
    const candidates = [
        record.credentialIdBase64Url,
        record.credentialIdBase64URL,
        record.credentialIdBase64,
        record.credentialId,
        record.id,
    ];
    for (const candidate of candidates) {
        if (typeof candidate === 'string' && candidate.trim()) {
            return candidate.trim();
        }
    }
    return '';
}

function readAdvancedCredentials() {
    return readStoredCredentials(ADVANCED_STORAGE_KEY)
        .map(cloneCredential)
        .filter(Boolean)
        .map(cred => ({ ...cred, type: cred.type || 'advanced' }));
}

function persistAdvancedCredentials(records) {
    return persistStoredCredentials(ADVANCED_STORAGE_KEY, records);
}

function ensureBase64Url(value) {
    if (typeof value !== 'string' || !value.trim()) {
        return '';
    }
    const trimmed = value.trim();
    if (/^[A-Za-z0-9_-]+$/.test(trimmed)) {
        return trimmed;
    }
    try {
        const decoded = atob(trimmed);
        return btoa(decoded).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    } catch (error) {
        try {
            const bytes = new Uint8Array(trimmed.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
            let binary = '';
            bytes.forEach(byte => {
                binary += String.fromCharCode(byte);
            });
            return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
        } catch (innerError) {
            return trimmed;
        }
    }
}

function cloneAdvancedCredential(record) {
    if (!record || typeof record !== 'object') {
        return null;
    }
    const credential = { type: 'advanced', ...record };
    if (!credential.credentialIdBase64Url) {
        credential.credentialIdBase64Url = ensureBase64Url(normaliseAdvancedCredentialId(credential));
    }
    return credential;
}

export function getAllAdvancedCredentials() {
    return readAdvancedCredentials().map(cloneAdvancedCredential).filter(Boolean);
}

export function saveAdvancedCredential(rawCredential) {
    if (!rawCredential || typeof rawCredential !== 'object') {
        return null;
    }

    const credential = cloneAdvancedCredential(rawCredential);
    if (!credential) {
        return null;
    }

    credential.type = 'advanced';

    const credentialId = normaliseAdvancedCredentialId(credential);
    if (!credentialId) {
        return null;
    }

    credential.credentialIdBase64Url = ensureBase64Url(credentialId);

    const stored = readAdvancedCredentials();
    const filtered = stored.filter(item => normaliseAdvancedCredentialId(item) !== credentialId);
    filtered.push(credential);
    persistAdvancedCredentials(filtered);
    return credential;
}

export function removeAdvancedCredential(credentialId) {
    const id = credentialId ? String(credentialId) : '';
    if (!id) {
        return false;
    }
    const stored = readAdvancedCredentials();
    const filtered = stored.filter(record => normaliseAdvancedCredentialId(record) !== id);
    const changed = filtered.length !== stored.length;
    if (changed) {
        persistAdvancedCredentials(filtered);
    }
    return changed;
}

export function clearAdvancedCredentials() {
    persistAdvancedCredentials([]);
}

export function updateAdvancedCredentialSignCount(credentialId, signCount) {
    const id = credentialId ? String(credentialId) : '';
    if (!id) {
        return false;
    }

    const stored = readAdvancedCredentials();
    let updated = false;
    const updatedRecords = stored.map(record => {
        if (normaliseAdvancedCredentialId(record) !== id) {
            return record;
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
        persistAdvancedCredentials(updatedRecords);
    }

    return updated;
}

function extractAlgorithm(record) {
    const candidates = [
        record.algorithm,
        record.publicKeyAlgorithm,
        record.coseAlgorithm,
        record.publicKeyCose && record.publicKeyCose[3],
    ];
    for (const candidate of candidates) {
        if (typeof candidate === 'number' && Number.isFinite(candidate)) {
            return candidate;
        }
    }
    return undefined;
}

function extractPublicKey(record) {
    const candidates = [
        record.publicKeyBytes,
        record.publicKeyBase64Url,
        record.publicKeyBase64,
        record.publicKey,
    ];
    for (const candidate of candidates) {
        if (typeof candidate === 'string' && candidate.trim()) {
            return ensureBase64Url(candidate);
        }
    }
    if (record.publicKeyCose && typeof record.publicKeyCose === 'object') {
        try {
            const json = JSON.stringify(record.publicKeyCose);
            return ensureBase64Url(btoa(json));
        } catch (error) {
            return '';
        }
    }
    return '';
}

export function prepareAdvancedCredentialsForServer(credentials = null) {
    const source = Array.isArray(credentials) ? credentials : getAllAdvancedCredentials();
    if (!source.length) {
        return [];
    }
    return source
        .filter(item => item && typeof item === 'object')
        .map(item => {
            const credentialId = ensureBase64Url(normaliseAdvancedCredentialId(item));
            const publicKey = extractPublicKey(item);
            const aaguidCandidate = item.aaguidBase64Url || item.aaguid || item.aaguidHex;
            const aaguid = aaguidCandidate ? ensureBase64Url(String(aaguidCandidate)) : null;
            const signCount = Number.isFinite(item.signCount) ? Number(item.signCount) : 0;
            const algorithm = extractAlgorithm(item);
            const attachment = item.authenticatorAttachment || item.attachment || item.properties?.authenticatorAttachment;
            const residentSource = (
                item.resident ?? item.residentKey ?? item.discoverable ?? item.properties?.residentKey ??
                item.relyingParty?.residentKey
            );
            const resident = typeof residentSource === 'boolean' ? residentSource : Boolean(item.residentKey);

            return {
                credentialId,
                publicKey,
                aaguid,
                signCount,
                algorithm,
                authenticatorAttachment: attachment || null,
                resident,
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
    getAllAdvancedCredentials,
    saveAdvancedCredential,
    removeAdvancedCredential,
    clearAdvancedCredentials,
    updateAdvancedCredentialSignCount,
    prepareAdvancedCredentialsForServer,
};
