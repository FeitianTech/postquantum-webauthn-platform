import {
    ensureBase64Url,
    normaliseAdvancedCredentialId,
} from './id-utils.js';

// The algorithm a saved record names: the server writes it twice, and in the COSE key.
function extractAlgorithm(record) {
    const candidates = [
        record.algorithm,
        record.publicKeyAlgorithm,
        record.publicKeyCose && record.publicKeyCose[3],
    ];
    for (const candidate of candidates) {
        if (typeof candidate === 'number' && Number.isFinite(candidate)) {
            return candidate;
        }
    }
    return undefined;
}

// The COSE public key the server wrote (base64url, or standard base64 in an
// earlier release's publicKeyBase64): every saved record holds one of these.
function extractPublicKey(record) {
    const candidates = [
        record.publicKey,
        record.publicKeyBase64,
        record.publicKeyBase64Url,
        record.publicKeyBytes,
    ];
    for (const candidate of candidates) {
        if (typeof candidate === 'string' && candidate.trim()) {
            return ensureBase64Url(candidate);
        }
    }
    return '';
}

export function prepareAdvancedCredentialsForServerFromSource(source) {
    if (!Array.isArray(source) || !source.length) {
        return [];
    }

    const uniqueById = new Map();

    source
        .filter(item => item && typeof item === 'object')
        .forEach(item => {
            const credentialId = ensureBase64Url(normaliseAdvancedCredentialId(item));
            if (!credentialId) {
                return;
            }
            const publicKey = extractPublicKey(item);
            if (!publicKey) {
                return;
            }
            const aaguid = item.aaguid ? ensureBase64Url(String(item.aaguid)) : null;
            const signCount = Number.isFinite(item.signCount) ? Number(item.signCount) : 0;
            const algorithm = extractAlgorithm(item);
            const attachment = item.authenticatorAttachment || item.properties?.authenticatorAttachment;
            const residentSource = item.residentKey ?? item.properties?.residentKey ?? item.relyingParty?.residentKey;
            const resident = typeof residentSource === 'boolean' ? residentSource : Boolean(item.residentKey);

            const prepared = {
                credentialId,
                publicKey,
                aaguid,
                signCount,
                algorithm,
                authenticatorAttachment: attachment || null,
                resident,
            };

            if (!uniqueById.has(credentialId)) {
                uniqueById.set(credentialId, prepared);
            } else {
                const existing = uniqueById.get(credentialId);
                if (prepared.signCount > existing.signCount) {
                    uniqueById.set(credentialId, prepared);
                }
            }
        });

    return Array.from(uniqueById.values());
}
