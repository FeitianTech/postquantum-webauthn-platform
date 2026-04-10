import {
    ensureBase64Url,
    normaliseAdvancedCredentialId,
} from './id-utils.js';

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
    if (!record || typeof record !== 'object') {
        return '';
    }

    const preferredCandidates = [
        record.publicKey,
        record.publicKeyBase64,
        record.publicKeyBase64Url,
        record.publicKeyCbor,
    ];
    for (const candidate of preferredCandidates) {
        if (typeof candidate === 'string' && candidate.trim()) {
            return ensureBase64Url(candidate);
        }
    }

    const secondaryCandidates = [
        record.publicKeyBytes,
    ];
    for (const candidate of secondaryCandidates) {
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
