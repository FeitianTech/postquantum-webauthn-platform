import {base64ToHex} from '../../shared/utils/binary.js';
import {normaliseAaguidValue} from '../credential-utils.js';

const AAGUID_EXTENSION_OID = '1.3.6.1.4.1.45724.1.1.4';

export function collectCredentialCertificates(cred) {
    if (!cred || typeof cred !== 'object') {
        return [];
    }

    const sources = [
        cred.attestationCertificate,
        cred.attestationCertificates,
        cred.attestation_certificate,
        cred.attestation_certificates,
        cred.attestationCertificatesDetails,
        cred.attestation_certificates_details,
        cred.properties?.attestationCertificate,
        cred.properties?.attestationCertificates,
        cred.properties?.attestation_certificate,
        cred.properties?.attestation_certificates,
        cred.relyingParty?.attestationCertificate,
        cred.relyingParty?.attestationCertificates,
        cred.relyingParty?.attestation_certificate,
        cred.relyingParty?.attestation_certificates,
    ];

    const collected = [];
    sources.forEach(source => {
        if (!source) {
            return;
        }
        if (Array.isArray(source)) {
            source.forEach(item => {
                if (item) {
                    collected.push(item);
                }
            });
        } else {
            collected.push(source);
        }
    });
    return collected;
}

export function normaliseHexFingerprint(value) {
    if (typeof value !== 'string') {
        return '';
    }
    const trimmed = value.replace(/[^0-9a-fA-F]/g, '');
    return trimmed ? trimmed.toLowerCase() : '';
}

export function normalisePemString(value) {
    if (typeof value !== 'string') {
        return '';
    }
    const stripped = value
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s+/g, '');
    return stripped.trim();
}

export function deriveCertificateIdentity(entry) {
    if (!entry || typeof entry !== 'object') {
        return '';
    }

    const pickHexValue = candidate => {
        if (typeof candidate !== 'string') {
            return '';
        }
        const trimmed = candidate.replace(/\s+/g, '').toLowerCase();
        return trimmed ? trimmed : '';
    };

    const pickBase64Value = candidate => {
        if (typeof candidate !== 'string') {
            return '';
        }
        const stripped = candidate.replace(/[^A-Za-z0-9+/=]/g, '');
        return stripped.trim();
    };

    const directRaw = pickHexValue(entry.raw);
    if (directRaw) {
        return `raw:${directRaw}`;
    }

    const directPem = normalisePemString(entry.pem);
    if (directPem) {
        return `pem:${directPem}`;
    }

    const parsed = entry.parsedX5c && typeof entry.parsedX5c === 'object'
        ? entry.parsedX5c
        : entry.parsed && typeof entry.parsed === 'object'
            ? entry.parsed
            : null;

    if (parsed) {
        const parsedRaw = pickHexValue(parsed.raw);
        if (parsedRaw) {
            return `raw:${parsedRaw}`;
        }

        const parsedDer = pickBase64Value(parsed.derBase64 || parsed.der_base64);
        if (parsedDer) {
            return `der:${parsedDer}`;
        }

        const parsedPem = normalisePemString(parsed.pem);
        if (parsedPem) {
            return `pem:${parsedPem}`;
        }

        const fingerprints = parsed.fingerprints && typeof parsed.fingerprints === 'object'
            ? parsed.fingerprints
            : null;
        if (fingerprints) {
            const fingerprintOrder = ['sha256', 'sha1', 'md5'];
            for (const key of fingerprintOrder) {
                const value = normaliseHexFingerprint(fingerprints[key]);
                if (value) {
                    return `${key}:${value}`;
                }
            }
        }
    }

    return '';
}

export function normaliseCertificateEntryForModal(entry) {
    if (!entry || typeof entry !== 'object') {
        return null;
    }

    const normalised = {
        parsedX5c: {},
    };

    if (entry.parsedX5c && typeof entry.parsedX5c === 'object') {
        normalised.parsedX5c = entry.parsedX5c;
    } else if (entry.parsed && typeof entry.parsed === 'object') {
        normalised.parsedX5c = entry.parsed;
    } else if (typeof entry === 'object') {
        normalised.parsedX5c = entry;
    }

    const pemValue = entry.pem || entry.parsedX5c?.pem || entry.parsed?.pem;
    if (typeof pemValue === 'string' && pemValue.trim() !== '') {
        normalised.pem = pemValue.trim();
    }

    let rawHex = typeof entry.raw === 'string' && entry.raw.trim() !== '' ? entry.raw.trim() : null;
    if (!rawHex) {
        const derBase64 = entry.derBase64
            || entry.der_base64
            || entry.parsedX5c?.derBase64
            || entry.parsed?.derBase64;
        if (typeof derBase64 === 'string' && derBase64.trim() !== '') {
            try {
                rawHex = base64ToHex(derBase64.trim());
            } catch (error) {
                rawHex = null;
            }
        }
    }
    if (rawHex) {
        normalised.raw = rawHex;
    }

    return normalised;
}

export function extractAaguidFromExtensionValue(extValue) {
    if (!extValue) {
        return '';
    }

    if (typeof extValue === 'string') {
        return normaliseAaguidValue(extValue);
    }

    if (Array.isArray(extValue)) {
        for (const item of extValue) {
            const candidate = extractAaguidFromExtensionValue(item);
            if (candidate) {
                return candidate;
            }
        }
        return '';
    }

    if (typeof extValue === 'object') {
        const keys = Object.keys(extValue);

        for (const key of keys) {
            if (typeof key === 'string' && key.toLowerCase().includes('aaguid')) {
                const candidate = normaliseAaguidValue(extValue[key]);
                if (candidate) {
                    return candidate;
                }
            }
        }

        const fallbackKeys = [
            'value',
            'Value',
            'hex',
            'Hex',
            'hexValue',
            'Hex value',
            'raw',
            'rawHex',
        ];

        for (const key of fallbackKeys) {
            if (Object.prototype.hasOwnProperty.call(extValue, key)) {
                const candidate = extractAaguidFromExtensionValue(extValue[key]);
                if (candidate) {
                    return candidate;
                }
            }
        }
    }

    return '';
}

export function extractAaguidFromCertificateEntry(entry) {
    if (!entry || typeof entry !== 'object') {
        return '';
    }

    if (entry.entry && entry.entry !== entry) {
        const nested = extractAaguidFromCertificateEntry(entry.entry);
        if (nested) {
            return nested;
        }
    }

    const parsed = entry.parsedX5c && typeof entry.parsedX5c === 'object'
        ? entry.parsedX5c
        : entry.parsed && typeof entry.parsed === 'object'
            ? entry.parsed
            : entry;

    const candidateSources = [
        entry.aaguid,
        entry.aaguidHex,
        entry.aaguidGuid,
        parsed?.aaguid,
        parsed?.aaguidHex,
        parsed?.aaguidGuid,
    ];

    for (const source of candidateSources) {
        const direct = normaliseAaguidValue(source);
        if (direct) {
            return direct;
        }
    }

    const extensions = Array.isArray(parsed?.extensions) ? parsed.extensions : [];
    for (const ext of extensions) {
        if (!ext || typeof ext !== 'object') {
            continue;
        }

        const oid = typeof ext.oid === 'string' ? ext.oid.trim() : '';
        const friendlyName = typeof ext.friendlyName === 'string' ? ext.friendlyName.trim().toLowerCase() : '';
        const extName = typeof ext.name === 'string' ? ext.name.trim().toLowerCase() : '';
        const isAaguidExtension = (
            oid === AAGUID_EXTENSION_OID
            || friendlyName.includes('aaguid')
            || extName.includes('aaguid')
        );

        if (!isAaguidExtension) {
            continue;
        }

        const valueCandidate = extractAaguidFromExtensionValue(ext.value);
        if (valueCandidate) {
            return valueCandidate;
        }
    }

    return '';
}

export function extractAaguidFromCertificateEntries(entries) {
    if (!entries) {
        return '';
    }

    if (!Array.isArray(entries)) {
        return extractAaguidFromCertificateEntry(entries);
    }

    for (const entry of entries) {
        const candidate = extractAaguidFromCertificateEntry(entry);
        if (candidate) {
            return candidate;
        }
    }

    return '';
}

export function partitionCertificateEntries(entries) {
    const result = {
        valid: [],
        failures: [],
    };

    if (!Array.isArray(entries) || !entries.length) {
        return result;
    }

    entries.forEach((entry, index) => {
        if (!entry || typeof entry !== 'object') {
            return;
        }

        const parsed = entry.parsedX5c && typeof entry.parsedX5c === 'object'
            ? entry.parsedX5c
            : null;

        if (parsed && parsed.parseError) {
            result.failures.push({ entry, index, parsed });
        } else {
            result.valid.push({ entry, index, parsed });
        }
    });

    if (result.failures.length && result.valid.length) {
        const validIdentities = new Set(
            result.valid
                .map(info => deriveCertificateIdentity(info.entry))
                .filter(identity => identity)
        );

        if (validIdentities.size) {
            result.failures = result.failures.filter(info => {
                const identity = deriveCertificateIdentity(info.entry);
                if (!identity) {
                    return true;
                }
                return !validIdentities.has(identity);
            });
        }
    }

    return result;
}
