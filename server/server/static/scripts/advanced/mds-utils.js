import { CERTIFICATION_OPTIONS } from './mds-constants.js';

export function collectOptionSets(data) {
    const sets = {
        protocol: new Set(),
        certification: new Set(CERTIFICATION_OPTIONS.map(option => formatEnum(option))),
        userVerification: new Set(),
        attachment: new Set(),
        transports: new Set(),
        keyProtection: new Set(),
        algorithms: new Set(),
    };

    data.forEach(entry => {
        if (entry.protocol) {
            sets.protocol.add(entry.protocol);
        }
        if (entry.certificationStatus) {
            sets.certification.add(formatEnum(entry.certificationStatus));
        }
        entry.userVerificationList.forEach(value => sets.userVerification.add(value));
        entry.attachmentList.forEach(value => sets.attachment.add(value));
        entry.transportsList.forEach(value => sets.transports.add(value));
        entry.keyProtectionList.forEach(value => sets.keyProtection.add(value));
        entry.algorithmsList.forEach(value => sets.algorithms.add(value));
    });

    return sets;
}

export function transformEntry(entry, index = 0) {
    const metadata = entry?.metadataStatement ?? {};
    const name = resolveName(metadata, entry);
    const protocol = formatProtocol(metadata.protocolFamily || metadata.protocolType);
    const { display: certification, status: certificationStatus } = formatCertification(entry?.statusReports || []);
    const identifier = resolveIdentifier(entry, metadata);
    const aaguid = resolveAaguid(entry, metadata) || '';
    const userVerificationList = extractUserVerification(metadata.userVerificationDetails);
    const attachmentList = extractList(metadata.attachmentHint).map(formatEnum);
    const transportsList = extractTransports(metadata);
    const keyProtectionList = extractList(metadata.keyProtection).map(formatEnum);
    const algorithmsList = extractList(metadata.authenticationAlgorithms).map(formatEnum);
    const icon = normaliseIcon(metadata.icon, metadata.iconType);
    const attestationCertificates = extractList(metadata.attestationRootCertificates);
    const attestationKeyIdentifiers = extractAttestationKeyIdentifiers(metadata, entry);

    const latestStatusDate = latestEffectiveDate(entry?.statusReports || []);
    const rawDate = entry?.timeOfLastStatusChange || latestStatusDate;
    const dateUpdated = rawDate ? formatDate(rawDate) : '';

    return {
        index,
        name,
        protocol,
        certification,
        certificationStatus,
        id: identifier,
        aaguid,
        icon,
        userVerification: userVerificationList.join(', '),
        userVerificationList,
        attachment: attachmentList.join(', '),
        attachmentList,
        transports: transportsList.join(', '),
        transportsList,
        keyProtection: keyProtectionList.join(', '),
        keyProtectionList,
        algorithms: algorithmsList.join(', '),
        algorithmsList,
        certificateAlgorithmInfo: '—',
        certificateAlgorithmInfoList: [],
        certificateCommonNames: '—',
        certificateCommonNameList: [],
        algorithmInfo: '—',
        commonName: '—',
        dateUpdated,
        dateTooltip: rawDate || undefined,
        metadataStatement: metadata,
        rawEntry: entry || null,
        statusReports: Array.isArray(entry?.statusReports) ? entry.statusReports : [],
        attestationCertificates,
        attestationKeyIdentifiers,
    };
}

export function extractAttestationKeyIdentifiers(metadata, entry) {
    const map = new Map();
    const addValue = value => {
        if (value === undefined || value === null) {
            return;
        }
        const text = String(value).trim();
        if (!text) {
            return;
        }
        const key = text.toLowerCase();
        if (!map.has(key)) {
            map.set(key, text);
        }
    };

    extractList(metadata?.attestationCertificateKeyIdentifiers).forEach(addValue);
    extractList(entry?.attestationCertificateKeyIdentifiers).forEach(addValue);

    return Array.from(map.values());
}

export function normaliseIcon(icon, iconType) {
    if (!icon) {
        return '';
    }
    const value = String(icon).trim();
    if (!value) {
        return '';
    }
    if (/^data:/i.test(value)) {
        return value;
    }
    if (/^https?:\/\//i.test(value)) {
        return value;
    }
    const type = typeof iconType === 'string' && iconType.trim() ? iconType.trim() : 'image/png';
    return `data:${type};base64,${value}`;
}

export function resolveName(metadata, entry) {
    const description = metadata.description;
    if (typeof description === 'string' && description.trim()) {
        return description.trim();
    }
    if (description && typeof description === 'object') {
        const values = Object.values(description).filter(Boolean);
        if (values.length) {
            return String(values[0]).trim();
        }
    }
    const altDescriptions = metadata.alternativeDescriptions;
    if (altDescriptions) {
        const altValues = typeof altDescriptions === 'object' ? Object.values(altDescriptions) : [];
        const candidate = altValues.find(value => typeof value === 'string' && value.trim());
        if (candidate) {
            return candidate.trim();
        }
    }
    const statusDescriptor = entry?.statusReports?.find(report => report.certificationDescriptor)?.certificationDescriptor;
    if (statusDescriptor) {
        return statusDescriptor;
    }
    return 'Unknown Authenticator';
}

export function resolveIdentifier(entry, metadata) {
    if (entry?.aaguid) {
        return entry.aaguid;
    }
    if (metadata?.aaguid) {
        return metadata.aaguid;
    }
    if (metadata?.aaid) {
        return metadata.aaid;
    }
    const attestKeyIds = extractList(metadata?.attestationCertificateKeyIdentifiers);
    if (attestKeyIds.length) {
        return attestKeyIds[0];
    }
    return '—';
}

export function resolveAaguid(entry, metadata) {
    const candidates = [entry?.aaguid, metadata?.aaguid];
    for (const candidate of candidates) {
        const formatted = formatGuidCandidate(candidate);
        if (formatted) {
            return formatted;
        }
    }
    return '';
}

export function formatGuidCandidate(value) {
    if (value === undefined || value === null) {
        return '';
    }

    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (!trimmed) {
            return '';
        }
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(trimmed)) {
            return trimmed.toLowerCase();
        }
        const clean = trimmed.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
        if (clean.length === 32) {
            return `${clean.slice(0, 8)}-${clean.slice(8, 12)}-${clean.slice(12, 16)}-${clean.slice(16, 20)}-${clean.slice(20)}`;
        }
        return '';
    }

    const bytes = extractByteArray(value);
    if (bytes && bytes.length === 16) {
        const hex = bytes.map(byte => byte.toString(16).padStart(2, '0')).join('');
        return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    }

    try {
        if (typeof value.toString === 'function') {
            return formatGuidCandidate(value.toString());
        }
    } catch (error) {
        // Ignore conversion errors.
    }
    return '';
}

export function extractByteArray(value) {
    if (!value) {
        return null;
    }
    if (Array.isArray(value)) {
        return value.every(item => Number.isInteger(item)) ? value : null;
    }
    if (value instanceof Uint8Array) {
        return Array.from(value);
    }
    if (ArrayBuffer.isView(value)) {
        return Array.from(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
    }
    if (value instanceof ArrayBuffer) {
        return Array.from(new Uint8Array(value));
    }
    return null;
}

export function extractUserVerification(details) {
    const values = new Set();
    if (Array.isArray(details)) {
        details.forEach(group => {
            if (Array.isArray(group)) {
                group.forEach(entry => {
                    if (entry && entry.userVerificationMethod) {
                        values.add(formatEnum(entry.userVerificationMethod));
                    }
                });
            }
        });
    }
    return Array.from(values).sort((a, b) => a.localeCompare(b));
}

export function extractTransports(metadata) {
    const infoTransports = extractList(metadata?.authenticatorGetInfo?.transports);
    const metadataTransports = extractList(metadata?.transports);
    const combined = new Set([
        ...infoTransports.map(formatEnum),
        ...metadataTransports.map(formatEnum),
    ]);
    return Array.from(combined).sort((a, b) => a.localeCompare(b));
}

export function extractList(value) {
    if (!value) {
        return [];
    }
    if (Array.isArray(value)) {
        return value.filter(Boolean);
    }
    return [value];
}

export function normaliseAaguid(value) {
    const formatted = formatGuidCandidate(value);
    return formatted ? formatted.toLowerCase() : '';
}

export function formatUpv(upv) {
    const list = Array.isArray(upv) ? upv : upv ? [upv] : [];
    const formatted = [];
    list.forEach(item => {
        if (item && typeof item === 'object') {
            const major = item.major ?? item.Major;
            const minor = item.minor ?? item.Minor;
            if (major !== undefined && minor !== undefined) {
                formatted.push(`${major}.${minor}`);
            }
        }
    });
    return formatted;
}

export function formatDetailValue(value) {
    if (typeof value === 'boolean') {
        return value ? 'true' : 'false';
    }
    if (value === undefined || value === null) {
        return '—';
    }
    if (Array.isArray(value)) {
        return value.map(item => formatDetailValue(item)).join(', ');
    }
    return String(value);
}

export function formatProtocol(protocol) {
    if (!protocol) {
        return '';
    }
    const normalised = formatEnum(protocol);
    const compact = normalised.replace(/\s+/g, '');
    if (/^fido\d$/i.test(compact)) {
        return compact.toUpperCase();
    }
    return normalised;
}

export function normaliseEnumKey(value) {
    if (value === undefined || value === null) {
        return '';
    }
    return String(value)
        .trim()
        .toUpperCase()
        .replace(/[^A-Z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '');
}

export function formatEnum(value) {
    if (!value && value !== 0) {
        return '';
    }
    return String(value)
        .split(/[_-]/)
        .map(part => part.trim())
        .filter(Boolean)
        .map(part => {
            if (/^[A-Z0-9]+$/.test(part)) {
                if (part.length <= 4) {
                    return part;
                }
                const lower = part.toLowerCase();
                return lower.charAt(0).toUpperCase() + lower.slice(1);
            }
            if (/^.*\d.*$/.test(part)) {
                return part.toUpperCase();
            }
            const lower = part.toLowerCase();
            return lower.charAt(0).toUpperCase() + lower.slice(1);
        })
        .join(' ');
}

export function formatCertification(statusReports) {
    if (!Array.isArray(statusReports) || !statusReports.length) {
        return { display: '', status: '' };
    }

    const sorted = [...statusReports].sort((a, b) => {
        const dateA = Date.parse(a.effectiveDate || '') || 0;
        const dateB = Date.parse(b.effectiveDate || '') || 0;
        return dateB - dateA;
    });

    const latest = sorted[0];
    if (!latest) {
        return { display: '', status: '' };
    }

    const statusRaw = typeof latest.status === 'string' ? latest.status.trim() : '';
    const statusValue = statusRaw ? statusRaw.toUpperCase() : '';
    const descriptor = typeof latest.certificationDescriptor === 'string' ? latest.certificationDescriptor.trim() : '';
    const certificateNumber = typeof latest.certificateNumber === 'string' ? latest.certificateNumber.trim() : '';

    const parts = [];
    const statusDisplay = statusValue ? formatEnum(statusValue) : '';
    if (statusDisplay) {
        parts.push(statusDisplay);
    }
    if (descriptor) {
        parts.push(descriptor);
    }
    if (certificateNumber) {
        parts.push(`(${certificateNumber})`);
    }

    return {
        display: parts.filter(Boolean).join(' • '),
        status: statusValue,
    };
}

export function latestEffectiveDate(statusReports) {
    if (!Array.isArray(statusReports) || !statusReports.length) {
        return '';
    }
    const sorted = [...statusReports].sort((a, b) => {
        const dateA = Date.parse(a.effectiveDate || '') || 0;
        const dateB = Date.parse(b.effectiveDate || '') || 0;
        return dateB - dateA;
    });
    return sorted[0]?.effectiveDate || '';
}

export function parseIsoDate(value) {
    if (typeof value !== 'string' || !value.trim()) {
        return null;
    }
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
        return null;
    }
    return parsed;
}

export function formatDate(value) {
    if (!value) {
        return '';
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return value;
    }
    return new Intl.DateTimeFormat(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
    }).format(date);
}

export function formatCertificateDateDisplay(value) {
    if (!value) {
        return '';
    }
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) {
        return date.toUTCString();
    }
    return typeof value === 'string' ? value : '';
}

export function createSummaryItem(label, value, options = {}) {
    if (!label) {
        return null;
    }

    const resolved = Array.isArray(value) ? value.filter(Boolean) : value;
    const isArray = Array.isArray(resolved);
    const scalar = !isArray ? resolved : null;
    const text = typeof scalar === 'string' ? scalar.trim() : scalar;

    if ((!isArray && (text === undefined || text === null || text === '')) || (isArray && !resolved.length)) {
        return null;
    }

    const item = document.createElement('li');
    item.className = 'mds-certificate-summary__item';

    const labelEl = document.createElement('div');
    labelEl.className = 'mds-certificate-summary__label';
    labelEl.textContent = label;
    item.appendChild(labelEl);

    const valueEl = document.createElement('div');
    valueEl.className = 'mds-certificate-summary__value';

    if (options.code) {
        const codeEl = document.createElement('code');
        codeEl.className = 'mds-certificate-summary__code';
        codeEl.textContent = String(value);
        valueEl.appendChild(codeEl);
    } else if (isArray) {
        resolved.forEach(entry => {
            const line = document.createElement('div');
            line.textContent = String(entry);
            valueEl.appendChild(line);
        });
    } else {
        valueEl.textContent = String(text);
    }

    item.appendChild(valueEl);
    return item;
}

export function determinePublicKeyAlgorithm(info) {
    if (!info || typeof info !== 'object') {
        return '';
    }
    const algorithm = info.algorithm;
    if (algorithm) {
        if (typeof algorithm === 'string') {
            const algorithmName = algorithm.trim();
            if (algorithmName) {
                return algorithmName;
            }
        }
        if (typeof algorithm === 'object') {
            const name = typeof algorithm.name === 'string' ? algorithm.name.trim() : '';
            if (name) {
                return name;
            }
        }
    }
    const type = typeof info.type === 'string' ? info.type.trim() : '';
    return type;
}

export function formatSignatureHashName(hash) {
    if (typeof hash !== 'string') {
        return '';
    }
    const trimmed = hash.trim();
    if (!trimmed) {
        return '';
    }
    const simpleShaMatch = /^sha(\d{3})$/i.exec(trimmed);
    if (simpleShaMatch) {
        return `SHA-${simpleShaMatch[1]}`;
    }
    return trimmed.toUpperCase();
}

export function renderCertificatePublicKey(info) {
    if (!info || typeof info !== 'object') {
        return null;
    }

    const section = document.createElement('div');
    section.className = 'mds-certificate-summary__section';

    const title = document.createElement('div');
    title.className = 'mds-certificate-summary__label';
    title.textContent = 'Public Key';
    section.appendChild(title);

    const list = document.createElement('ul');
    list.className = 'mds-certificate-summary__list';

    const algorithmItem = createSummaryItem('Algorithm', determinePublicKeyAlgorithm(info));
    if (algorithmItem) {
        list.appendChild(algorithmItem);
    }

    const algorithmDetails = info.algorithm && typeof info.algorithm === 'object' ? info.algorithm : null;
    const curveValue = info.curve || (algorithmDetails && algorithmDetails.namedCurve);
    if (curveValue) {
        const curveItem = createSummaryItem('Named Curve', curveValue);
        if (curveItem) {
            list.appendChild(curveItem);
        }
    }

    const modulusLength = algorithmDetails && algorithmDetails.modulusLength;
    const keySize = modulusLength || info.keySize;
    if (keySize) {
        const sizeItem = createSummaryItem('Key Size', `${keySize} bit`);
        if (sizeItem) {
            list.appendChild(sizeItem);
        }
    }

    if (info.publicExponent !== undefined && info.publicExponent !== null) {
        const exponentItem = createSummaryItem('Public Exponent', String(info.publicExponent));
        if (exponentItem) {
            list.appendChild(exponentItem);
        }
    }

    if (info.modulusHex) {
        const modulusItem = createSummaryItem('Modulus', info.modulusHex, { code: true });
        if (modulusItem) {
            list.appendChild(modulusItem);
        }
    }

    if (info.uncompressedPoint) {
        const pointItem = createSummaryItem('Uncompressed Point', info.uncompressedPoint, { code: true });
        if (pointItem) {
            list.appendChild(pointItem);
        }
    }

    if (info.subjectPublicKeyInfoBase64) {
        const valueItem = createSummaryItem('Value', info.subjectPublicKeyInfoBase64, { code: true });
        if (valueItem) {
            list.appendChild(valueItem);
        }
    }

    if (!list.childElementCount) {
        return null;
    }

    section.appendChild(list);
    return section;
}

export function renderCertificateSignature(signature) {
    if (!signature || typeof signature !== 'object') {
        return null;
    }

    const section = document.createElement('div');
    section.className = 'mds-certificate-summary__section';

    const title = document.createElement('div');
    title.className = 'mds-certificate-summary__label';
    title.textContent = 'Signature';
    section.appendChild(title);

    const list = document.createElement('ul');
    list.className = 'mds-certificate-summary__list';

    if (signature.algorithm) {
        const algorithmItem = createSummaryItem('Algorithm', signature.algorithm);
        if (algorithmItem) {
            list.appendChild(algorithmItem);
        }
    }

    if (signature.hash) {
        const hashName = typeof signature.hash === 'object' && signature.hash !== null
            ? signature.hash.name
            : signature.hash;
        const hashValue = typeof hashName === 'string' ? formatSignatureHashName(hashName) : hashName;
        const hashItem = createSummaryItem('Hash', hashValue);
        if (hashItem) {
            list.appendChild(hashItem);
        }
    }

    if (signature.hex) {
        const valueItem = createSummaryItem('Value', signature.hex, { code: true });
        if (valueItem) {
            list.appendChild(valueItem);
        }
    }

    if (!list.childElementCount) {
        return null;
    }

    section.appendChild(list);
    return section;
}

export function renderCertificateSummary(details) {
    if (!details || typeof details !== 'object') {
        return null;
    }

    const fragment = document.createDocumentFragment();

    const infoList = document.createElement('ul');
    infoList.className = 'mds-certificate-summary__list';

    const validity = details.validity || {};
    const serialNumber = details.serialNumber || {};

    [
        createSummaryItem('Subject', details.subject),
        createSummaryItem('Issuer', details.issuer),
        createSummaryItem('Not Before', formatCertificateDateDisplay(validity.notBefore)),
        createSummaryItem('Not After', formatCertificateDateDisplay(validity.notAfter)),
        createSummaryItem('Serial Number', serialNumber.decimal || serialNumber.hex),
        serialNumber.hex ? createSummaryItem('Serial Number (Hex)', serialNumber.hex) : null,
    ].forEach(item => {
        if (item) {
            infoList.appendChild(item);
        }
    });

    if (infoList.childElementCount) {
        fragment.appendChild(infoList);
    }

    const publicKeySection = renderCertificatePublicKey(details.publicKeyInfo);
    if (publicKeySection) {
        fragment.appendChild(publicKeySection);
    }

    const signatureSection = renderCertificateSignature(details.signature);
    if (signatureSection) {
        fragment.appendChild(signatureSection);
    }

    return fragment.childElementCount ? fragment : null;
}

export function decodeBase64Url(value) {
    let base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const padding = base64.length % 4;
    if (padding) {
        base64 += '='.repeat(4 - padding);
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
}
