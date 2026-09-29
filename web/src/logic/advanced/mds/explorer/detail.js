// What the explorer's authenticator page shows of an entry, and in what order.
// No DOM.
//
// detailSections(entry) gives the page's sections in order. Each has a `key`, a
// `title`, and what it holds: `fields` (label and value, or label and `codes`)
// and `chipLists` (label and values), `combinations`, `certificates` or
// `statusReports`. A section the page leaves out is not in the list; the
// Overview and the Metadata Statement always are, even with nothing under them.
import { MISSING_CELL_TEXT } from './rows.js';
import { extractList } from '../utils/extractors.js';
import { formatDate, formatDetailValue, formatUpv } from '../utils/formatters.js';
import { formatGuidCandidate } from '../utils/resolvers.js';

export const DEFAULT_DETAIL_TITLE = 'Authenticator';

// The page's title: the entry's name as written, when it is not blank.
export function detailTitle(entry) {
    const name = entry?.name;
    return typeof name === 'string' && name.trim() ? name : DEFAULT_DETAIL_TITLE;
}

// The subtitle's parts: the AAGUID, the id when it is another, the protocol.
export function detailSubtitleParts(entry) {
    if (!entry) {
        return [];
    }
    const parts = [];
    if (entry.aaguid) {
        parts.push({ label: 'AAGUID', value: String(entry.aaguid) });
    }
    if (entry.id && entry.id !== entry.aaguid) {
        parts.push({ label: 'ID', value: String(entry.id) });
    }
    if (entry.protocol) {
        parts.push({ label: '', value: String(entry.protocol) });
    }
    return parts;
}

// "AAGUID: … • ID: … • FIDO2".
export function formatDetailSubtitle(entry) {
    return detailSubtitleParts(entry)
        .map(part => (part.label ? `${part.label}: ${part.value}` : part.value))
        .join(' • ');
}

// One list item (never null: the list reader drops empty items first).
function rawDisplayString(value) {
    if (typeof value === 'string') {
        return value;
    }
    if (typeof value === 'number' || typeof value === 'bigint') {
        return String(value);
    }
    try {
        // true as "true", an object as its JSON; a function or a symbol has no
        // JSON: nothing to show.
        return JSON.stringify(value) ?? '';
    } catch {
        try {
            return String(value);
        } catch {
            return '';
        }
    }
}

// A list's values as the metadata writes them (a number as written, a boolean
// as true / false, an object as its JSON), the empty ones left out.
export function rawListValues(value) {
    return extractList(value)
        .map(item => rawDisplayString(item))
        .filter(text => text !== '');
}

// A field is shown when it has a value that is not blank.
function field(label, value, { identifier = false } = {}) {
    if (value === undefined || value === null) {
        return null;
    }
    const text = String(value);
    if (!text.trim()) {
        return null;
    }
    return identifier ? { label, value: text, identifier: true } : { label, value: text };
}

function present(items) {
    return items.filter(Boolean);
}

function chipList(label, value) {
    const values = rawListValues(value);
    return values.length ? { label, values } : null;
}

function overviewSection(entry, metadata) {
    return {
        key: 'overview',
        title: 'Overview',
        fields: present([
            entry.id ? field('Identifier', entry.id, { identifier: true }) : field('Identifier', MISSING_CELL_TEXT),
            entry.aaguid ? field('AAGUID', entry.aaguid, { identifier: true }) : null,
            entry.protocol ? field('Protocol', entry.protocol) : null,
            entry.certification ? field('Certification', entry.certification) : null,
            field('Authenticator Version', metadata.authenticatorVersion),
            entry.dateUpdated ? field('Date Updated', entry.dateUpdated) : null,
        ]),
        chipLists: [],
    };
}

// The attestation certificate key identifiers, trimmed, the blank ones left out.
function keyIdentifierCodes(values) {
    return extractList(values)
        .map(value => String(value).trim())
        .filter(Boolean);
}

function metadataStatementSection(entry, metadata) {
    const codes = keyIdentifierCodes(entry.attestationKeyIdentifiers);
    const upv = formatUpv(metadata.upv);
    return {
        key: 'metadataStatement',
        title: 'Metadata Statement',
        fields: present([
            metadata.description ? field('Description', metadata.description) : null,
            metadata.legalHeader ? field('Legal Header', metadata.legalHeader) : null,
            field('Schema', metadata.schema),
            field('Crypto Strength', metadata.cryptoStrength),
            codes.length ? { label: 'Attestation Certificate Key IDs', codes } : null,
            upv.length ? field('UPV', upv.join(', ')) : null,
        ]),
        chipLists: present([
            chipList('Authentication Algorithms', metadata.authenticationAlgorithms),
            chipList('Public Key Algorithms', metadata.publicKeyAlgAndEncodings),
            chipList('Attestation Types', metadata.attestationTypes),
            chipList('Key Protection', metadata.keyProtection),
            chipList('Matcher Protection', metadata.matcherProtection),
            chipList('Attachment Hints', metadata.attachmentHint),
            chipList('TC Display', metadata.tcDisplay),
        ]),
    };
}

// A descriptor's properties as "Label: value", joined by " • ", each only when
// the descriptor has it; '' for no descriptor.
function describe(descriptor, properties) {
    if (!descriptor || typeof descriptor !== 'object') {
        return '';
    }
    return properties
        .filter(([key]) => descriptor[key] !== undefined)
        .map(([key, label]) => `${label}: ${descriptor[key]}`)
        .join(' • ');
}

const CODE_ACCURACY = [
    ['base', 'Base'],
    ['minLength', 'Min length'],
    ['maxRetries', 'Max retries'],
    ['blockSlowdown', 'Block slowdown'],
];

const BIOMETRIC_ACCURACY = [
    ['selfAttestedFRR', 'Self-attested FRR'],
    ['selfAttestedFAR', 'Self-attested FAR'],
    ['maxTemplates', 'Max templates'],
    ['maxRetries', 'Max retries'],
    ['blockSlowdown', 'Block slowdown'],
];

const PATTERN_ACCURACY = [
    ['minComplexity', 'Min complexity'],
    ['maxRetries', 'Max retries'],
    ['blockSlowdown', 'Block slowdown'],
];

// One method of a combination: its name as published and its descriptors: the
// code, biometric and pattern accuracy (`caDesc`, `baDesc`, `paDesc`).
function verificationMethod(item) {
    const method = item.userVerificationMethod;
    return {
        method: method !== undefined && method !== null ? String(method) : '',
        codeAccuracy: describe(item.caDesc, CODE_ACCURACY),
        biometricAccuracy: describe(item.baDesc, BIOMETRIC_ACCURACY),
        patternAccuracy: describe(item.paDesc, PATTERN_ACCURACY),
    };
}

// "Combination n" for each combination with a method's name or its code
// accuracy to show; n counts the combinations left out too.
function verificationCombinations(details) {
    const groups = Array.isArray(details) ? details : [];
    const combinations = [];
    groups.forEach((group, index) => {
        const items = (Array.isArray(group) ? group : [group]).filter(item => item && typeof item === 'object');
        const methods = items
            .map(item => verificationMethod(item))
            .filter(method => method.method || method.codeAccuracy);
        if (methods.length) {
            combinations.push({ title: `Combination ${index + 1}`, methods });
        }
    });
    return combinations;
}

// "Certificate n" for each certificate that is not empty.
function attestationCertificates(certificates) {
    const values = Array.isArray(certificates) ? certificates.filter(Boolean) : [];
    return values.map((certificate, index) => ({
        number: index + 1,
        label: `Certificate ${index + 1}`,
        certificate,
    }));
}

const GET_INFO_NUMBERS = [
    ['maxMsgSize', 'Max Message Size'],
    ['maxCredentialCountInList', 'Max Credential Count'],
    ['maxCredentialIdLength', 'Max Credential ID Length'],
    ['maxSerializedLargeBlobArray', 'Max Serialized Large Blob Array'],
    ['minPINLength', 'Min PIN Length'],
    ['firmwareVersion', 'Firmware Version'],
    ['maxCredBlobLength', 'Max Cred Blob Length'],
    ['maxRPIDsForSetMinPINLength', 'Max RP IDs for Set Min PIN Length'],
    ['remainingDiscoverableCredentials', 'Remaining Discoverable Credentials'],
];

function authenticatorInfoSection(info) {
    const options = info.options && typeof info.options === 'object'
        ? Object.entries(info.options).filter(([, value]) => value !== undefined && value !== null)
        : [];
    return {
        key: 'authenticatorGetInfo',
        title: 'Authenticator Get Info',
        fields: present([
            info.aaguid ? field('AAGUID', formatGuidCandidate(info.aaguid) || String(info.aaguid), { identifier: true }) : null,
            ...GET_INFO_NUMBERS.map(([key, label]) => field(label, info[key])),
        ]),
        chipLists: present([
            chipList('Versions', info.versions),
            chipList('Extensions', info.extensions),
            chipList('Transports', info.transports),
            chipList('Algorithms', info.algorithms),
            chipList('pinUvAuth Protocols', info.pinUvAuthProtocols),
            options.length
                ? { label: 'Options', values: options.map(([key, value]) => `${key}: ${formatDetailValue(value)}`) }
                : null,
        ]),
    };
}

export const STATUS_REPORT_COLUMNS = ['Status', 'Effective Date', 'Authenticator Version', 'Certificate Number', 'Descriptor'];

function reportCell(value) {
    return value !== undefined && value !== null ? String(value) : MISSING_CELL_TEXT;
}

// A status report's row: the cells, and the Descriptor column's two lines,
// "descriptor • url" and "Policy: … • Requirements: … • Changed: …" ('' when a
// line has nothing; the column shows "—" when neither has).
function statusReportRow(report) {
    const changed = [];
    if (report.certificationPolicyVersion) {
        changed.push(`Policy: ${report.certificationPolicyVersion}`);
    }
    if (report.certificationRequirementsVersion) {
        changed.push(`Requirements: ${report.certificationRequirementsVersion}`);
    }
    if (report.timeOfLastStatusChange) {
        changed.push(`Changed: ${formatDate(report.timeOfLastStatusChange)}`);
    }
    return {
        status: reportCell(report.status),
        effectiveDate: reportCell(report.effectiveDate),
        authenticatorVersion: reportCell(report.authenticatorVersion),
        certificateNumber: report.certificateNumber ? String(report.certificateNumber) : MISSING_CELL_TEXT,
        descriptor: [report.certificationDescriptor, report.url].filter(Boolean).map(String).join(' • '),
        details: changed.join(' • '),
    };
}

export function detailSections(entry) {
    const source = entry && typeof entry === 'object' ? entry : {};
    const metadata = source.metadataStatement && typeof source.metadataStatement === 'object'
        ? source.metadataStatement
        : {};
    const sections = [overviewSection(source, metadata), metadataStatementSection(source, metadata)];

    const combinations = verificationCombinations(metadata.userVerificationDetails);
    if (combinations.length) {
        sections.push({ key: 'userVerification', title: 'User Verification Details', combinations });
    }

    const certificates = attestationCertificates(source.attestationCertificates);
    if (certificates.length) {
        sections.push({ key: 'certificates', title: 'Attestation Root Certificates', certificates });
    }

    const info = metadata.authenticatorGetInfo;
    if (info && typeof info === 'object') {
        sections.push(authenticatorInfoSection(info));
    }

    const reports = Array.isArray(source.statusReports) ? source.statusReports : [];
    if (reports.length) {
        sections.push({
            key: 'statusReports',
            title: 'Status Reports',
            columns: STATUS_REPORT_COLUMNS,
            statusReports: reports.filter(report => report && typeof report === 'object').map(statusReportRow),
        });
    }

    return sections;
}
