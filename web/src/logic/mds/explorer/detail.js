// What the explorer's authenticator page shows of an entry, and in what order.
// No DOM.
//
// detailSections(entry) gives the page's sections in order. Each has a `key`, a
// `title`, and what it holds: `fields` (label and value, or label and `codes`)
// and `chipLists` (label and values), `combinations`, `certificates` or
// `statusReports`. A section the page leaves out is not in the list; the
// Overview and the Metadata Statement always are, even with nothing under them.
import { MISSING_CELL_TEXT } from './rows.js';
import { formatDetailValue, formatUpv } from '../formatters.js';
import { aaguidGuid } from '../../shared/aaguid.js';
import { BIOMETRIC_REPORT_COLUMNS, STATUS_REPORT_COLUMNS, biometricReportRow, statusReportRow } from './status-reports.js';

/** @import { StatusReportRow } from './status-reports.js' */

export function extractList(value) {
    if (!value) {
        return [];
    }
    if (Array.isArray(value)) {
        return value.filter(Boolean);
    }
    return [value];
}

export const DEFAULT_DETAIL_TITLE = 'Authenticator';

// The page's title: the entry's name as written, when it is not blank.
/**
 * @param {Record<string, any> | null | undefined} entry
 * @returns {string}
 */
export function detailTitle(entry) {
    const name = entry?.name;
    return typeof name === 'string' && name.trim() ? name : DEFAULT_DETAIL_TITLE;
}

// The subtitle's parts: the AAGUID, the id when it is another, the protocol.
/**
 * @param {Record<string, any> | null | undefined} entry
 * @returns {Array<{ label: string, value: string }>}
 */
export function detailSubtitleParts(entry) {
    if (!entry) {
        return [];
    }
    /** @type {Array<{ label: string, value: string }>} */
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
/**
 * @param {Record<string, any> | null | undefined} entry
 * @returns {string}
 */
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

// A text the statement gives in several languages: one field for each, the
// language after the label, as in "Friendly Name (en-US)".
function languageFields(label, texts) {
    if (!texts || typeof texts !== 'object' || Array.isArray(texts)) {
        return [];
    }
    return Object.entries(texts)
        .filter(([, text]) => text !== null)
        .map(([language, text]) => field(`${label} (${language})`, rawDisplayString(text)));
}

function metadataStatementSection(entry, metadata) {
    const codes = keyIdentifierCodes(entry.attestationKeyIdentifiers);
    const upv = formatUpv(metadata.upv);
    return {
        key: 'metadataStatement',
        title: 'Metadata Statement',
        fields: present([
            metadata.description ? field('Description', metadata.description) : null,
            ...languageFields('Description', metadata.alternativeDescriptions),
            ...languageFields('Friendly Name', metadata.friendlyNames),
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
            info.aaguid ? field('AAGUID', aaguidGuid(info.aaguid) || String(info.aaguid), { identifier: true }) : null,
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

function reportObjects(value) {
    return Array.isArray(value) ? value.filter(report => report && typeof report === 'object') : [];
}

// The status reports, under the entry's last status change and its rogue list;
// shown when the entry has a report or a rogue list.
function statusReportsSection(entry) {
    const reports = Array.isArray(entry.statusReports) ? entry.statusReports : [];
    const rogueList = present([
        field('Rogue List URL', entry.rogueListURL),
        field('Rogue List Hash', entry.rogueListHash, { identifier: true }),
    ]);
    if (!reports.length && !rogueList.length) {
        return null;
    }
    const fields = present([field('Last Status Change', entry.timeOfLastStatusChange), ...rogueList]);
    return {
        key: 'statusReports',
        title: 'Status Reports',
        ...(fields.length ? { fields } : {}),
        ...(reports.length
            ? { columns: STATUS_REPORT_COLUMNS, statusReports: reportObjects(reports).map(statusReportRow) }
            : {}),
    };
}

/**
 * A field: a value (an identifier is copyable, in Geist Mono), or a list of codes.
 * @typedef {{ label: string, value?: string, codes?: string[], identifier?: boolean }} DetailField
 * @typedef {{ label: string, values: string[] }} ChipList
 * @typedef {object} VerificationMethod
 * @property {string} method
 * @property {string} codeAccuracy
 * @property {string} biometricAccuracy
 * @property {string} patternAccuracy
 * @typedef {{ title: string, methods: VerificationMethod[] }} Combination
 * @typedef {{ number: number, label: string, certificate: string }} CertificateLink
 */

/**
 * One of the page's sections, in this order; what it holds depends on its kind.
 * @typedef {object} DetailSection
 * @property {string} key
 * @property {string} title
 * @property {DetailField[]} [fields]
 * @property {ChipList[]} [chipLists]
 * @property {Combination[]} [combinations]
 * @property {CertificateLink[]} [certificates]
 * @property {string[]} [columns]
 * @property {StatusReportRow[]} [statusReports]
 */

/**
 * @param {Record<string, any> | null | undefined} entry
 * @returns {DetailSection[]}
 */
export function detailSections(entry) {
    const source = entry && typeof entry === 'object' ? entry : {};
    const metadata = source.metadataStatement && typeof source.metadataStatement === 'object'
        ? source.metadataStatement
        : {};
    /** @type {DetailSection[]} */
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

    const status = statusReportsSection(source);
    if (status) {
        sections.push(status);
    }

    const biometricReports = reportObjects(source.biometricStatusReports);
    if (biometricReports.length) {
        sections.push({
            key: 'biometricStatusReports',
            title: 'Biometric Status Reports',
            columns: BIOMETRIC_REPORT_COLUMNS,
            statusReports: biometricReports.map(biometricReportRow),
        });
    }

    return sections;
}
