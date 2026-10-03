// What the explorer's authenticator page shows of an entry, and in what order.
// No DOM.
//
// detailSections(entry) gives the page's sections in order. Each has a `key`, a
// `title`, and what it holds: `fields` (label and value, or label and `codes`)
// and `chipLists` (label and values), `combinations`, `certificates` or
// `statusReports`. A section the page leaves out is not in the list; the
// Overview and the Metadata Statement always are, even with nothing under them.
import { MISSING_CELL_TEXT } from './rows.js';
import { formatUpv } from '../formatters.js';
import { chipList, describe, extractList, field, nameFromKey, present, rawDisplayString, valueText } from './detail-fields.js';
import { authenticatorInfoSection } from './get-info.js';
import { BIOMETRIC_REPORT_COLUMNS, STATUS_REPORT_COLUMNS, biometricReportRow, statusReportRow } from './status-reports.js';

/** @import { ChipList, DetailField } from './detail-fields.js' */
/** @import { StatusReportRow } from './status-reports.js' */

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
            field('Key Restricted', metadata.isKeyRestricted),
            field('Fresh User Verification Required', metadata.isFreshUserVerificationRequired),
            field('Multi-Device Credential Support', metadata.multiDeviceCredentialSupport),
            field('TC Display Content Type', metadata.tcDisplayContentType),
            ...pngFields(metadata.tcDisplayPNGCharacteristics),
            ...otherStatementFields(metadata),
        ]),
        chipLists: present([
            chipList('Authentication Algorithms', metadata.authenticationAlgorithms),
            chipList('Public Key Algorithms', metadata.publicKeyAlgAndEncodings),
            chipList('Attestation Types', metadata.attestationTypes),
            chipList('Key Protection', metadata.keyProtection),
            chipList('Matcher Protection', metadata.matcherProtection),
            chipList('Attachment Hints', metadata.attachmentHint),
            chipList('TC Display', metadata.tcDisplay),
            chipList('Supported Extensions', extractList(metadata.supportedExtensions).map(extensionText)),
        ]),
    };
}

// The statement's members the page shows elsewhere: in the overview, above, in
// a section of their own, or not at all (the images).
const STATEMENT_SHOWN = new Set([
    'aaid', 'aaguid', 'protocolFamily', 'authenticatorVersion',
    'description', 'alternativeDescriptions', 'friendlyNames', 'legalHeader', 'schema', 'cryptoStrength',
    'attestationCertificateKeyIdentifiers', 'upv', 'isKeyRestricted', 'isFreshUserVerificationRequired',
    'multiDeviceCredentialSupport', 'tcDisplayContentType', 'tcDisplayPNGCharacteristics',
    'authenticationAlgorithms', 'publicKeyAlgAndEncodings', 'attestationTypes', 'keyProtection',
    'matcherProtection', 'attachmentHint', 'tcDisplay', 'supportedExtensions',
    'userVerificationDetails', 'attestationRootCertificates', 'authenticatorGetInfo',
    'icon', 'iconDark', 'providerLogoLight', 'providerLogoDark',
]);
const STATEMENT_NAMES = {
    operatingEnv: 'Operating Environment',
    cxConfigURL: 'Credential Exchange Config URL',
    ecdaaTrustAnchors: 'ECDAA Trust Anchors',
};

// Every other member of the statement, MDS3's own under their names and any a
// later version adds named from its key.
function otherStatementFields(metadata) {
    return Object.keys(metadata)
        .filter(key => !STATEMENT_SHOWN.has(key) && metadata[key] !== null)
        .map(key => field(STATEMENT_NAMES[key] ?? nameFromKey(key), valueText(metadata[key])));
}

// "credProtect (tag 1, data 03, fail if unknown)": an extension the statement
// says the authenticator supports, and what its descriptor says of it.
function extensionText(descriptor) {
    if (typeof descriptor !== 'object') {
        return descriptor;
    }
    const notes = [
        descriptor.tag !== undefined && descriptor.tag !== null ? `tag ${descriptor.tag}` : '',
        descriptor.data ? `data ${descriptor.data}` : '',
        descriptor.fail_if_unknown === true ? 'fail if unknown' : '',
    ].filter(Boolean);
    const id = descriptor.id !== undefined && descriptor.id !== null ? String(descriptor.id) : '';
    return [id, notes.length ? `(${notes.join(', ')})` : ''].filter(Boolean).join(' ');
}

const PNG_CHARACTERISTICS = [
    ['width', 'Width'],
    ['height', 'Height'],
    ['bitDepth', 'Bit depth'],
    ['colorType', 'Color type'],
    ['compression', 'Compression'],
    ['filter', 'Filter'],
    ['interlace', 'Interlace'],
];

// A palette entry as "rgb(255, 255, 255)", or its JSON when it is not three numbers.
function paletteEntry(entry) {
    const channels = [entry?.r, entry?.g, entry?.b];
    return channels.every(channel => typeof channel === 'number')
        ? `rgb(${channels.join(', ')})`
        : rawDisplayString(entry);
}

// The transaction display's PNG characteristics: a field for each descriptor
// ("TC Display PNG", numbered when there are several), its palette last.
function pngFields(descriptors) {
    const values = Array.isArray(descriptors) ? descriptors.filter(item => item && typeof item === 'object') : [];
    return values.map((descriptor, index) => {
        const palette = Array.isArray(descriptor.plte) ? `Palette: ${descriptor.plte.map(paletteEntry).join(', ')}` : '';
        const text = [describe(descriptor, PNG_CHARACTERISTICS), palette].filter(Boolean).join(' • ');
        return field(values.length > 1 ? `TC Display PNG ${index + 1}` : 'TC Display PNG', text);
    });
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
