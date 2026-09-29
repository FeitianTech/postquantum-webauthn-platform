// What the Codec shows for an answer, without the page: the header, the notes,
// the findings and the sections in their order. The current panel
// (render-sections.js) and the new UI in web/ both use this one copy.
import { describeEncodedOutput } from './encoding/summary.js';
import { formatKey } from './labels.js';

// Sections come in this order for each type (the part before " ("); any other
// key follows in the answer's own order.
const SECTION_ORDER = {
    PublicKeyCredential: [
        'credential',
        'attestationObject',
        'attestationStatementDecoded',
        'authenticatorData',
        'clientDataJSON',
        'clientExtensionResults',
        'extensionsDecoded',
        'responseDetails',
    ],
    'Attestation object': [
        'attestationObject',
        'attestationStatementDecoded',
        'authenticatorData',
        'extensionsDecoded',
        'extensions',
        'edn',
    ],
    'Authenticator data': ['authenticatorData'],
    'WebAuthn client data': ['clientDataJSON'],
    'X.509 certificate': ['raw', 'pem', 'parsedX5c', 'certificates'],
    CBOR: [
        'ctapDecoded',
        'getInfoDecoded',
        'attestationStatementDecoded',
        'extensionsDecoded',
        'expandedJson',
        'decodedValue',
        'ctap',
        'edn',
    ],
};

export const CODEC_NO_DECODED_DATA = 'No decoded data available.';
export const CODEC_NO_STRUCTURED_DATA = 'No structured data available.';
export const CODEC_LENIENT_NOTE = 'Decoded in lenient mode (best effort); skipped items are listed below.';

function hasOwn(object, key) {
    return Object.prototype.hasOwnProperty.call(object, key);
}

// One section: the EDN view (the bytes exactly), a top-level expandedJson, or
// a value shown by values.js.
function codecSection(key, value) {
    const kind = key === 'edn' ? 'edn' : key === 'expandedJson' ? 'expandedJson' : 'value';
    return { key, label: formatKey(key), kind, value };
}

/** The sections of an answer's `data`, in the order they are shown. */
export function codecSections(type, data) {
    if (data === undefined) {
        return [];
    }
    if (data === null || typeof data !== 'object' || Array.isArray(data)) {
        return [codecSection(type || 'Data', data)];
    }

    const baseType = typeof type === 'string' ? type.split(' (', 1)[0] : '';
    const preferredOrder = hasOwn(SECTION_ORDER, baseType) ? SECTION_ORDER[baseType] : [];
    const usedKeys = new Set();
    const sections = [];
    preferredOrder.forEach((key) => {
        if (hasOwn(data, key)) {
            sections.push(codecSection(key, data[key]));
            usedKeys.add(key);
        }
    });
    Object.keys(data).forEach((key) => {
        if (!usedKeys.has(key)) {
            sections.push(codecSection(key, data[key]));
        }
    });
    return sections;
}

export function codecFindingsHeading(count) {
    return count === 1 ? '1 finding' : `${count} findings`;
}

/**
 * A finding's parts: the field it was found in (a PublicKeyCredential field
 * counts its offset from that field), "offset N" when it has one (a finding in
 * JSON has only a path), the path, the message and the category, and the
 * panel's one line for it.
 */
export function codecFindingParts(finding) {
    const source = typeof finding?.source === 'string' ? finding.source : null;
    const offset = Number.isInteger(finding?.offset) ? `offset ${finding.offset}` : null;
    const path = typeof finding?.path === 'string' ? finding.path : '';
    const message = typeof finding?.message === 'string' ? finding.message : '';
    const category = typeof finding?.category === 'string' ? finding.category : null;
    const line = `${source ? `${source}: ` : ''}${offset ? `${offset} · ` : ''}${path} — ${message}`;
    return { source, offset, path, message, category, line };
}

/**
 * Everything the output shows for `payload` in `mode`: `empty` alone when the
 * answer is not an object; otherwise the pill, the type, the lenient note, the
 * findings (or, when there are none, the malformed line), and either the encoded
 * bytes (encode mode, when the answer holds them) or the sections, with the
 * sentence for none.
 */
export function describeCodecResult(payload, mode = 'decode') {
    if (!payload || typeof payload !== 'object') {
        return { empty: CODEC_NO_DECODED_DATA };
    }

    const findings = Array.isArray(payload.findings) ? payload.findings : [];
    const malformed = Array.isArray(payload.malformed) ? payload.malformed : [];
    const encoded = mode === 'encode' ? describeEncodedOutput(payload.data) : null;
    const sections = encoded ? [] : codecSections(payload.type, payload.data);

    return {
        empty: null,
        success: Boolean(payload.success),
        pill: payload.success ? 'Success' : 'Error',
        type: payload.type || 'Decoded data',
        lenientNote: payload.decodeMode === 'lenient' ? CODEC_LENIENT_NOTE : null,
        findingsHeading: findings.length > 0 ? codecFindingsHeading(findings.length) : null,
        findings: findings.map((finding) => ({
            ...codecFindingParts(finding),
            // The server also lists it among the malformed segments.
            malformed: typeof finding?.message === 'string' && malformed.includes(finding.message),
        })),
        malformed: findings.length === 0 && malformed.length > 0
            ? `Malformed segments: ${malformed.join(', ')}`
            : null,
        encoded,
        sections,
        noSections: !encoded && sections.length === 0 ? CODEC_NO_STRUCTURED_DATA : null,
    };
}
