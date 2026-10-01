// What the explorer's certificate page shows of an attestation root. No DOM.
import { readFailedResponse } from '../../shared/failed-response.js';
import { formatCertificateDateDisplay, formatSignatureHashName } from '../utils/formatters.js';

export const CERTIFICATE_DECODE_PATH = '/api/mds/decode-certificate';
export const DEFAULT_CERTIFICATE_TITLE = 'Attestation Certificate';
export const NO_CERTIFICATE_DETAILS = 'No decoded certificate details available.';
export const CERTIFICATE_DECODE_FAILED = 'Unable to decode certificate.';

// The certificate as sent to the server: the base64 without its whitespace.
export function normaliseCertificateBase64(value) {
    if (typeof value !== 'string') {
        return '';
    }
    return value.replace(/\s+/g, '').trim();
}

// Decoded Output: the server's summary text, else the details as JSON.
export function formatCertificateOutput(details) {
    if (!details || typeof details !== 'object') {
        return NO_CERTIFICATE_DETAILS;
    }
    if (typeof details.summary === 'string' && details.summary.trim()) {
        return details.summary.trim();
    }
    return JSON.stringify(details, null, 2);
}

// POST /api/mds/decode-certificate. A refusal throws "Certificate decode failed
// with status N" (what the page says), with the server's own sentence, when it
// gave one, as the error's `reason`.
export async function requestCertificateDecode(certificate) {
    const response = await fetch(CERTIFICATE_DECODE_PATH, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ certificate }),
        cache: 'no-store',
    });

    if (!response.ok) {
        const error = new Error(`Certificate decode failed with status ${response.status}`);
        const failure = await readFailedResponse(response);
        error.reason = typeof failure.body?.error === 'string' ? failure.text : '';
        throw error;
    }

    const payload = await response.json();
    return payload?.details ?? null;
}

// What a failed decode says: the error's message, else the page's sentence.
export function certificateDecodeFailure(error) {
    return error instanceof Error ? error.message : CERTIFICATE_DECODE_FAILED;
}

// The public key's algorithm: its name, else the key's type.
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
    return typeof info.type === 'string' ? info.type.trim() : '';
}

// One line of the summary, or null when it has nothing to show: a label and its
// value (trimmed), or its `lines` for a list; `code` values are shown as given.
export function certificateSummaryItem(label, value, { primary = false, code = false } = {}) {
    if (!label) {
        return null;
    }
    const isList = Array.isArray(value);
    const resolved = isList ? value.filter(Boolean) : value;
    const text = typeof resolved === 'string' ? resolved.trim() : resolved;
    if (isList ? !resolved.length : text === undefined || text === null || text === '') {
        return null;
    }
    const item = { label, primary, code };
    if (code) {
        return { ...item, value: String(value) };
    }
    return isList ? { ...item, lines: resolved.map(String) } : { ...item, value: String(text) };
}

function summarySection(title, items) {
    const present = items.filter(Boolean);
    return present.length ? { title, items: present } : null;
}

export function certificatePublicKeySection(info) {
    if (!info || typeof info !== 'object') {
        return null;
    }
    const algorithmDetails = info.algorithm && typeof info.algorithm === 'object' ? info.algorithm : null;
    const curve = info.curve || (algorithmDetails && algorithmDetails.namedCurve);
    const keySize = (algorithmDetails && algorithmDetails.modulusLength) || info.keySize;
    return summarySection('Public Key', [
        certificateSummaryItem('Algorithm', determinePublicKeyAlgorithm(info)),
        curve ? certificateSummaryItem('Named Curve', curve) : null,
        keySize ? certificateSummaryItem('Key Size', `${keySize} bit`) : null,
        info.publicExponent !== undefined && info.publicExponent !== null
            ? certificateSummaryItem('Public Exponent', String(info.publicExponent))
            : null,
        info.modulusHex ? certificateSummaryItem('Modulus', info.modulusHex, { code: true }) : null,
        info.uncompressedPoint ? certificateSummaryItem('Uncompressed Point', info.uncompressedPoint, { code: true }) : null,
        info.subjectPublicKeyInfoBase64
            ? certificateSummaryItem('Value', info.subjectPublicKeyInfoBase64, { code: true })
            : null,
    ]);
}

export function certificateSignatureSection(signature) {
    if (!signature || typeof signature !== 'object') {
        return null;
    }
    let hash = null;
    if (signature.hash) {
        const hashName = typeof signature.hash === 'object' ? signature.hash.name : signature.hash;
        hash = certificateSummaryItem('Hash', typeof hashName === 'string' ? formatSignatureHashName(hashName) : hashName);
    }
    return summarySection('Signature', [
        signature.algorithm ? certificateSummaryItem('Algorithm', signature.algorithm) : null,
        hash,
        signature.hex ? certificateSummaryItem('Value', signature.hex, { code: true }) : null,
    ]);
}

// The summary above the raw and decoded blocks: its first items (subject,
// issuer, validity, serial numbers), then the Public Key and Signature
// sections; null when it would show nothing.
export function certificateSummary(details) {
    if (!details || typeof details !== 'object') {
        return null;
    }
    const validity = details.validity || {};
    const serialNumber = details.serialNumber || {};
    const primary = { primary: true };
    const items = [
        certificateSummaryItem('Subject', details.subject, primary),
        certificateSummaryItem('Issuer', details.issuer, primary),
        certificateSummaryItem('Not Before', formatCertificateDateDisplay(validity.notBefore), primary),
        certificateSummaryItem('Not After', formatCertificateDateDisplay(validity.notAfter), primary),
        certificateSummaryItem('Serial Number', serialNumber.decimal || serialNumber.hex, primary),
        serialNumber.hex ? certificateSummaryItem('Serial Number (Hex)', serialNumber.hex) : null,
    ].filter(Boolean);
    const sections = [certificatePublicKeySection(details.publicKeyInfo), certificateSignatureSection(details.signature)]
        .filter(Boolean);
    return items.length || sections.length ? { items, sections } : null;
}

// What the page shows for a decode: its title (the subject), subtitle (the
// issuer, '' for none), the summary or the sentence in its place, and Decoded
// Output. A failure shows its sentence in both, under the default title.
export function describeCertificate({ details = null, error = null } = {}) {
    if (error) {
        const message = certificateDecodeFailure(error);
        return {
            title: DEFAULT_CERTIFICATE_TITLE,
            subtitle: '',
            summary: null,
            message,
            output: message,
            failed: true,
            reason: typeof error?.reason === 'string' ? error.reason : '',
        };
    }
    const summary = certificateSummary(details);
    const subject = typeof details?.subject === 'string' ? details.subject.trim() : '';
    const issuer = typeof details?.issuer === 'string' ? details.issuer.trim() : '';
    return {
        title: subject || DEFAULT_CERTIFICATE_TITLE,
        subtitle: issuer,
        summary,
        message: summary ? '' : NO_CERTIFICATE_DETAILS,
        output: formatCertificateOutput(details),
        failed: false,
        reason: '',
    };
}
