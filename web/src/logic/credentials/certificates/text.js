// A certificate as text, as the registration view's certificate shows it: the
// summary a record from an earlier release kept, else the same text written from
// the certificate's fields, line for line as the server writes its summary
// (webauthn/attestation/certificate_summary.py). A registration keeps one form of
// each value, the signature's hex and the public key's base64, and the lines of
// hex are written from those. DOM-free: both interfaces import it.
import {base64ToBytes} from '../../shared/base64.js';
import {bytesToHex} from '../../shared/bytes.js';

const SUBJECT_KEY_IDENTIFIER_OID = '2.5.29.14';

// The type the server gives an EdDSA key (its class's name), and the type its summary names.
const EDDSA_TYPES = Object.freeze({ Ed25519PublicKey: 'Ed25519', Ed448PublicKey: 'Ed448' });

// Hex text's digits, as the server reads hex with separators: whitespace, a leading
// 0x and colons aside, an odd count led by a zero; null when it is not hex.
function hexDigits(value) {
    if (typeof value !== 'string') {
        return null;
    }
    const digits = value.replace(/\s+/g, '').replace(/^0[xX]|:/g, '');
    if (!/^[0-9a-fA-F]*$/.test(digits)) {
        return null;
    }
    return (digits.length % 2 ? `0${digits}` : digits).toLowerCase();
}

// Hex digits as the server writes bytes: colon-separated, sixteen bytes to a line.
function hexLines(digits) {
    const lines = [];
    for (let start = 0; start < (digits || '').length; start += 32) {
        lines.push(digits.slice(start, start + 32).replace(/(..)(?!$)/g, '$1:'));
    }
    return lines;
}

// Standard base64's bytes in those lines; none when it does not decode.
function base64Lines(value) {
    try {
        return hexLines(bytesToHex(base64ToBytes(value)));
    } catch (error) {
        return [];
    }
}

// A value as Python writes it into the text: True and False for booleans.
function pythonText(value) {
    return typeof value === 'boolean' ? (value ? 'True' : 'False') : String(value);
}

// An extension's value as indented lines: a map's keys with their values (none for
// an empty one), a list item by item, anything else on a line of its own.
function structuredLines(value, indent) {
    const pad = '    '.repeat(indent);
    if (value === null || value === undefined) {
        return [];
    }
    if (Array.isArray(value)) {
        if (value.every(item => typeof item === 'string')) {
            return value.filter(item => item !== '').map(item => `${pad}${item}`);
        }
        return value.flatMap(item => structuredLines(item, indent));
    }
    if (typeof value === 'object') {
        return Object.entries(value).flatMap(([key, item]) => {
            if (item === null || item === undefined || item === '') {
                return [];
            }
            return typeof item === 'object'
                ? [`${pad}${key}:`, ...structuredLines(item, indent + 1)]
                : [`${pad}${key}: ${pythonText(item)}`];
        });
    }
    return [`${pad}${pythonText(value)}`];
}

// The first lines: version, serial number, signature algorithm, issuer.
function identityLines(details) {
    const lines = [];
    if (details.version && typeof details.version.display === 'string') {
        lines.push(`Version: ${details.version.display}`);
    }
    const serial = details.serialNumber && typeof details.serialNumber === 'object' ? details.serialNumber : {};
    const [decimal, hex] = [serial.decimal, serial.hex].map(part => (typeof part === 'string' ? part : null));
    if (decimal !== null || hex !== null) {
        const both = decimal !== null && hex !== null;
        lines.push(`Certificate Serial Number: ${both ? `${decimal} (${hex})` : decimal ?? hex}`);
    }
    if (typeof details.signatureAlgorithm === 'string') {
        lines.push(`Signature Algorithm: ${details.signatureAlgorithm}`);
    }
    if (typeof details.issuer === 'string') {
        lines.push(`Issuer: ${details.issuer}`);
    }
    return lines;
}

function validityLines(validity) {
    if (!validity || typeof validity !== 'object') {
        return [];
    }
    const dates = [['Not Before', validity.notBefore], ['Not After', validity.notAfter]]
        .filter(([, date]) => typeof date === 'string');
    return dates.length ? ['Validity:', ...dates.map(([label, date]) => `    ${label}: ${date}`)] : [];
}

// What the server read of a key: ML-DSA's, or what a key it could not load declares.
function describedKeyEntries(info, algorithm) {
    return [
        ['Type', info.type],
        ['Algorithm OID', algorithm.oid],
        ['ML-DSA parameter set', algorithm.mlDsaParameterSet],
        ['Claimed NIST level', algorithm.claimedNistLevel],
        ['Signature length (bytes)', algorithm.signatureLengthBytes],
        ['Public key size (bits)', info.keySize || null],
        ['Public Key (base64)', info.publicKeyBase64],
        ['Public Key (hex)', base64Lines(info.publicKeyBase64)],
        ['Wrapped Public Key (hex)', base64Lines(info.wrappedPublicKeyBase64)],
    ];
}

// The key's labels and values, as the server's summary gives them for its type.
function publicKeyEntries(info) {
    const algorithm = info.algorithm && typeof info.algorithm === 'object' ? info.algorithm : {};
    const keySize = info.keySize ? `(${info.keySize} bit)` : null;
    if (info.mechanismFamily === 'ML-DSA' || typeof algorithm.oid === 'string') {
        return describedKeyEntries(info, algorithm);
    }
    if (info.type === 'ECC') {
        return [['Type', 'ECC'], ['Public-Key', keySize], ['pub', hexLines(hexDigits(info.uncompressedPoint))], ['Curve', info.curve]];
    }
    if (info.type === 'RSA') {
        return [
            ['Type', 'RSA'],
            ['Public-Key', keySize],
            ['Modulus', hexLines(hexDigits(info.modulusHex))],
            ['Exponent', info.publicExponent],
        ];
    }
    if (Object.hasOwn(EDDSA_TYPES, info.type)) {
        return [['Type', EDDSA_TYPES[info.type]], ['Public Key', hexLines(hexDigits(info.publicKeyHex))]];
    }
    return [['Type', info.type]];
}

// "Subject Public Key Info:", each label with its value, or its lines under it.
function publicKeyLines(info) {
    if (!info || typeof info !== 'object') {
        return [];
    }
    const lines = publicKeyEntries(info).flatMap(([label, value]) => {
        if (value === null || value === undefined || value === '' || (Array.isArray(value) && !value.length)) {
            return [];
        }
        return Array.isArray(value)
            ? [`    ${label}:`, ...value.map(line => `        ${line}`)]
            : [`    ${label}: ${pythonText(value)}`];
    });
    return lines.length ? ['Subject Public Key Info:', ...lines] : [];
}

// An extension's header: the server's own, else its OID and (name), or either
// alone, or "Extension"; "[critical]" after a critical one.
function extensionHeader(ext) {
    const includeOid = ext.includeOidInHeader === undefined
        ? true
        : Boolean(ext.includeOidInHeader);
    const headerOverride = typeof ext.displayHeader === 'string'
        ? ext.displayHeader.trim()
        : '';
    const oid = typeof ext.oid === 'string' ? ext.oid.trim() : '';
    const friendlyName = typeof ext.friendlyName === 'string'
        ? ext.friendlyName.trim()
        : '';
    const extName = typeof ext.name === 'string' ? ext.name.trim() : '';

    let header = headerOverride;
    if (!header) {
        const headerParts = [];
        if (includeOid && oid) {
            headerParts.push(oid);
        }

        let displayName = friendlyName;
        if (!displayName && extName && extName !== oid) {
            displayName = extName;
        }

        if (displayName) {
            if (includeOid && headerParts.length) {
                headerParts.push(`(${displayName})`);
            } else {
                headerParts.push(displayName);
            }
        }

        if (!headerParts.length) {
            if (extName) {
                headerParts.push(extName);
            } else if (oid) {
                headerParts.push(oid);
            } else {
                headerParts.push('Extension');
            }
        }

        header = headerParts.join(' ');
    }

    return ext.critical ? `${header} [critical]` : header;
}

// "X509v3 extensions:", each its header and value.
function extensionLines(extensions) {
    if (!Array.isArray(extensions) || !extensions.length) {
        return [];
    }
    return ['X509v3 extensions:', ...extensions
        .filter(ext => ext && typeof ext === 'object')
        .flatMap(ext => [`    ${extensionHeader(ext)}:`, ...structuredLines(ext.value, 2)])];
}

// The signature's bytes in lines, under the certificate's signature algorithm.
function signatureLines(details) {
    const lines = hexLines(hexDigits(details.signature && details.signature.hex));
    if (!lines.length) {
        return [];
    }
    const algorithm = typeof details.signatureAlgorithm === 'string' ? details.signatureAlgorithm : '';
    return [`Signature Algorithm: ${algorithm}`, ...lines.map(line => `    ${line}`)];
}

// "Fingerprint:", MD5, SHA1 and SHA256 in that order, each in its lines (a value
// that is no hex as it is).
function fingerprintLines(fingerprints) {
    if (!fingerprints || typeof fingerprints !== 'object') {
        return [];
    }
    const lines = ['md5', 'sha1', 'sha256'].flatMap(name => {
        const value = fingerprints[name];
        if (typeof value !== 'string' || value === '') {
            return [];
        }
        const digits = hexDigits(value);
        const valueLines = digits === null ? [value] : hexLines(digits);
        return [`    ${name.toUpperCase()}:`, ...valueLines.map(line => `        ${line}`)];
    });
    return lines.length ? ['Fingerprint:', ...lines] : [];
}

// The subject key identifier's lines, from its extension's value.
function subjectKeyIdentifierLines(extensions) {
    const extension = Array.isArray(extensions)
        ? extensions.find(ext => ext && ext.oid === SUBJECT_KEY_IDENTIFIER_OID)
        : null;
    const lines = extension && extension.value && Array.isArray(extension.value['Hex value'])
        ? extension.value['Hex value']
        : [];
    return lines.length ? ['Subject Key Identifier:', ...lines.map(line => `    ${line}`)] : [];
}

export function formatCertificateDetails(details) {
    if (!details || typeof details !== 'object') {
        return '';
    }

    if (typeof details.summary === 'string' && details.summary.trim() !== '') {
        return details.summary.trim();
    }

    const sections = [
        identityLines(details),
        validityLines(details.validity),
        typeof details.subject === 'string' ? [`Subject: ${details.subject}`] : [],
        publicKeyLines(details.publicKeyInfo),
        extensionLines(details.extensions),
        signatureLines(details),
        fingerprintLines(details.fingerprints),
        subjectKeyIdentifierLines(details.extensions),
    ];
    return sections.filter(lines => lines.length).map(lines => lines.join('\n')).join('\n\n').trim();
}
