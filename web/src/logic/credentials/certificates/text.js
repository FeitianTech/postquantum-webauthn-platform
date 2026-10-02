// A certificate as text, as the registration view's certificate shows it: the
// decoder's summary when it gave one, else an OpenSSL-like text built from its
// fields. DOM-free: both interfaces import it.

function appendKeyValueLines(output, value, indentLevel = 0) {
    if (value === null || value === undefined) {
        return;
    }

    const indent = '    '.repeat(indentLevel);

    if (typeof value === 'string' || typeof value === 'number') {
        if (String(value).trim() !== '') {
            output.push(`${indent}${value}`);
        }
        return;
    }

    if (typeof value === 'boolean') {
        output.push(`${indent}${value}`);
        return;
    }

    if (Array.isArray(value)) {
        if (value.length === 0) {
            return;
        }

        const filtered = value.filter(item => item !== null && item !== undefined);
        if (filtered.length === 0) {
            return;
        }

        const allScalars = filtered.every(item => {
            return (
                typeof item === 'string' ||
                typeof item === 'number' ||
                typeof item === 'boolean'
            );
        });

        if (allScalars) {
            filtered.forEach(item => {
                output.push(`${indent}${item}`);
            });
        } else {
            filtered.forEach(item => {
                if (typeof item === 'object') {
                    output.push(`${indent}-`);
                    appendKeyValueLines(output, item, indentLevel + 1);
                } else {
                    output.push(`${indent}- ${item}`);
                }
            });
        }
        return;
    }

    if (typeof value === 'object') {
        const entries = Object.entries(value).filter(([key, val]) => {
            if (val === null || val === undefined || val === '') {
                return false;
            }
            if (typeof key === 'string' && key.toLowerCase().includes('base64')) {
                return false;
            }
            return true;
        });

        if (entries.length === 0) {
            return;
        }

        entries.forEach(([key, val]) => {
            if (typeof val === 'object') {
                if (Array.isArray(val)) {
                    if (val.length === 0) {
                        return;
                    }
                    output.push(`${indent}${key}:`);
                    appendKeyValueLines(output, val, indentLevel + 1);
                } else {
                    const nestedEntries = Object.entries(val).filter(([, nestedVal]) => nestedVal !== null && nestedVal !== undefined && nestedVal !== '');
                    if (nestedEntries.length === 0) {
                        return;
                    }
                    output.push(`${indent}${key}:`);
                    appendKeyValueLines(output, val, indentLevel + 1);
                }
            } else {
                output.push(`${indent}${key}: ${val}`);
            }
        });
        return;
    }

    output.push(`${indent}${String(value)}`);
}

// A fingerprint's hex, given as text, in lines of 16 colon-separated bytes.
function hexToColonLines(hexString, bytesPerLine = 16) {
    let clean = hexString.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
    if (!clean) {
        return [];
    }
    if (clean.length % 2 !== 0) {
        clean = `0${clean}`;
    }
    const pairs = [];
    for (let i = 0; i < clean.length; i += 2) {
        pairs.push(clean.slice(i, i + 2));
    }
    const output = [];
    for (let i = 0; i < pairs.length; i += bytesPerLine) {
        output.push(pairs.slice(i, i + bytesPerLine).join(':'));
    }
    return output;
}

// The lines written so far: a blank line opens a section, never two in a row.
function lineWriter() {
    const lines = [];
    return {
        lines,
        add: line => lines.push(line),
        blank: () => {
            if (lines.length && lines[lines.length - 1] !== '') {
                lines.push('');
            }
        },
    };
}

/** @typedef {ReturnType<typeof lineWriter>} LineWriter */

// The version after "Version: ": the server's display, then its hex when the
// display does not already carry it ("3 (0x2)"); '' for none.
function versionText(version) {
    if (typeof version !== 'object') {
        return String(version).trim() !== '' ? String(version) : '';
    }
    const parts = [];
    if (typeof version.display === 'string' && version.display.trim() !== '') {
        parts.push(version.display.trim());
    }
    if (typeof version.hex === 'string' && version.hex.trim() !== '') {
        const hex = version.hex.trim();
        if (!parts.length || (parts[0] !== hex && !parts[0].includes(`(${hex})`))) {
            parts.push(hex);
        }
    }
    return parts.join(' ');
}

// The serial number after "Certificate Serial Number: ": decimal / hex; '' for none.
function serialNumberText(serialNumber) {
    if (typeof serialNumber !== 'object') {
        return String(serialNumber).trim() !== '' ? String(serialNumber) : '';
    }
    const parts = [];
    if (typeof serialNumber.decimal === 'string' && serialNumber.decimal.trim() !== '') {
        parts.push(serialNumber.decimal.trim());
    }
    if (typeof serialNumber.hex === 'string' && serialNumber.hex.trim() !== '') {
        parts.push(serialNumber.hex.trim());
    }
    return parts.join(' / ');
}

/**
 * The first lines: version, serial number, signature algorithm, issuer.
 * @param {LineWriter} out
 */
function writeIdentity(out, details) {
    const version = details.version ? versionText(details.version) : '';
    if (version) {
        out.add(`Version: ${version}`);
    }
    const serialNumber = details.serialNumber ? serialNumberText(details.serialNumber) : '';
    if (serialNumber) {
        out.add(`Certificate Serial Number: ${serialNumber}`);
    }
    if (typeof details.signatureAlgorithm === 'string' && details.signatureAlgorithm.trim() !== '') {
        out.add(`Signature Algorithm: ${details.signatureAlgorithm.trim()}`);
    }
    if (typeof details.issuer === 'string' && details.issuer.trim() !== '') {
        out.add(`Issuer: ${details.issuer.trim()}`);
    }
}

/**
 * "Validity:" with its two dates, the subject, and "Subject Public Key Info:".
 * @param {LineWriter} out
 */
function writeSubject(out, details) {
    const validity = details.validity;
    if (validity && (validity.notBefore || validity.notAfter)) {
        out.blank();
        out.add('Validity:');
        if (validity.notBefore) {
            out.add(`    Not Before: ${validity.notBefore}`);
        }
        if (validity.notAfter) {
            out.add(`    Not After: ${validity.notAfter}`);
        }
    }
    if (typeof details.subject === 'string' && details.subject.trim() !== '') {
        out.blank();
        out.add(`Subject: ${details.subject.trim()}`);
    }
    if (details.publicKeyInfo && typeof details.publicKeyInfo === 'object') {
        out.blank();
        out.add('Subject Public Key Info:');
        appendKeyValueLines(out.lines, details.publicKeyInfo, 1);
    }
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

/**
 * "X509v3 extensions:", each its header and value.
 * @param {LineWriter} out
 */
function writeExtensions(out, extensions) {
    if (!Array.isArray(extensions) || !extensions.length) {
        return;
    }
    out.blank();
    out.add('X509v3 extensions:');
    extensions.forEach(ext => {
        if (!ext || typeof ext !== 'object') {
            return;
        }
        out.add(`    ${extensionHeader(ext)}:`);
        if ('value' in ext) {
            appendKeyValueLines(out.lines, ext.value, 2);
        }
    });
}

/**
 * The signature: its algorithm, then its bytes in lines (or in one colon line).
 * @param {LineWriter} out
 */
function writeSignature(out, details) {
    if (!details.signature || typeof details.signature !== 'object') {
        return;
    }
    const algorithm = typeof details.signature.algorithm === 'string'
        ? details.signature.algorithm.trim()
        : '';
    const signatureLines = Array.isArray(details.signature.lines)
        ? details.signature.lines.filter(line => typeof line === 'string' && line.trim() !== '')
        : [];
    const signatureColon = typeof details.signature.colon === 'string'
        ? details.signature.colon.trim()
        : '';

    if (algorithm || signatureLines.length || signatureColon) {
        out.blank();
        const algorithmLabel = algorithm || (typeof details.signatureAlgorithm === 'string' ? details.signatureAlgorithm.trim() : 'Signature');
        out.add(`Signature Algorithm: ${algorithmLabel}`);
        if (signatureLines.length) {
            signatureLines.forEach(line => out.add(`    ${line}`));
        } else if (signatureColon) {
            out.add(`    ${signatureColon}`);
        }
    }
}

/**
 * "Fingerprint:", each digest's name and its bytes in colon lines.
 * @param {LineWriter} out
 */
function writeFingerprints(out, fingerprints) {
    if (!fingerprints || typeof fingerprints !== 'object') {
        return;
    }
    const fingerprintEntries = Object.entries(fingerprints)
        .filter(([, value]) => typeof value === 'string' && value.trim() !== '');

    if (fingerprintEntries.length) {
        out.blank();
        out.add('Fingerprint:');
        fingerprintEntries.forEach(([algorithm, value]) => {
            const label = typeof algorithm === 'string' && algorithm.trim() !== ''
                ? algorithm.trim().toUpperCase()
                : 'VALUE';
            const colonLines = hexToColonLines(value);
            out.add(`    ${label}:`);
            if (colonLines.length) {
                colonLines.forEach(line => out.add(`        ${line}`));
            } else {
                out.add(`        ${value}`);
            }
        });
    }
}

export function formatCertificateDetails(details) {
    if (!details || typeof details !== 'object') {
        return '';
    }

    if (typeof details.summary === 'string' && details.summary.trim() !== '') {
        return details.summary.trim();
    }

    const out = lineWriter();
    writeIdentity(out, details);
    writeSubject(out, details);
    writeExtensions(out, details.extensions);
    writeSignature(out, details);
    writeFingerprints(out, details.fingerprints);
    return out.lines.join('\n').trim();
}
